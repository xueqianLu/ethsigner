package signer

import (
	"encoding/base64"
	"fmt"
	"github.com/aws/smithy-go/rand"
	"log"
	"strings"
	"sync"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/hashicorp/vault/api"
)

// KeyManager manages key metadata for keys stored in HashiCorp Vault.
// It maps Ethereum addresses to Vault's transit key names.
// It is safe for concurrent use.
type KeyManager struct {
	vaultClient  *api.Client
	transitPath  string
	addressToKey map[common.Address]string // Map ETH address to Vault key name
	mu           sync.RWMutex
}

// NewKeyManager creates a new KeyManager and initializes it with keys from Vault.
func NewKeyManager(vaultClient *api.Client, transitPath string) (*KeyManager, error) {
	km := &KeyManager{
		vaultClient:  vaultClient,
		transitPath:  transitPath,
		addressToKey: make(map[common.Address]string),
	}

	// Ensure the transit secrets engine is enabled at the specified path.
	if err := km.enableTransitEngine(); err != nil {
		return nil, fmt.Errorf("failed to enable transit secrets engine: %w", err)
	}

	// Load existing keys from Vault and populate the address map.
	if err := km.loadExistingKeys(); err != nil {
		return nil, fmt.Errorf("failed to load existing keys from vault: %w", err)
	}

	return km, nil
}

// enableTransitEngine ensures the transit secrets engine is mounted.
func (km *KeyManager) enableTransitEngine() error {
	mounts, err := km.vaultClient.Sys().ListMounts()
	if err != nil {
		return err
	}

	mountPath := km.transitPath + "/"
	if _, ok := mounts[mountPath]; !ok {
		log.Printf("Transit secrets engine not found at '%s', enabling it now.", km.transitPath)
		return km.vaultClient.Sys().Mount(km.transitPath, &api.MountInput{
			Type: "transit",
		})
	}
	log.Printf("Transit secrets engine already enabled at '%s'.", km.transitPath)
	return nil
}

// loadExistingKeys lists keys in Vault and maps their addresses.
func (km *KeyManager) loadExistingKeys() error {
	path := fmt.Sprintf("%s/keys", km.transitPath)
	secret, err := km.vaultClient.Logical().List(path)
	if err != nil {
		return err
	}

	// If there are no keys, secret might be nil.
	if secret == nil || secret.Data["keys"] == nil {
		log.Println("No existing keys found in Vault transit engine.")
		return nil
	}

	keys, ok := secret.Data["keys"].([]interface{})
	if !ok {
		return fmt.Errorf("unexpected format for keys from vault")
	}

	km.mu.Lock()
	defer km.mu.Unlock()

	for _, k := range keys {
		keyName, ok := k.(string)
		if !ok {
			continue
		}

		address, err := km.getAddressForKey(keyName)
		if err != nil {
			log.Printf("Warning: could not get address for key '%s': %v", keyName, err)
			continue
		}
		km.addressToKey[address] = keyName
		log.Printf("Loaded key '%s' for address %s", keyName, address.Hex())
	}

	return nil
}

// CreateKey creates a new key in Vault and returns its Ethereum address.
func (km *KeyManager) CreateKey() (common.Address, error) {
	// The key name will be the Ethereum address, but we don't know the address yet.
	// So we create a temporary key, calculate its address, and then rename it.
	// A simpler approach for this example is to use a UUID for the key name.
	// Let's use the key name as the address hex, which is cleaner.

	// 1. Create a new key in Vault
	// Key names must be unique. We can use a counter or UUID.
	// For simplicity, let's derive the address and use it as the key name.
	// This is tricky because we need the public key first.
	// Let's create a key with a temporary name, get its public key,
	// calculate the address, and then we know the mapping.
	// Vault doesn't support renaming keys, so we'll just use a generated name.
	// A good practice is to use a unique ID.
	id, _ := rand.CryptoRandInt63n(2 ^ 63)
	keyName := fmt.Sprintf("eth-key-%d", id)

	path := fmt.Sprintf("%s/keys/%s", km.transitPath, keyName)
	_, err := km.vaultClient.Logical().Write(path, map[string]interface{}{
		"type": "ecdsa-p256",
	})
	if err != nil {
		return common.Address{}, fmt.Errorf("failed to create key in vault: %w", err)
	}

	// 2. Get the public key and calculate the address
	address, err := km.getAddressForKey(keyName)
	if err != nil {
		// Rollback: delete the created key if we can't get its address
		deletePath := fmt.Sprintf("%s/keys/%s/config", km.transitPath, keyName)
		_, delErr := km.vaultClient.Logical().Write(deletePath, map[string]interface{}{"deletion_allowed": true})
		if delErr == nil {
			km.vaultClient.Logical().Delete(path)
		}
		return common.Address{}, fmt.Errorf("failed to get address for new key: %w", err)
	}

	// 3. Store the mapping
	km.mu.Lock()
	defer km.mu.Unlock()
	km.addressToKey[address] = keyName

	log.Printf("Successfully created key '%s' for address %s", keyName, address.Hex())
	return address, nil
}

// GetKeyName returns the Vault key name for a given address.
func (km *KeyManager) GetKeyName(address common.Address) (string, error) {
	km.mu.RLock()
	defer km.mu.RUnlock()

	keyName, ok := km.addressToKey[address]
	if !ok {
		return "", fmt.Errorf("account not found or not managed by this signer: %s", address.Hex())
	}
	return keyName, nil
}

// GetAccounts returns all managed account addresses.
func (km *KeyManager) GetAccounts() []common.Address {
	km.mu.RLock()
	defer km.mu.RUnlock()

	var addresses []common.Address
	for addr := range km.addressToKey {
		addresses = append(addresses, addr)
	}
	return addresses
}

// getAddressForKey retrieves the public key from Vault and computes its Ethereum address.
func (km *KeyManager) getAddressForKey(keyName string) (common.Address, error) {
	path := fmt.Sprintf("%s/keys/%s", km.transitPath, keyName)
	secret, err := km.vaultClient.Logical().Read(path)
	if err != nil {
		return common.Address{}, err
	}
	if secret == nil || secret.Data["keys"] == nil {
		return common.Address{}, fmt.Errorf("key '%s' not found in vault", keyName)
	}

	// The public key is in a map of versions. We need the latest one.
	keysData, ok := secret.Data["keys"].(map[string]interface{})
	if !ok {
		return common.Address{}, fmt.Errorf("unexpected format for key data")
	}

	// Find the latest version of the key
	latestVersion := "0"
	for v := range keysData {
		if v > latestVersion {
			latestVersion = v
		}
	}

	keyData, ok := keysData[latestVersion].(map[string]interface{})
	if !ok {
		return common.Address{}, fmt.Errorf("unexpected format for key version data")
	}

	pubKeyBase64, ok := keyData["public_key"].(string)
	if !ok {
		return common.Address{}, fmt.Errorf("public key not found in key data")
	}

	// Vault returns a base64-encoded DER-encoded PKIX format public key.
	pubKeyBytes, err := base64.StdEncoding.DecodeString(pubKeyBase64)
	if err != nil {
		return common.Address{}, fmt.Errorf("failed to decode public key: %w", err)
	}

	pubKey, err := crypto.UnmarshalPubkey(pubKeyBytes)
	if err != nil {
		// Vault's ecdsa-p256 public keys might need to be parsed differently.
		// Let's try to parse it as a generic public key first.
		genericPubKey, err2 := crypto.DecompressPubkey(pubKeyBytes)
		if err2 != nil {
			return common.Address{}, fmt.Errorf("failed to unmarshal or parse public key: %v / %v", err, err2)
		}
		pubKey = genericPubKey
	}

	address := crypto.PubkeyToAddress(*pubKey)
	return address, nil
}

// SignWithVault performs a signing operation using Vault's transit engine.
func (km *KeyManager) SignWithVault(keyName string, dataToSign []byte) ([]byte, error) {
	path := fmt.Sprintf("%s/sign/%s", km.transitPath, keyName)
	b64Data := base64.StdEncoding.EncodeToString(dataToSign)

	resp, err := km.vaultClient.Logical().Write(path, map[string]interface{}{
		"input":                b64Data,
		"signature_algorithm":  "pkcs1v15", // This is for RSA, for ECDSA it's auto-detected. Let's use default.
		"marshaling_algorithm": "jws",      // Use JWS to get r and s values
	})
	if err != nil {
		return nil, fmt.Errorf("failed to sign with vault: %w", err)
	}

	signature, ok := resp.Data["signature"].(string)
	if !ok {
		return nil, fmt.Errorf("signature not found in vault response")
	}

	// The signature is in "vault:v1:..." format. We need to decode it.
	parts := strings.Split(signature, ":")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid signature format from vault")
	}

	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("failed to decode signature: %w", err)
	}

	// The JWS format for ECDSA gives us r and s concatenated.
	// r is the first 32 bytes, s is the next 32 bytes.
	if len(sigBytes) != 64 {
		return nil, fmt.Errorf("expected 64-byte signature from vault, got %d", len(sigBytes))
	}

	return sigBytes, nil
}
