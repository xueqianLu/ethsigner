package signer

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"github.com/aws/smithy-go/rand"
	"github.com/ethereum/go-ethereum/core/types"
	"log"
	"math/big"
	"strings"
	"sync"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/hashicorp/vault/api"
)

// VaultKeyManager manages keys stored in HashiCorp Vault.
type VaultKeyManager struct {
	vaultClient  *api.Client
	transitPath  string
	addressToKey map[common.Address]string // Map ETH address to Vault key name
	mu           sync.RWMutex
}

// NewVaultKeyManager creates a new VaultKeyManager and initializes it with keys from Vault.
func NewVaultKeyManager(vaultClient *api.Client, transitPath string) (*VaultKeyManager, error) {
	km := &VaultKeyManager{
		vaultClient:  vaultClient,
		transitPath:  transitPath,
		addressToKey: make(map[common.Address]string),
	}

	if err := km.enableTransitEngine(); err != nil {
		return nil, fmt.Errorf("failed to enable transit secrets engine: %w", err)
	}

	if err := km.loadExistingKeys(); err != nil {
		return nil, fmt.Errorf("failed to load existing keys from vault: %w", err)
	}

	return km, nil
}

func (km *VaultKeyManager) enableTransitEngine() error {
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

func (km *VaultKeyManager) loadExistingKeys() error {
	path := fmt.Sprintf("%s/keys", km.transitPath)
	secret, err := km.vaultClient.Logical().List(path)
	if err != nil {
		return err
	}

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
func (km *VaultKeyManager) CreateKey() (common.Address, string, error) {
	id, _ := rand.CryptoRandInt63n(2 ^ 63)
	keyName := fmt.Sprintf("eth-key-%d", id)

	path := fmt.Sprintf("%s/keys/%s", km.transitPath, keyName)
	_, err := km.vaultClient.Logical().Write(path, map[string]interface{}{
		"type": "secp256k1",
	})
	if err != nil {
		return common.Address{}, "", fmt.Errorf("failed to create key in vault: %w", err)
	}

	address, err := km.getAddressForKey(keyName)
	if err != nil {
		deletePath := fmt.Sprintf("%s/keys/%s/config", km.transitPath, keyName)
		_, delErr := km.vaultClient.Logical().Write(deletePath, map[string]interface{}{"deletion_allowed": true})
		if delErr == nil {
			km.vaultClient.Logical().Delete(path)
		}
		return common.Address{}, "", fmt.Errorf("failed to get address for new key: %w", err)
	}

	km.mu.Lock()
	defer km.mu.Unlock()
	km.addressToKey[address] = keyName

	log.Printf("Successfully created key '%s' for address %s", keyName, address.Hex())
	return address, "", nil
}

// GetAccounts returns all managed account addresses.
func (km *VaultKeyManager) GetAccounts() []common.Address {
	km.mu.RLock()
	defer km.mu.RUnlock()

	var addresses []common.Address
	for addr := range km.addressToKey {
		addresses = append(addresses, addr)
	}
	return addresses
}

func (km *VaultKeyManager) getAddressForKey(keyName string) (common.Address, error) {
	path := fmt.Sprintf("%s/keys/%s", km.transitPath, keyName)
	secret, err := km.vaultClient.Logical().Read(path)
	if err != nil {
		return common.Address{}, err
	}
	if secret == nil || secret.Data["keys"] == nil {
		return common.Address{}, fmt.Errorf("key '%s' not found in vault", keyName)
	}

	keysData, ok := secret.Data["keys"].(map[string]interface{})
	if !ok {
		return common.Address{}, fmt.Errorf("unexpected format for key data")
	}

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

	block, _ := pem.Decode([]byte(pubKeyBase64))
	if block == nil {
		return common.Address{}, fmt.Errorf("failed to parse PEM block containing the public key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return common.Address{}, fmt.Errorf("failed to parse DER encoded public key: %w", err)
	}

	ecdsaPubKey, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return common.Address{}, fmt.Errorf("key is not an ECDSA public key")
	}

	address := crypto.PubkeyToAddress(*ecdsaPubKey)
	return address, nil
}

func (km *VaultKeyManager) signWithVault(keyName string, dataToSign []byte) ([]byte, error) {
	path := fmt.Sprintf("%s/sign/%s/sha2-256", km.transitPath, keyName)
	b64Data := base64.StdEncoding.EncodeToString(dataToSign)

	resp, err := km.vaultClient.Logical().Write(path, map[string]interface{}{
		"input":     b64Data,
		"algorithm": "secp256k1",
	})
	if err != nil {
		return nil, fmt.Errorf("failed to sign with vault: %w", err)
	}

	signature, ok := resp.Data["signature"].(string)
	if !ok {
		return nil, fmt.Errorf("signature not found in vault response")
	}

	parts := strings.Split(signature, ":")
	if len(parts) < 3 {
		return nil, fmt.Errorf("invalid signature format from vault: %s", signature)
	}

	sigParts := strings.Split(parts[2], "+")
	r, err := base64.RawURLEncoding.DecodeString(sigParts[0])
	if err != nil {
		return nil, fmt.Errorf("failed to decode r part of signature: %w", err)
	}
	s, err := base64.RawURLEncoding.DecodeString(sigParts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode s part of signature: %w", err)
	}

	rBytes := make([]byte, 32)
	sBytes := make([]byte, 32)
	copy(rBytes[32-len(r):], r)
	copy(sBytes[32-len(s):], s)

	return append(rBytes, sBytes...), nil
}

// SignTx signs a transaction using a key stored in Vault.
func (km *VaultKeyManager) SignTx(address common.Address, password string, tx *types.Transaction, chainID *big.Int) (*types.Transaction, error) {
	keyName, err := km.getKeyName(address)
	if err != nil {
		return nil, err
	}

	signer := types.NewEIP155Signer(chainID)
	txHash := signer.Hash(tx)

	signature, err := km.signWithVault(keyName, txHash.Bytes())
	if err != nil {
		return nil, fmt.Errorf("failed to sign transaction with vault: %w", err)
	}

	// The signature from Vault is just r and s. We need to find the correct v.
	// The v value is a recovery ID, 0 or 1 for secp256k1.
	// We can try both and see which one recovers the correct public key.
	// Note: This is a simplified approach. A more robust solution would involve
	// Vault returning the recovery ID or ensuring a deterministic signature.
	// For now, we'll try to recover the public key and find the right v.
	// This is computationally expensive and should be optimized in a production system.
	// However, for this example, it demonstrates the principle.
	v, err := km.recoverV(signature, txHash.Bytes(), address)
	if err != nil {
		return nil, err
	}
	signature = append(signature, v)

	return tx.WithSignature(signer, signature)
}

// SignMessage signs a message using a key stored in Vault.
func (km *VaultKeyManager) SignMessage(address common.Address, password string, message []byte) ([]byte, error) {
	keyName, err := km.getKeyName(address)
	if err != nil {
		return nil, err
	}

	// EIP-191: Signed Data Standard
	// The message is prefixed with "\x19Ethereum Signed Message:\n" and the length of the message.
	prefixedMessage := fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(message), message)
	messageHash := crypto.Keccak256Hash([]byte(prefixedMessage))

	signature, err := km.signWithVault(keyName, messageHash.Bytes())
	if err != nil {
		return nil, fmt.Errorf("failed to sign message with vault: %w", err)
	}

	v, err := km.recoverV(signature, messageHash.Bytes(), address)
	if err != nil {
		return nil, err
	}
	signature = append(signature, v)

	return signature, nil
}

func (km *VaultKeyManager) getKeyName(address common.Address) (string, error) {
	km.mu.RLock()
	defer km.mu.RUnlock()

	keyName, ok := km.addressToKey[address]
	if !ok {
		return "", fmt.Errorf("account not found or not managed by this signer: %s", address.Hex())
	}
	return keyName, nil
}

// recoverV attempts to find the correct recovery ID (v) for a signature.
func (km *VaultKeyManager) recoverV(signature, hash []byte, expectedAddress common.Address) (byte, error) {
	for i := 0; i < 2; i++ {
		sigWithV := append(signature, byte(i))
		recoveredPub, err := crypto.Ecrecover(hash, sigWithV)
		if err != nil {
			continue
		}

		var pubkey *ecdsa.PublicKey
		pubkey, err = crypto.UnmarshalPubkey(recoveredPub)
		if err != nil {
			continue
		}

		recoveredAddr := crypto.PubkeyToAddress(*pubkey)
		if recoveredAddr == expectedAddress {
			return byte(i), nil
		}
	}
	return 0, fmt.Errorf("could not recover public key for the given signature")
}
