package signer

import (
	"crypto/ecdsa"
	"fmt"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"sync"

	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
)

// LocalKeyManager manages keys stored locally on disk.
type LocalKeyManager struct {
	keyDir   string
	password string
	keys     map[common.Address]*ecdsa.PrivateKey
	mu       sync.RWMutex
}

// NewLocalKeyManager creates a new LocalKeyManager and loads existing keys from disk.
func NewLocalKeyManager(keyDir, password string) (*LocalKeyManager, error) {
	if err := os.MkdirAll(keyDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create key directory: %w", err)
	}

	km := &LocalKeyManager{
		keyDir:   keyDir,
		password: password,
		keys:     make(map[common.Address]*ecdsa.PrivateKey),
	}

	files, err := os.ReadDir(keyDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read key directory: %w", err)
	}

	for _, file := range files {
		if !file.IsDir() {
			filePath := filepath.Join(keyDir, file.Name())
			keyJson, err := os.ReadFile(filePath)
			if err != nil {
				log.Printf("Warning: failed to read key file %s: %v", file.Name(), err)
				continue
			}
			key, err := keystore.DecryptKey(keyJson, password)
			if err != nil {
				log.Printf("Warning: failed to decrypt key file %s: %v", file.Name(), err)
				continue
			}
			address := key.Address
			km.keys[address] = key.PrivateKey
			log.Printf("Loaded local key for address %s", address.Hex())
		}
	}

	return km, nil
}

// CreateKey generates a new key pair and saves it to disk (encrypted).
func (km *LocalKeyManager) CreateKey() (common.Address, error) {
	privateKey, err := crypto.GenerateKey()
	if err != nil {
		return common.Address{}, fmt.Errorf("failed to generate private key: %w", err)
	}
	address := crypto.PubkeyToAddress(privateKey.PublicKey)

	keyStruct := &keystore.Key{
		Address:    address,
		PrivateKey: privateKey,
	}
	keyJson, err := keystore.EncryptKey(keyStruct, km.password, keystore.StandardScryptN, keystore.StandardScryptP)
	if err != nil {
		return common.Address{}, fmt.Errorf("failed to encrypt private key: %w", err)
	}
	filePath := filepath.Join(km.keyDir, address.Hex()+".json")
	if err := os.WriteFile(filePath, keyJson, 0600); err != nil {
		return common.Address{}, fmt.Errorf("failed to save encrypted key: %w", err)
	}

	km.mu.Lock()
	defer km.mu.Unlock()
	km.keys[address] = privateKey

	log.Printf("Created and saved encrypted local key for address %s", address.Hex())
	return address, nil
}

// GetAccounts returns all managed account addresses.
func (km *LocalKeyManager) GetAccounts() []common.Address {
	km.mu.RLock()
	defer km.mu.RUnlock()

	var addresses []common.Address
	for addr := range km.keys {
		addresses = append(addresses, addr)
	}
	return addresses
}

// SignTx signs a transaction using a locally stored private key.
func (km *LocalKeyManager) SignTx(address common.Address, tx *types.Transaction, chainID *big.Int) (*types.Transaction, error) {
	km.mu.RLock()
	privateKey, ok := km.keys[address]
	km.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("account not found: %s", address.Hex())
	}

	signedTx, err := types.SignTx(tx, types.NewPragueSigner(chainID), privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign transaction: %w", err)
	}

	return signedTx, nil
}

// SignMessage signs a message using a locally stored private key.
func (km *LocalKeyManager) SignMessage(address common.Address, message []byte) ([]byte, error) {
	km.mu.RLock()
	privateKey, ok := km.keys[address]
	km.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("account not found: %s", address.Hex())
	}

	// EIP-191: Signed Data Standard
	prefixedMessage := fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(message), message)
	messageHash := crypto.Keccak256Hash([]byte(prefixedMessage))

	signature, err := crypto.Sign(messageHash.Bytes(), privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign message: %w", err)
	}

	// Adjust the V value of the signature
	// In go-ethereum, crypto.Sign returns a signature with V as 0 or 1.
	// For eth_sign RPC calls, it's common to add 27 to V.
	// So, V becomes 27 or 28.
	signature[64] += 27

	return signature, nil
}
