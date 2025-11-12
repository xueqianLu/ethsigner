package signer

import (
	"crypto/ecdsa"
	"crypto/rand"
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

const passwordLength = 32

func generatePassword() (string, error) {
	bytes := make([]byte, passwordLength)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", bytes), nil
}

// LocalKeyManager manages keys stored locally on disk.
type LocalKeyManager struct {
	keyDir   string
	accounts map[common.Address]struct{}
	mu       sync.RWMutex
}

// NewLocalKeyManager creates a new LocalKeyManager and loads existing keys from disk.
func NewLocalKeyManager(keyDir string) (*LocalKeyManager, error) {
	if err := os.MkdirAll(keyDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create key directory: %w", err)
	}

	km := &LocalKeyManager{
		keyDir:   keyDir,
		accounts: make(map[common.Address]struct{}),
	}

	files, err := os.ReadDir(keyDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read key directory: %w", err)
	}

	for _, file := range files {
		if !file.IsDir() {
			fileName := file.Name()
			// Assuming file name is address.hex.json
			addressHex := fileName[:len(fileName)-len(filepath.Ext(fileName))]
			if common.IsHexAddress(addressHex) {
				address := common.HexToAddress(addressHex)
				km.accounts[address] = struct{}{}
				log.Printf("Loaded local key for address %s", address.Hex())
			}
		}
	}

	return km, nil
}

// CreateKey generates a new key pair and saves it to disk (encrypted).
func (km *LocalKeyManager) CreateKey() (common.Address, string, error) {
	privateKey, err := crypto.GenerateKey()
	if err != nil {
		return common.Address{}, "", fmt.Errorf("failed to generate private key: %w", err)
	}
	address := crypto.PubkeyToAddress(privateKey.PublicKey)

	password, err := generatePassword()
	if err != nil {
		return common.Address{}, "", fmt.Errorf("failed to generate password: %w", err)
	}

	keyStruct := &keystore.Key{
		Address:    address,
		PrivateKey: privateKey,
	}
	keyJson, err := keystore.EncryptKey(keyStruct, password, keystore.StandardScryptN, keystore.StandardScryptP)
	if err != nil {
		return common.Address{}, "", fmt.Errorf("failed to encrypt private key: %w", err)
	}
	filePath := filepath.Join(km.keyDir, address.Hex()+".json")
	if err := os.WriteFile(filePath, keyJson, 0600); err != nil {
		return common.Address{}, "", fmt.Errorf("failed to save encrypted key: %w", err)
	}

	km.mu.Lock()
	defer km.mu.Unlock()
	km.accounts[address] = struct{}{}

	log.Printf("Created and saved encrypted local key for address %s", address.Hex())
	return address, password, nil
}

// GetAccounts returns all managed account addresses.
func (km *LocalKeyManager) GetAccounts() []common.Address {
	km.mu.RLock()
	defer km.mu.RUnlock()

	var addresses []common.Address
	for addr := range km.accounts {
		addresses = append(addresses, addr)
	}
	return addresses
}

func (km *LocalKeyManager) getPrivateKey(address common.Address, password string) (*ecdsa.PrivateKey, error) {
	filePath := filepath.Join(km.keyDir, address.Hex()+".json")
	keyJson, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read key file for address %s: %w", address.Hex(), err)
	}

	key, err := keystore.DecryptKey(keyJson, password)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt key for address %s: %w", address.Hex(), err)
	}
	return key.PrivateKey, nil
}

// SignTx signs a transaction using a locally stored private key.
func (km *LocalKeyManager) SignTx(address common.Address, password string, tx *types.Transaction, chainID *big.Int) (*types.Transaction, error) {
	privateKey, err := km.getPrivateKey(address, password)
	if err != nil {
		return nil, err
	}

	signedTx, err := types.SignTx(tx, types.NewPragueSigner(chainID), privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign transaction: %w", err)
	}

	return signedTx, nil
}

// SignMessage signs a message using a locally stored private key.
func (km *LocalKeyManager) SignMessage(address common.Address, password string, message []byte) ([]byte, error) {
	privateKey, err := km.getPrivateKey(address, password)
	if err != nil {
		return nil, err
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
