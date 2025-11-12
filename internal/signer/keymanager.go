package signer

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"math/big"
)

// KeyManager defines the interface for managing cryptographic keys and performing signing operations.
// It abstracts the underlying key storage, which can be a local keystore or a remote service like Vault.
type KeyManager interface {
	// GetAccounts returns a list of all Ethereum addresses managed by the KeyManager.
	GetAccounts() []common.Address

	// CreateKey generates a new key pair and returns the corresponding Ethereum address and the password used for encryption.
	// The key is stored in the underlying storage backend, encrypted with the returned password.
	CreateKey() (common.Address, string, error)

	// SignTx signs a given Ethereum transaction with the key corresponding to the specified address.
	// It requires the password to decrypt the key.
	SignTx(address common.Address, password string, tx *types.Transaction, chainID *big.Int) (*types.Transaction, error)

	// SignMessage signs an arbitrary message with the key for the given address, following the EIP-191 standard.
	// It requires the password to decrypt the key.
	SignMessage(address common.Address, password string, message []byte) ([]byte, error)
}
