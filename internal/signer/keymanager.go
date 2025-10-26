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

	// CreateKey generates a new key pair and returns the corresponding Ethereum address.
	// The key is stored in the underlying storage backend.
	CreateKey() (common.Address, error)

	// SignTx signs a given Ethereum transaction with the key corresponding to the specified address.
	// It requires the chain ID for EIP-155 replay protection.
	SignTx(address common.Address, tx *types.Transaction, chainID *big.Int) (*types.Transaction, error)

	// SignMessage signs an arbitrary message with the key for the given address, following the EIP-191 standard.
	SignMessage(address common.Address, message []byte) ([]byte, error)
}
