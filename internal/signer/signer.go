package signer

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"math/big"
)

// Signer provides transaction and message signing functionality.
type Signer struct {
	keyManager KeyManager
}

// NewSigner creates a new Signer with a given KeyManager.
func NewSigner(keyManager KeyManager) *Signer {
	return &Signer{
		keyManager: keyManager,
	}
}

// GetAccounts returns the list of accounts managed by the underlying KeyManager.
func (s *Signer) GetAccounts() []common.Address {
	return s.keyManager.GetAccounts()
}

// CreateKey creates a new account in the KeyManager and returns its address and password.
func (s *Signer) CreateKey() (common.Address, string, error) {
	return s.keyManager.CreateKey()
}

// SignTx signs a transaction with the specified account.
func (s *Signer) SignTx(address common.Address, password string, tx *types.Transaction, chainID *big.Int) (*types.Transaction, error) {
	return s.keyManager.SignTx(address, password, tx, chainID)
}

// SignMessage signs a message with the specified account.
func (s *Signer) SignMessage(address common.Address, password string, message []byte) ([]byte, error) {
	return s.keyManager.SignMessage(address, password, message)
}
