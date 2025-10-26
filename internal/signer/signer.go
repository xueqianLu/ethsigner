package signer

import (
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
)

// Signer provides transaction and message signing functionality using Vault.
type Signer struct {
	km *KeyManager
}

// NewSigner creates a new Signer.
func NewSigner(km *KeyManager) *Signer {
	return &Signer{km: km}
}

// SignTransaction signs an Ethereum transaction using a key from Vault.
func (s *Signer) SignTransaction(from common.Address, tx *types.Transaction) (*types.Transaction, error) {
	// 1. Get the appropriate signer for the chain ID
	chainID := tx.ChainId()
	if chainID == nil {
		return nil, fmt.Errorf("transaction chain ID is required for signing")
	}
	txSigner := types.NewEIP155Signer(chainID)
	txHash := txSigner.Hash(tx)

	// 2. Get the Vault key name for the given address
	keyName, err := s.km.GetKeyName(from)
	if err != nil {
		return nil, err
	}

	// 3. Sign the hash with Vault
	// This returns a 64-byte signature (r and s)
	rsSignature, err := s.km.SignWithVault(keyName, txHash.Bytes())
	if err != nil {
		return nil, fmt.Errorf("failed to sign transaction hash with vault: %w", err)
	}

	// 4. Determine the correct recovery ID (v)
	// This is necessary because Vault doesn't provide it directly.
	v, err := s.recoverV(txHash.Bytes(), rsSignature, from)
	if err != nil {
		return nil, fmt.Errorf("failed to recover signature 'v' value: %w", err)
	}

	// 5. Append the recovery ID to the signature
	// The final signature must be in [R || S || V] format
	// v is 0 or 1, but for EIP-155 it's encoded. The signer handles this.
	finalSignature := make([]byte, 65)
	copy(finalSignature[0:32], rsSignature[0:32])   // R
	copy(finalSignature[32:64], rsSignature[32:64]) // S
	finalSignature[64] = v                          // V

	// 6. Apply the signature to the transaction
	signedTx, err := tx.WithSignature(txSigner, finalSignature)
	if err != nil {
		return nil, fmt.Errorf("failed to apply signature to transaction: %w", err)
	}

	return signedTx, nil
}

// SignMessage signs a message with a given account using a key from Vault.
func (s *Signer) SignMessage(from common.Address, message []byte) ([]byte, error) {
	// 1. Create the EIP-191 prefixed message hash
	prefixedMessage := fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(message), message)
	msgHash := crypto.Keccak256Hash([]byte(prefixedMessage))

	// 2. Get the Vault key name for the given address
	keyName, err := s.km.GetKeyName(from)
	if err != nil {
		return nil, err
	}

	// 3. Sign the hash with Vault
	rsSignature, err := s.km.SignWithVault(keyName, msgHash.Bytes())
	if err != nil {
		return nil, fmt.Errorf("failed to sign message hash with vault: %w", err)
	}

	// 4. Determine the correct recovery ID (v)
	v, err := s.recoverV(msgHash.Bytes(), rsSignature, from)
	if err != nil {
		return nil, fmt.Errorf("failed to recover signature 'v' value: %w", err)
	}

	// 5. Construct the final signature in [R || S || V] format
	// For message signing, v should be 27 or 28.
	finalSignature := make([]byte, 65)
	copy(finalSignature[0:32], rsSignature[0:32])   // R
	copy(finalSignature[32:64], rsSignature[32:64]) // S
	finalSignature[64] = v + 27                     // V (adjusted for message signing)

	return finalSignature, nil
}

// recoverV attempts to find the correct recovery ID (0 or 1) for a signature.
// It does this by trying both possible values and checking which one recovers
// the public key corresponding to the provided 'from' address.
func (s *Signer) recoverV(hash, rsSignature []byte, from common.Address) (byte, error) {
	for i := 0; i < 2; i++ {
		v := byte(i)
		sigWithV := append(rsSignature, v)

		recoveredPubKey, err := crypto.Ecrecover(hash, sigWithV)
		if err != nil {
			continue // Try the next v
		}

		pubKey, err := crypto.UnmarshalPubkey(recoveredPubKey)
		if err != nil {
			continue
		}

		recoveredAddr := crypto.PubkeyToAddress(*pubKey)
		if recoveredAddr == from {
			return v, nil // Found the correct recovery ID
		}
	}
	return 0, fmt.Errorf("could not find a valid recovery ID for the signature")
}
