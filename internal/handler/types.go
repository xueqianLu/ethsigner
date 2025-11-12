package handler

import "math/big"

// SignTxRequest represents the request to sign a transaction.
type SignTxRequest struct {
	From      string   `json:"from"`
	To        string   `json:"to"`
	Secret    string   `json:"secret"`
	Nonce     uint64   `json:"nonce"`
	Value     *big.Int `json:"value"`
	Data      []byte   `json:"data"`
	GasLimit  uint64   `json:"gasLimit"`
	GasPrice  *big.Int `json:"gasPrice,omitempty"`  // Legacy
	GasFeeCap *big.Int `json:"gasFeeCap,omitempty"` // EIP-1559
	GasTipCap *big.Int `json:"gasTipCap,omitempty"` // EIP-1559
	ChainID   string   `json:"chainId"`
}

// SignTxResponse represents the response for a signed transaction.
type SignTxResponse struct {
	RawTx string `json:"rawTx"`
}

// SignMessageRequest represents the request to sign a message.
type SignMessageRequest struct {
	From    string `json:"from"`
	Secret  string `json:"secret"`
	Message string `json:"message"`
}

// SignMessageResponse represents the response for a signed message.
type SignMessageResponse struct {
	Signature string `json:"signature"`
}

// ErrorResponse represents a standard error response.
type ErrorResponse struct {
	Error string `json:"error"`
}
