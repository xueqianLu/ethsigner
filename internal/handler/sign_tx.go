package handler

import (
	"encoding/json"
	"math/big"
	"net/http"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/xueqianLu/ethsigner/internal/signer"
)

// SignTxHandler handles transaction signing requests.
type SignTxHandler struct {
	signer *signer.Signer
}

// NewSignTxHandler creates a new SignTxHandler.
func NewSignTxHandler(s *signer.Signer) *SignTxHandler {
	return &SignTxHandler{signer: s}
}

// ServeHTTP implements the http.Handler interface.
func (h *SignTxHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req SignTxRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Secret == "" {
		http.Error(w, "Password is required", http.StatusBadRequest)
		return
	}

	// Convert address strings to common.Address
	fromAddr := common.HexToAddress(req.From)
	var toAddr *common.Address
	if req.To != "" {
		to := common.HexToAddress(req.To)
		toAddr = &to
	}

	// Parse ChainID from the request
	if req.ChainID == "" {
		http.Error(w, "ChainID is required", http.StatusBadRequest)
		return
	}
	chainID, ok := new(big.Int).SetString(req.ChainID, 10)
	if !ok {
		http.Error(w, "Invalid ChainID", http.StatusBadRequest)
		return
	}

	// Create the transaction object
	var tx *types.Transaction
	// EIP-1559
	if req.GasFeeCap != nil && req.GasTipCap != nil {
		tx = types.NewTx(&types.DynamicFeeTx{
			ChainID:   chainID,
			Nonce:     req.Nonce,
			GasFeeCap: req.GasFeeCap,
			GasTipCap: req.GasTipCap,
			Gas:       req.GasLimit,
			To:        toAddr,
			Value:     req.Value,
			Data:      req.Data,
		})
	} else { // Legacy
		tx = types.NewTx(&types.LegacyTx{
			Nonce:    req.Nonce,
			GasPrice: req.GasPrice,
			Gas:      req.GasLimit,
			To:       toAddr,
			Value:    req.Value,
			Data:     req.Data,
		})
	}

	// Sign the transaction
	signedTx, err := h.signer.SignTx(fromAddr, req.Secret, tx, chainID)
	if err != nil {
		http.Error(w, "Failed to sign transaction: "+err.Error(), http.StatusInternalServerError)
		return
	}

	rawTx, err := signedTx.MarshalBinary()
	if err != nil {
		http.Error(w, "Failed to marshal signed transaction: "+err.Error(), http.StatusInternalServerError)
		return
	}

	resp := SignTxResponse{
		RawTx: common.Bytes2Hex(rawTx),
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
	}
}
