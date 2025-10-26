package handler

import (
	"encoding/json"
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
	defer r.Body.Close()

	from := common.HexToAddress(req.From)
	to := common.HexToAddress(req.To)

	var tx *types.Transaction
	if req.GasFeeCap != nil && req.GasTipCap != nil {
		// EIP-1559 Transaction
		tx = types.NewTx(&types.DynamicFeeTx{
			ChainID:   req.ChainID,
			Nonce:     req.Nonce,
			GasTipCap: req.GasTipCap,
			GasFeeCap: req.GasFeeCap,
			Gas:       req.GasLimit,
			To:        &to,
			Value:     req.Value,
			Data:      req.Data,
		})
	} else {
		// Legacy Transaction
		tx = types.NewTx(&types.LegacyTx{
			Nonce:    req.Nonce,
			GasPrice: req.GasPrice,
			Gas:      req.GasLimit,
			To:       &to,
			Value:    req.Value,
			Data:     req.Data,
		})
	}

	signedTx, err := h.signer.SignTransaction(from, tx)
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

