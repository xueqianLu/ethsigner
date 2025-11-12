package handler

import (
	"encoding/json"
	"net/http"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/xueqianLu/ethsigner/internal/signer"
)

// SignMessageHandler handles message signing requests.
type SignMessageHandler struct {
	signer *signer.Signer
}

// NewSignMessageHandler creates a new SignMessageHandler.
func NewSignMessageHandler(s *signer.Signer) *SignMessageHandler {
	return &SignMessageHandler{signer: s}
}

// ServeHTTP implements the http.Handler interface.
func (h *SignMessageHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req SignMessageRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	if req.Secret == "" {
		http.Error(w, "Password is required", http.StatusBadRequest)
		return
	}

	from := common.HexToAddress(req.From)
	message := []byte(req.Message)

	signature, err := h.signer.SignMessage(from, req.Secret, message)
	if err != nil {
		http.Error(w, "Failed to sign message: "+err.Error(), http.StatusInternalServerError)
		return
	}

	resp := SignMessageResponse{
		Signature: hexutil.Encode(signature),
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
	}
}
