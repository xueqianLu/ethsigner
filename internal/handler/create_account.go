package handler

import (
	"encoding/json"
	"net/http"

	"github.com/xueqianLu/ethsigner/internal/signer"
)

// CreateAccountResponse represents the response for a new account creation.
type CreateAccountResponse struct {
	Address string `json:"address"`
}

// CreateAccountHandler handles requests to create a new account.
type CreateAccountHandler struct {
	km *signer.KeyManager
}

// NewCreateAccountHandler creates a new CreateAccountHandler.
func NewCreateAccountHandler(km *signer.KeyManager) *CreateAccountHandler {
	return &CreateAccountHandler{km: km}
}

// ServeHTTP implements the http.Handler interface.
func (h *CreateAccountHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	address, err := h.km.CreateKey()
	if err != nil {
		http.Error(w, "Failed to create new account: "+err.Error(), http.StatusInternalServerError)
		return
	}

	resp := CreateAccountResponse{
		Address: address.Hex(),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
	}
}

