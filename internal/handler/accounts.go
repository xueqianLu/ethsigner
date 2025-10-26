package handler

import (
	"encoding/json"
	"net/http"

	"github.com/xueqianLu/ethsigner/internal/signer"
)

// AccountsHandler handles requests for the list of accounts.
type AccountsHandler struct {
	km *signer.KeyManager
}

// NewAccountsHandler creates a new AccountsHandler.
func NewAccountsHandler(km *signer.KeyManager) *AccountsHandler {
	return &AccountsHandler{km: km}
}

// ServeHTTP implements the http.Handler interface.
func (h *AccountsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	accounts := h.km.GetAccounts()
	var accStrs []string
	for _, acc := range accounts {
		accStrs = append(accStrs, acc.Hex())
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(accStrs); err != nil {
		http.Error(w, "Failed to encode accounts", http.StatusInternalServerError)
	}
}

