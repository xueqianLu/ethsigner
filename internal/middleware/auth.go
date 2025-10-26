package middleware

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io/ioutil"
	"net/http"
	"strconv"
	"time"
)

const (
	apiKeyHeader    = "X-API-Key"
	signatureHeader = "X-Signature"
	timestampHeader = "X-Timestamp"
	maxTimeSkew     = 60 // seconds
)

// AuthMiddleware provides HMAC-based authentication.
type AuthMiddleware struct {
	apiKey    string
	apiSecret string
}

// NewAuthMiddleware creates a new AuthMiddleware.
func NewAuthMiddleware(apiKey, apiSecret string) *AuthMiddleware {
	return &AuthMiddleware{
		apiKey:    apiKey,
		apiSecret: apiSecret,
	}
}

// Wrap wraps an http.Handler with authentication.
func (m *AuthMiddleware) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 1. Check API Key
		requestAPIKey := r.Header.Get(apiKeyHeader)
		if requestAPIKey != m.apiKey {
			http.Error(w, "Invalid API Key", http.StatusUnauthorized)
			return
		}

		// 2. Check Timestamp
		timestampStr := r.Header.Get(timestampHeader)
		if timestampStr == "" {
			http.Error(w, "Missing timestamp header", http.StatusUnauthorized)
			return
		}
		timestamp, err := strconv.ParseInt(timestampStr, 10, 64)
		if err != nil {
			http.Error(w, "Invalid timestamp format", http.StatusUnauthorized)
			return
		}
		if time.Now().Unix()-timestamp > maxTimeSkew {
			http.Error(w, "Timestamp expired", http.StatusUnauthorized)
			return
		}

		// 3. Check Signature
		requestSignature := r.Header.Get(signatureHeader)
		if requestSignature == "" {
			http.Error(w, "Missing signature header", http.StatusUnauthorized)
			return
		}

		// Read the body
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "Failed to read request body", http.StatusInternalServerError)
			return
		}
		// Restore the body so the next handler can read it
		r.Body = ioutil.NopCloser(bytes.NewBuffer(body))

		// Create the payload to sign
		payload := timestampStr + string(body)

		// Calculate the expected signature
		mac := hmac.New(sha256.New, []byte(m.apiSecret))
		mac.Write([]byte(payload))
		expectedSignature := hex.EncodeToString(mac.Sum(nil))

		// Compare signatures
		if !hmac.Equal([]byte(requestSignature), []byte(expectedSignature)) {
			http.Error(w, "Invalid signature", http.StatusUnauthorized)
			return
		}

		// If all checks pass, call the next handler
		next.ServeHTTP(w, r)
	})
}

