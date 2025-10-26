package client

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/big"
	"net/http"
	"strconv"
	"time"
)

// CreateAccountResponse represents the response for a new account creation.
type CreateAccountResponse struct {
	Address string `json:"address"`
}

// SignTxRequest represents the request to sign a transaction.
type SignTxRequest struct {
	From      string   `json:"from"`
	To        string   `json:"to"`
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
	Message string `json:"message"`
}

// SignMessageResponse represents the response for a signed message.
type SignMessageResponse struct {
	Signature string `json:"signature"`
}

const (
	apiKeyHeader    = "X-API-Key"
	signatureHeader = "X-Signature"
	timestampHeader = "X-Timestamp"
)

// Client is a client for the ethsigner service.
type Client struct {
	baseURL    string
	apiKey     string
	apiSecret  string
	httpClient *http.Client
}

// NewClient creates a new ethsigner client.
func NewClient(baseURL, apiKey, apiSecret string) *Client {
	return &Client{
		baseURL:   baseURL,
		apiKey:    apiKey,
		apiSecret: apiSecret,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// Health checks the health of the signer service.
func (c *Client) Health() (string, error) {
	resp, err := c.httpClient.Get(c.baseURL + "/health")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("service returned non-OK status: %s, body: %s", resp.Status, string(body))
	}

	return string(body), nil
}

// GetAccounts retrieves the list of accounts managed by the signer.
func (c *Client) GetAccounts() ([]string, error) {
	var accounts []string
	err := c.doRequest(http.MethodGet, "/accounts", nil, &accounts)
	return accounts, err
}

// CreateAccount requests the creation of a new account in the signer.
func (c *Client) CreateAccount() (*CreateAccountResponse, error) {
	var resp CreateAccountResponse
	err := c.doRequest(http.MethodPost, "/create-account", nil, &resp)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}

// SignTransaction sends a transaction to the signer service to be signed.
func (c *Client) SignTransaction(req SignTxRequest) (*SignTxResponse, error) {
	var resp SignTxResponse
	err := c.doRequest(http.MethodPost, "/sign-transaction", req, &resp)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}

// SignMessage sends a message to the signer service to be signed.
func (c *Client) SignMessage(req SignMessageRequest) (*SignMessageResponse, error) {
	var resp SignMessageResponse
	err := c.doRequest(http.MethodPost, "/sign-message", req, &resp)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *Client) doRequest(method, path string, data, result interface{}) error {
	var reqBody []byte
	var err error

	if data != nil {
		reqBody, err = json.Marshal(data)
		if err != nil {
			return fmt.Errorf("failed to marshal request data: %w", err)
		}
	}

	req, err := http.NewRequest(method, c.baseURL+path, bytes.NewBuffer(reqBody))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	signature := c.calculateSignature(timestamp, reqBody)

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(apiKeyHeader, c.apiKey)
	req.Header.Set(timestampHeader, timestamp)
	req.Header.Set(signatureHeader, signature)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("request failed with status %d: %s", resp.StatusCode, string(respBody))
	}

	if result != nil {
		if err := json.Unmarshal(respBody, result); err != nil {
			return fmt.Errorf("failed to unmarshal response: %w", err)
		}
	}

	return nil
}

func (c *Client) calculateSignature(timestamp string, body []byte) string {
	payload := timestamp + string(body)
	mac := hmac.New(sha256.New, []byte(c.apiSecret))
	mac.Write([]byte(payload))
	return hex.EncodeToString(mac.Sum(nil))
}
