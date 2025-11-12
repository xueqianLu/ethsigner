package main

import (
	"fmt"
	"github.com/xueqianLu/ethsigner/pkg/client"
	"log"
	"math/big"
)

const (
	baseURL   = "http://localhost:2818"
	apiKey    = ""
	apiSecret = ""
)

func main() {
	// Create a new client
	c := client.NewClient(baseURL, apiKey, apiSecret)

	// 1. Health Check
	fmt.Println("1. Performing Health Check...")
	health, err := c.Health()
	if err != nil {
		log.Fatalf("Health check failed: %v", err)
	}
	fmt.Printf("   Health status: %s\n\n", health)

	// 3. Get All Accounts
	//fmt.Println("3. Getting All Accounts...")
	accounts, err := c.GetAccounts()
	if err != nil {
		log.Fatalf("Failed to get accounts: %v", err)
	}
	fmt.Printf("   Available accounts: %v\n\n", accounts)
	//
	// 2. Create a new Account via the API
	//fmt.Println("Creating a new account...")
	createResp, err := c.CreateAccount()
	if err != nil {
		log.Fatalf("Failed to create account: %v", err)
	}
	fmt.Printf("   Successfully created new account: %s\n", createResp.Address)
	fmt.Printf("   IMPORTANT: Store this secret securely: %s\n\n", createResp.Secret)

	// Use the newly created account and password for the next steps
	signerAddress := createResp.Address
	signerPassword := createResp.Secret

	// 4. Sign a Legacy Transaction with the new account
	fmt.Println("4. Signing a Legacy Transaction...")
	legacyTxReq := client.SignTxRequest{
		From:     signerAddress,
		Secret:   signerPassword,
		To:       "0x70997970C51812dc3A010C7d01b50e0d17dc79C8", // An example recipient
		Nonce:    0,
		Value:    big.NewInt(10000000000000000), // 0.01 ETH
		Data:     []byte{},
		GasLimit: 21000,
		GasPrice: big.NewInt(20000000000), // 20 Gwei
		ChainID:  "1337",                  // Local testnet chain ID
	}
	signedLegacyTx, err := c.SignTransaction(legacyTxReq)
	if err != nil {
		log.Fatalf("Failed to sign legacy transaction: %v", err)
	}
	fmt.Printf("   Signed Legacy Tx: %s\n\n", signedLegacyTx.RawTx)

	// 5. Sign an EIP-1559 Transaction with the new account
	fmt.Println("5. Signing an EIP-1559 Transaction...")
	eip1559TxReq := client.SignTxRequest{
		From:      signerAddress,
		Secret:    signerPassword,
		To:        "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
		Nonce:     1,
		Value:     big.NewInt(20000000000000000), // 0.02 ETH
		Data:      []byte("hello"),
		GasLimit:  23000,
		GasFeeCap: big.NewInt(30000000000), // 30 Gwei
		GasTipCap: big.NewInt(20000000000), // 2 Gwei
		ChainID:   "1337",
	}
	signedEIP1559Tx, err := c.SignTransaction(eip1559TxReq)
	if err != nil {
		log.Fatalf("Failed to sign EIP-1559 transaction: %v", err)
	}
	fmt.Printf("   Signed EIP-1559 Tx: %s\n\n", signedEIP1559Tx.RawTx)

	// 6. Sign a Message with the new account
	fmt.Println("6. Signing a Message...")
	messageReq := client.SignMessageRequest{
		From:    signerAddress,
		Secret:  signerPassword,
		Message: "Hello, Vault!",
	}
	signedMessage, err := c.SignMessage(messageReq)
	if err != nil {
		log.Fatalf("Failed to sign message: %v", err)
	}
	fmt.Printf("   Message Signature: %s\n", signedMessage.Signature)
}
