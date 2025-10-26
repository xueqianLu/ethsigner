package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/hashicorp/vault/api"
	"github.com/xueqianLu/ethsigner/internal/config"
	"github.com/xueqianLu/ethsigner/internal/handler"
	"github.com/xueqianLu/ethsigner/internal/middleware"
	"github.com/xueqianLu/ethsigner/internal/server"
	"github.com/xueqianLu/ethsigner/internal/signer"
)

func main() {
	// Load configuration
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Create Vault client
	vaultConfig := api.DefaultConfig()
	if err := vaultConfig.ReadEnvironment(); err != nil {
		log.Printf("Warning: could not read Vault environment variables: %v", err)
	}
	if cfg.Vault.Addr != "" {
		vaultConfig.Address = cfg.Vault.Addr
	}
	vaultClient, err := api.NewClient(vaultConfig)
	if err != nil {
		log.Fatalf("Failed to create Vault client: %v", err)
	}
	if cfg.Vault.Token != "" {
		vaultClient.SetToken(cfg.Vault.Token)
	}

	// Initialize components
	keyManager, err := signer.NewKeyManager(vaultClient, cfg.Vault.TransitPath)
	if err != nil {
		log.Fatalf("Failed to create KeyManager: %v", err)
	}

	ethSigner := signer.NewSigner(keyManager)
	authMiddleware := middleware.NewAuthMiddleware(cfg.Auth.APIKey, cfg.Auth.APISecret)

	// Setup handlers
	healthHandler := handler.NewHealthHandler()
	accountsHandler := handler.NewAccountsHandler(keyManager)
	createAccountHandler := handler.NewCreateAccountHandler(keyManager)
	signTxHandler := handler.NewSignTxHandler(ethSigner)
	signMessageHandler := handler.NewSignMessageHandler(ethSigner)

	// Setup routes
	mux := http.NewServeMux()
	mux.Handle("/health", healthHandler)
	mux.Handle("/accounts", authMiddleware.Wrap(accountsHandler))
	mux.Handle("/create-account", authMiddleware.Wrap(createAccountHandler))
	mux.Handle("/sign-transaction", authMiddleware.Wrap(signTxHandler))
	mux.Handle("/sign-message", authMiddleware.Wrap(signMessageHandler))

	// Start server
	srv := server.NewServer(mux, cfg.Server.Port)
	fmt.Printf("Server listening on port %s\n", cfg.Server.Port)
	log.Fatal(srv.ListenAndServe())
}
