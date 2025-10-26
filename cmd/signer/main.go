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

	var keyManager signer.KeyManager
	switch cfg.KeyManager.Type {
	case "local":
		keyManager, err = signer.NewLocalKeyManager(cfg.KeyManager.Local.KeyDir, cfg.KeyManager.Local.Password)
		if err != nil {
			log.Fatalf("Failed to initialize local key manager: %v", err)
		}
		log.Println("Using local key manager")
	case "vault":
		// Vault client configuration
		vaultConfig := &api.Config{
			Address: cfg.KeyManager.Vault.Address,
		}
		vaultClient, err := api.NewClient(vaultConfig)
		if err != nil {
			log.Fatalf("Failed to create Vault client: %v", err)
		}
		vaultClient.SetToken(cfg.KeyManager.Vault.Token)

		keyManager, err = signer.NewVaultKeyManager(vaultClient, cfg.KeyManager.Vault.TransitPath)
		if err != nil {
			log.Fatalf("Failed to initialize Vault key manager: %v", err)
		}
		log.Println("Using Vault key manager")
	default:
		log.Fatalf("Invalid key manager type specified: %s", cfg.KeyManager.Type)
	}

	// Create a new signer instance
	ethSigner := signer.NewSigner(keyManager)

	// Register handlers
	mux := http.NewServeMux()
	mux.Handle("/accounts", handler.NewAccountsHandler(ethSigner))
	mux.Handle("/create-account", handler.NewCreateAccountHandler(ethSigner))
	mux.Handle("/sign-transaction", handler.NewSignTxHandler(ethSigner))
	mux.Handle("/sign-message", handler.NewSignMessageHandler(ethSigner))
	mux.Handle("/health", handler.NewHealthHandler())

	// Apply middleware
	var finalHandler http.Handler = mux
	finalHandler = middleware.Logging(finalHandler)

	// Create a new server
	srv := server.NewServer(finalHandler, cfg.Server.Port)

	// Start the server
	log.Printf("Server starting on port %s", cfg.Server.Port)
	fmt.Printf("Server listening on port %s\n", cfg.Server.Port)
	log.Fatal(srv.ListenAndServe())
}
