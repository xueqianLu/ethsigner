package config

import (
	"github.com/spf13/viper"
	"log"
)

// Config holds the application configuration.
type Config struct {
	Server     ServerConfig     `mapstructure:"server"`
	KeyManager KeyManagerConfig `mapstructure:"key_manager"`
}

// KeyManagerConfig holds the configuration for the key manager.
type KeyManagerConfig struct {
	Type  string      `mapstructure:"type"` // "local" or "vault"
	Local LocalConfig `mapstructure:"local"`
	Vault VaultConfig `mapstructure:"vault"`
}

// LocalConfig holds the configuration for the local key manager.
type LocalConfig struct {
	KeyDir string `mapstructure:"key_dir"`
}

// ServerConfig holds the server configuration.
type ServerConfig struct {
	Port    string `mapstructure:"port"`
	Address string `mapstructure:"address"`
}

// VaultConfig holds the Vault configuration.
type VaultConfig struct {
	Address     string `mapstructure:"address"`
	Token       string `mapstructure:"token"`
	TransitPath string `mapstructure:"transit_path"`
}

// LoadConfig reads configuration from file or environment variables.
func LoadConfig() (config Config, err error) {
	viper.AddConfigPath(".")
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AutomaticEnv()

	// Set default values
	viper.SetDefault("server.port", "8080")
	viper.SetDefault("vault.addr", "http://127.0.0.1:8200")
	viper.SetDefault("vault.token", "root")
	viper.SetDefault("vault.transit_path", "transit")

	if err = viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			// Config file was found but another error was produced
			return
		}
	}

	err = viper.Unmarshal(&config)
	log.Printf("Loaded config: %+v", config)
	return
}
