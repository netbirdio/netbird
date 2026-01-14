package proxy

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/caarlos0/env/v11"
)

var (
	ErrFailedToParseConfig = errors.New("failed to parse config from env")
)

// Config holds the configuration for the reverse proxy server
type Config struct {
	// ListenAddress is the address the proxy server will listen on (e.g., ":443" or "0.0.0.0:443")
	ListenAddress string `env:"NB_PROXY_LISTEN_ADDRESS" envDefault:":443" json:"listen_address"`

	// ReadTimeout is the maximum duration for reading the entire request, including the body
	ReadTimeout time.Duration `env:"NB_PROXY_READ_TIMEOUT" envDefault:"30s" json:"read_timeout"`

	// WriteTimeout is the maximum duration before timing out writes of the response
	WriteTimeout time.Duration `env:"NB_PROXY_WRITE_TIMEOUT" envDefault:"30s" json:"write_timeout"`

	// IdleTimeout is the maximum amount of time to wait for the next request when keep-alives are enabled
	IdleTimeout time.Duration `env:"NB_PROXY_IDLE_TIMEOUT" envDefault:"60s" json:"idle_timeout"`

	// ShutdownTimeout is the maximum duration to wait for graceful shutdown
	ShutdownTimeout time.Duration `env:"NB_PROXY_SHUTDOWN_TIMEOUT" envDefault:"10s" json:"shutdown_timeout"`

	// LogLevel sets the logging verbosity (debug, info, warn, error)
	LogLevel string `env:"NB_PROXY_LOG_LEVEL" envDefault:"info" json:"log_level"`

	// GRPCListenAddress is the address for the gRPC control server (empty to disable)
	GRPCListenAddress string `env:"NB_PROXY_GRPC_LISTEN_ADDRESS" envDefault:":50051" json:"grpc_listen_address"`

	// ProxyID is a unique identifier for this proxy instance
	ProxyID string `env:"NB_PROXY_ID" envDefault:"" json:"proxy_id"`

	// EnableGRPC enables the gRPC control server
	EnableGRPC bool `env:"NB_PROXY_ENABLE_GRPC" envDefault:"false" json:"enable_grpc"`
}

// ParseAndLoad parses configuration from environment variables
func ParseAndLoad() (Config, error) {
	var cfg Config

	if err := env.Parse(&cfg); err != nil {
		return cfg, fmt.Errorf("%w: %s", ErrFailedToParseConfig, err)
	}

	if err := cfg.Validate(); err != nil {
		return cfg, fmt.Errorf("invalid config: %w", err)
	}

	return cfg, nil
}

// LoadFromFile reads configuration from a JSON file
func LoadFromFile(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("failed to read config file: %w", err)
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("failed to parse config file: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return Config{}, fmt.Errorf("invalid config: %w", err)
	}

	return cfg, nil
}

// LoadFromFileOrEnv loads configuration from a file if path is provided, otherwise from environment variables
// Environment variables will override file-based configuration if both are present
func LoadFromFileOrEnv(configPath string) (Config, error) {
	var cfg Config

	// If config file is provided, load it first
	if configPath != "" {
		fileCfg, err := LoadFromFile(configPath)
		if err != nil {
			return Config{}, fmt.Errorf("failed to load config from file: %w", err)
		}
		cfg = fileCfg
	}

	// Parse environment variables (will override file config with any set env vars)
	if err := env.Parse(&cfg); err != nil {
		return Config{}, fmt.Errorf("%w: %s", ErrFailedToParseConfig, err)
	}

	if err := cfg.Validate(); err != nil {
		return Config{}, fmt.Errorf("invalid config: %w", err)
	}

	return cfg, nil
}

// Validate checks if the configuration is valid
func (c *Config) Validate() error {
	if c.ListenAddress == "" {
		return errors.New("listen_address is required")
	}

	validLogLevels := map[string]bool{
		"debug": true,
		"info":  true,
		"warn":  true,
		"error": true,
	}

	if !validLogLevels[c.LogLevel] {
		return fmt.Errorf("invalid log_level: %s (must be debug, info, warn, or error)", c.LogLevel)
	}

	return nil
}
