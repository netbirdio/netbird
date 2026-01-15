package proxy

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"time"

	"github.com/caarlos0/env/v11"

	"github.com/netbirdio/netbird/proxy/internal/reverseproxy"
)

var (
	ErrFailedToParseConfig = errors.New("failed to parse config from env")
)

// Duration is a time.Duration that can be unmarshaled from JSON as a string
type Duration time.Duration

// UnmarshalJSON implements json.Unmarshaler for Duration
func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}

	parsed, err := time.ParseDuration(s)
	if err != nil {
		return err
	}

	*d = Duration(parsed)
	return nil
}

// MarshalJSON implements json.Marshaler for Duration
func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Duration(d).String())
}

// ToDuration converts Duration to time.Duration
func (d Duration) ToDuration() time.Duration {
	return time.Duration(d)
}

// Config holds the configuration for the reverse proxy server
type Config struct {
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

	// Reverse Proxy Configuration
	ReverseProxy reverseproxy.Config `json:"reverse_proxy"`
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
	} else {
		// Parse environment variables (will override file config with any set env vars)
		if err := env.Parse(&cfg); err != nil {
			return Config{}, fmt.Errorf("%w: %s", ErrFailedToParseConfig, err)
		}
	}

	if err := cfg.Validate(); err != nil {
		return Config{}, fmt.Errorf("invalid config: %w", err)
	}

	return cfg, nil
}

// UnmarshalJSON implements custom JSON unmarshaling with automatic duration parsing
// Uses reflection to find all time.Duration fields and parse them from string
func (c *Config) UnmarshalJSON(data []byte) error {
	// First unmarshal into a map to get raw values
	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	// Get reflection value and type
	val := reflect.ValueOf(c).Elem()
	typ := val.Type()

	// Iterate through all fields
	for i := 0; i < val.NumField(); i++ {
		field := val.Field(i)
		fieldType := typ.Field(i)

		// Get JSON tag name
		jsonTag := fieldType.Tag.Get("json")
		if jsonTag == "" || jsonTag == "-" {
			continue
		}

		// Parse tag to get field name (handle omitempty, etc.)
		jsonFieldName := jsonTag
		if idx := len(jsonTag); idx > 0 {
			for j, c := range jsonTag {
				if c == ',' {
					jsonFieldName = jsonTag[:j]
					break
				}
			}
		}

		// Get raw value from JSON
		rawValue, exists := raw[jsonFieldName]
		if !exists {
			continue
		}

		// Check if this field is a time.Duration
		if field.Type() == reflect.TypeOf(time.Duration(0)) {
			// Try to parse as string duration
			if strValue, ok := rawValue.(string); ok {
				duration, err := time.ParseDuration(strValue)
				if err != nil {
					return fmt.Errorf("invalid duration for field %s: %w", jsonFieldName, err)
				}
				field.Set(reflect.ValueOf(duration))
			} else {
				return fmt.Errorf("field %s must be a duration string", jsonFieldName)
			}
		} else {
			// For non-duration fields, unmarshal normally
			fieldData, err := json.Marshal(rawValue)
			if err != nil {
				return fmt.Errorf("failed to marshal field %s: %w", jsonFieldName, err)
			}

			// Create a new instance of the field type
			if field.CanSet() {
				newVal := reflect.New(field.Type())
				if err := json.Unmarshal(fieldData, newVal.Interface()); err != nil {
					return fmt.Errorf("failed to unmarshal field %s: %w", jsonFieldName, err)
				}
				field.Set(newVal.Elem())
			}
		}
	}

	return nil
}

// Validate checks if the configuration is valid
func (c *Config) Validate() error {
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
