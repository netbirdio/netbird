package llm_response_parser

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/netbirdio/netbird/proxy/internal/middleware"
	"github.com/netbirdio/netbird/proxy/internal/middleware/builtin"
)

// Factory constructs configured Middleware instances for the registry.
type Factory struct{}

// ID returns the registry identifier.
func (Factory) ID() string { return ID }

// New decodes RawConfig (empty / null / "{}" all accepted) and returns
// a configured Middleware. Construction never fails on a well-formed
// empty config; only structurally invalid JSON is rejected.
func (Factory) New(rawConfig []byte) (middleware.Middleware, error) {
	cfg, err := decodeConfig(rawConfig)
	if err != nil {
		return nil, fmt.Errorf("decode config: %w", err)
	}
	return New(cfg), nil
}

func decodeConfig(raw []byte) (config, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return config{}, nil
	}
	var cfg config
	if err := json.Unmarshal(trimmed, &cfg); err != nil {
		return config{}, err
	}
	return cfg, nil
}

func init() {
	builtin.Register(Factory{})
}
