package llm_guardrail

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/netbirdio/netbird/proxy/internal/middleware"
	"github.com/netbirdio/netbird/proxy/internal/middleware/builtin"
)

// Config is the JSON-decoded shape accepted by the factory. The
// runtime path consumes the normalised allowlist; raw config is not
// retained beyond construction.
type Config struct {
	ModelAllowlist []string      `json:"model_allowlist"`
	PromptCapture  PromptCapture `json:"prompt_capture"`
}

// PromptCapture toggles the optional prompt capture + redaction step
// that emits llm.request_prompt onto the metadata bag.
type PromptCapture struct {
	Enabled   bool `json:"enabled"`
	RedactPii bool `json:"redact_pii"`
}

// Factory builds a configured llm_guardrail middleware instance.
type Factory struct{}

// ID returns the registry identifier matching the middleware ID.
func (Factory) ID() string { return ID }

// New decodes the raw JSON config and returns a ready Middleware. An
// empty / null / empty-object payload yields a zero-value Config.
func (Factory) New(rawConfig []byte) (middleware.Middleware, error) {
	cfg := Config{}
	if len(rawConfig) > 0 && !isEmptyJSON(rawConfig) {
		if err := json.Unmarshal(rawConfig, &cfg); err != nil {
			return nil, fmt.Errorf("decode config: %w", err)
		}
	}
	return New(cfg), nil
}

// isEmptyJSON reports whether the payload is whitespace, null, or an
// empty object/array. The caller skips Unmarshal in that case so the
// zero-value Config flows through unchanged.
func isEmptyJSON(raw []byte) bool {
	trimmed := strings.TrimSpace(string(raw))
	switch trimmed {
	case "", "null", "{}", "[]":
		return true
	}
	return false
}

// normaliseConfig lowercases and trims allowlist entries so the runtime
// match is case-insensitive. Empty entries are dropped.
func normaliseConfig(cfg Config) Config {
	if len(cfg.ModelAllowlist) == 0 {
		return cfg
	}
	cleaned := make([]string, 0, len(cfg.ModelAllowlist))
	for _, entry := range cfg.ModelAllowlist {
		n := normaliseModel(entry)
		if n == "" {
			continue
		}
		cleaned = append(cleaned, n)
	}
	cfg.ModelAllowlist = cleaned
	return cfg
}

// normaliseModel lowercases and trims a single model identifier.
func normaliseModel(model string) string {
	return strings.ToLower(strings.TrimSpace(model))
}

func init() {
	builtin.Register(Factory{})
}
