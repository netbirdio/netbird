package llm_guardrail

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/netbirdio/netbird/proxy/internal/middleware"
	"github.com/netbirdio/netbird/proxy/internal/middleware/builtin"
)

// Config is the JSON-decoded shape accepted by the factory. The
// runtime path consumes the normalised allowlists; raw config is not
// retained beyond construction.
type Config struct {
	// ProviderAllowlists maps a resolved provider id (the value llm_router
	// stamps as KeyLLMResolvedProviderID) to that provider's model allowlist. A
	// provider present here is restricted to the listed models; a provider
	// absent is unrestricted. The synthesiser only lists a provider when EVERY
	// policy authorising it enables an allowlist, so a provider reachable by any
	// un-guardrailed policy is intentionally absent (unrestricted) here and the
	// precise per-policy/group decision is left to management. Keeping the gate
	// per-provider — rather than one account-wide union — is what stops a model
	// allowlisted for one provider from leaking onto another and stops an
	// un-guardrailed policy's traffic from being blocked by an unrelated
	// policy's allowlist.
	ProviderAllowlists map[string][]string `json:"provider_allowlists,omitempty"`
	PromptCapture      PromptCapture       `json:"prompt_capture"`
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
// match is case-insensitive. Empty entries are dropped. A provider whose
// entries all drop out keeps an empty (non-nil) list — an allowlist that
// permits nothing — which is the intended "deny every model" for that
// provider, distinct from the provider being absent (unrestricted).
func normaliseConfig(cfg Config) Config {
	if len(cfg.ProviderAllowlists) == 0 {
		cfg.ProviderAllowlists = nil
		return cfg
	}
	cleaned := make(map[string][]string, len(cfg.ProviderAllowlists))
	for provider, models := range cfg.ProviderAllowlists {
		list := make([]string, 0, len(models))
		for _, entry := range models {
			n := normaliseModel(entry)
			if n == "" {
				continue
			}
			list = append(list, n)
		}
		cleaned[provider] = list
	}
	cfg.ProviderAllowlists = cleaned
	return cfg
}

// normaliseModel lowercases and trims a single model identifier.
func normaliseModel(model string) string {
	return strings.ToLower(strings.TrimSpace(model))
}

func init() {
	builtin.Register(Factory{})
}
