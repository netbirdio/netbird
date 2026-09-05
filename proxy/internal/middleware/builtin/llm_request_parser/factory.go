package llm_request_parser

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/netbirdio/netbird/proxy/internal/middleware"
	"github.com/netbirdio/netbird/proxy/internal/middleware/builtin"
)

// config is the on-wire config envelope for the middleware.
//
// ProviderID, when set, names the parser to use directly (matched
// against llm.ParserByName, e.g. "openai", "anthropic"). The
// agent-network synthesiser stamps this so requests routed through a
// synthesised provider service don't depend on URL-shape sniffing,
// which is the only signal the middleware otherwise has.
type config struct {
	ProviderID string `json:"provider_id,omitempty"`
	// RedactPii, when true, runs PII redaction over the captured raw prompt
	// before it is emitted as llm.request_prompt_raw — so the
	// agent-network access-log row does NOT carry raw emails / SSNs /
	// phone numbers even though the framework's per-key redactor (Scan)
	// doesn't cover those prompt-shaped patterns. Sourced by the
	// synthesiser from the account's redact_pii toggle.
	RedactPii bool `json:"redact_pii,omitempty"`
	// CapturePrompt gates emission of llm.request_prompt_raw. A nil pointer
	// preserves the legacy default (emit), so callers that don't know about
	// the toggle (or pre-existing tests with empty config) keep working.
	// The synthesiser sets this explicitly to the account's
	// enable_prompt_collection toggle: false here suppresses the key
	// entirely so the access-log row carries no prompt content at all,
	// independent of redact_pii (which only controls the form of the
	// content when it IS emitted).
	CapturePrompt *bool `json:"capture_prompt,omitempty"`
}

// Factory builds llm_request_parser instances from raw config bytes.
type Factory struct{}

// ID returns the registry identifier.
func (Factory) ID() string { return ID }

// New constructs a middleware instance. Empty, null, and {} configs are
// accepted; non-empty rawConfig that fails to unmarshal is rejected so
// misconfigurations surface at chain build time.
func (Factory) New(rawConfig []byte) (middleware.Middleware, error) {
	var cfg config
	if len(bytes.TrimSpace(rawConfig)) > 0 {
		// Strict decode: a typo'd field (e.g. "capture_prompts") must fail
		// chain build rather than silently fall back to the emit-everything
		// default and leak prompts.
		dec := json.NewDecoder(bytes.NewReader(rawConfig))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&cfg); err != nil {
			return nil, fmt.Errorf("decode config: %w", err)
		}
	}
	// Default capturePrompt to true (legacy emission) when the field is
	// absent so non-agent-network callers and pre-toggle tests keep working.
	capturePrompt := true
	if cfg.CapturePrompt != nil {
		capturePrompt = *cfg.CapturePrompt
	}
	return middlewareImpl{providerID: cfg.ProviderID, redactPii: cfg.RedactPii, capturePrompt: capturePrompt}, nil
}

func init() {
	builtin.Register(Factory{})
}
