// Package llm_guardrail implements the SlotOnRequest middleware that
// enforces the per-target LLM guardrail policy: a model allowlist
// check and an opt-in prompt-capture step that may run a PII redactor
// before emitting the prompt into the metadata bag.
//
// The middleware runs after llm_request_parser, which is responsible
// for extracting the model and raw prompt onto the metadata side
// channel. llm_guardrail consumes those keys, decides allow/deny, and
// emits its own decision metadata plus the optional redacted prompt.
package llm_guardrail

import (
	"context"
	"unicode/utf8"

	"github.com/netbirdio/netbird/proxy/internal/llm"
	"github.com/netbirdio/netbird/proxy/internal/middleware"
)

// ID is the registry key for this middleware.
const ID = "llm_guardrail"

const (
	version          = "1.0.0"
	maxPromptBytes   = 3500
	denyCodeModel    = "llm_policy.model_blocked"
	denyReasonModel  = "model_blocked"
	denyMessageModel = "model is not in the policy allowlist"
	// Deny reason used when an allowlist is configured but the request model
	// could not be determined. URL/path-routed providers (AWS Bedrock, Google
	// Vertex, ...) carry the model outside the JSON body, so a request shape the
	// parser does not recognise reaches the guardrail with no model. Such a
	// request must be denied (fail closed), never waved through.
	denyCodeModelUnknown    = "llm_policy.model_unknown"
	denyReasonModelUnknown  = "model_unknown"
	denyMessageModelUnknown = "request model could not be determined for the policy allowlist"
)

// Middleware enforces the model allowlist and optionally captures the
// request prompt with PII redaction.
type Middleware struct {
	cfg Config
}

// New constructs a Middleware with the supplied configuration. Model
// allowlist entries are normalised so the runtime check is
// case-insensitive and trim-tolerant.
func New(cfg Config) *Middleware {
	return &Middleware{cfg: normaliseConfig(cfg)}
}

// ID returns the registry identifier.
func (m *Middleware) ID() string { return ID }

// Version returns the implementation version.
func (m *Middleware) Version() string { return version }

// Slot reports the chain slot the middleware lives in.
func (m *Middleware) Slot() middleware.Slot { return middleware.SlotOnRequest }

// AcceptedContentTypes lists the request body content types the
// middleware needs. Guardrail consumes metadata produced upstream and
// does not touch the body itself, but we keep application/json so the
// body policy retains the parsed payload upstream when required.
func (m *Middleware) AcceptedContentTypes() []string {
	return []string{"application/json"}
}

// MetadataKeys is the closed set of metadata keys this middleware may
// emit. The accumulator drops anything outside this allowlist.
func (m *Middleware) MetadataKeys() []string {
	return []string{
		middleware.KeyLLMPolicyDecision,
		middleware.KeyLLMPolicyReason,
		middleware.KeyLLMRequestPrompt,
	}
}

// MutationsSupported reports whether the middleware emits header / body
// mutations. Guardrail never mutates the request.
func (m *Middleware) MutationsSupported() bool { return false }

// Invoke runs the policy. The model allowlist is the only deny path;
// prompt capture only affects the metadata emitted alongside an allow.
func (m *Middleware) Invoke(_ context.Context, in *middleware.Input) (*middleware.Output, error) {
	model, modelPresent := lookupMetadata(in.Metadata, middleware.KeyLLMModel)

	if denial := m.evaluateAllowlist(model, modelPresent); denial != nil {
		return denial, nil
	}

	out := &middleware.Output{
		Decision: middleware.DecisionAllow,
		Metadata: []middleware.KV{
			{Key: middleware.KeyLLMPolicyDecision, Value: "allow"},
			{Key: middleware.KeyLLMPolicyReason, Value: ""},
		},
	}

	if prompt, ok := m.capturePrompt(in.Metadata); ok {
		out.Metadata = append(out.Metadata, middleware.KV{
			Key:   middleware.KeyLLMRequestPrompt,
			Value: prompt,
		})
	}

	return out, nil
}

// Close releases resources owned by the middleware. Stateless, so this
// is a no-op.
func (m *Middleware) Close() error { return nil }

// evaluateAllowlist returns a deny Output when the configured allowlist
// rejects the model. A nil return means the request should proceed.
func (m *Middleware) evaluateAllowlist(model string, modelPresent bool) *middleware.Output {
	if len(m.cfg.ModelAllowlist) == 0 {
		return nil
	}
	// Fail closed: with an allowlist configured, a request whose model the
	// upstream parser could not extract (absent or empty) must be denied rather
	// than allowed. This is what enforces the allowlist for URL/path-routed
	// providers (Bedrock, Vertex, ...) whose model lives outside the JSON body.
	if !modelPresent || normaliseModel(model) == "" {
		return denyModel("", denyCodeModelUnknown, denyMessageModelUnknown, denyReasonModelUnknown)
	}
	if m.modelInAllowlist(model) {
		return nil
	}
	return denyModel(model, denyCodeModel, denyMessageModel, denyReasonModel)
}

// denyModel builds a 403 deny Output for a model-allowlist rejection. model is
// included in the details only when non-empty.
func denyModel(model, code, message, reason string) *middleware.Output {
	details := map[string]string{}
	if model != "" {
		details["model"] = model
	}
	return &middleware.Output{
		Decision:   middleware.DecisionDeny,
		DenyStatus: 403,
		DenyReason: &middleware.DenyReason{
			Code:    code,
			Message: message,
			Details: details,
		},
		Metadata: []middleware.KV{
			{Key: middleware.KeyLLMPolicyDecision, Value: "deny"},
			{Key: middleware.KeyLLMPolicyReason, Value: reason},
		},
	}
}

// modelInAllowlist reports whether the model matches any allowlist
// entry under the case-insensitive, trim-tolerant comparison rule.
func (m *Middleware) modelInAllowlist(model string) bool {
	normalised := normaliseModel(model)
	if normalised == "" {
		return false
	}
	for _, allowed := range m.cfg.ModelAllowlist {
		if allowed == normalised {
			return true
		}
		// Accept a Vertex entry stored with its "@version" suffix against the
		// suffix-stripped request model. Entries without "@" stay exact.
		if v := llm.NormalizeVertexModel(allowed); v != "" && v != allowed && v == normalised {
			return true
		}
	}
	return false
}

// capturePrompt returns the prompt to emit and whether it should be
// emitted at all. The truncation guarantee is upheld here regardless of
// whether redaction grew the string.
func (m *Middleware) capturePrompt(meta []middleware.KV) (string, bool) {
	if !m.cfg.PromptCapture.Enabled {
		return "", false
	}
	raw, ok := lookupMetadata(meta, middleware.KeyLLMRequestPromptRaw)
	if !ok {
		return "", false
	}
	prompt := raw
	if m.cfg.PromptCapture.RedactPii {
		prompt = redactPII(prompt)
	}
	if len(prompt) > maxPromptBytes {
		// Back off to a UTF-8 rune boundary so we never emit a string
		// split mid-rune.
		cut := maxPromptBytes
		for cut > 0 && !utf8.RuneStart(prompt[cut]) {
			cut--
		}
		prompt = prompt[:cut]
	}
	return prompt, true
}

// lookupMetadata finds the first KV with the given key. Returns the
// value and true when present; the empty string and false otherwise.
func lookupMetadata(meta []middleware.KV, key string) (string, bool) {
	for _, kv := range meta {
		if kv.Key == key {
			return kv.Value, true
		}
	}
	return "", false
}
