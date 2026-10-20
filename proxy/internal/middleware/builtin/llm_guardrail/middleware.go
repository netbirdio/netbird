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
	providerID, _ := lookupMetadata(in.Metadata, middleware.KeyLLMResolvedProviderID)
	surface, _ := lookupMetadata(in.Metadata, middleware.KeyLLMProvider)
	nonInference, _ := lookupMetadata(in.Metadata, middleware.KeyLLMNonInference)

	if denial := m.evaluateAllowlist(providerID, surface, model, modelPresent, nonInference == "true"); denial != nil {
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

// evaluateAllowlist denies when the resolved provider's allowlist rejects the
// model; nil means proceed. Scoped to the provider llm_router resolved, so an
// unrestricted provider (absent from config) is never caught by another's list.
func (m *Middleware) evaluateAllowlist(providerID, surface, model string, modelPresent, nonInference bool) *middleware.Output {
	if len(m.cfg.ProviderAllowlists) == 0 {
		return nil
	}
	// Restrictions exist but the resolved provider is unknown, so we can't tell
	// if this request targets a restricted provider — fail closed. llm_router
	// normally stamps the provider first, so this is a defensive guard.
	if providerID == "" {
		return denyModel(surface, "", denyCodeModelUnknown, denyMessageModelUnknown, denyReasonModelUnknown)
	}
	allowlist, restricted := m.cfg.ProviderAllowlists[providerID]
	if !restricted {
		// This provider has no allowlist (some authorising policy left it
		// unrestricted); management owns any per-policy/group decision.
		return nil
	}
	// Fail closed: with an allowlist in effect for this provider, a request whose
	// model the parser couldn't extract (absent/empty) is denied. This enforces
	// the allowlist for path-routed providers (Bedrock, Vertex) with no body model.
	//
	// The exception is a non-inference endpoint the router already authorised.
	// The model listing and the connection-warming probe name no model
	// anywhere — not in a body, not in the path — so failing closed here
	// rejected model discovery for exactly the accounts that configured an
	// allowlist, which is the outage this endpoint is meant to avoid. The
	// per-model lookup does name one (the router stamps it from the path), so
	// it still falls through to the allowlist check below.
	if !modelPresent || normaliseModel(model) == "" {
		if nonInference {
			return nil
		}
		return denyModel(surface, "", denyCodeModelUnknown, denyMessageModelUnknown, denyReasonModelUnknown)
	}
	if modelInAllowlist(allowlist, model) {
		return nil
	}
	return denyModel(surface, model, denyCodeModel, denyMessageModel, denyReasonModel)
}

// denyModel builds a 403 deny Output for a model-allowlist rejection. model is
// included in the details only when non-empty.
func denyModel(surface, model, code, message, reason string) *middleware.Output {
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
			Surface: surface,
		},
		Metadata: []middleware.KV{
			{Key: middleware.KeyLLMPolicyDecision, Value: "deny"},
			{Key: middleware.KeyLLMPolicyReason, Value: reason},
		},
	}
}

// modelInAllowlist reports whether the model matches any entry in the supplied
// (already-normalised) allowlist under the case-insensitive, trim-tolerant
// comparison rule.
func modelInAllowlist(allowlist []string, model string) bool {
	normalised := normaliseModel(model)
	if normalised == "" {
		return false
	}
	for _, allowed := range allowlist {
		if allowed == normalised {
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
