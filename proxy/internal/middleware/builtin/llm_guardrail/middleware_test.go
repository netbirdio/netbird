package llm_guardrail

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/proxy/internal/middleware"
)

func metaValue(t *testing.T, kvs []middleware.KV, key string) (string, bool) {
	t.Helper()
	for _, kv := range kvs {
		if kv.Key == key {
			return kv.Value, true
		}
	}
	return "", false
}

func newInput(meta ...middleware.KV) *middleware.Input {
	return &middleware.Input{Slot: middleware.SlotOnRequest, Metadata: meta}
}

const (
	testProvider  = "prov-1"
	otherProvider = "prov-2"
)

// providerCfg builds a Config restricting testProvider to the given models.
func providerCfg(models ...string) Config {
	return Config{ProviderAllowlists: map[string][]string{testProvider: models}}
}

// newInputProvider builds an input that carries a resolved provider id (as
// llm_router would stamp) plus any extra metadata.
func newInputProvider(provider string, meta ...middleware.KV) *middleware.Input {
	all := make([]middleware.KV, 0, len(meta)+1)
	all = append(all, middleware.KV{Key: middleware.KeyLLMResolvedProviderID, Value: provider})
	all = append(all, meta...)
	return &middleware.Input{Slot: middleware.SlotOnRequest, Metadata: all}
}

func TestMiddlewareIdentity(t *testing.T) {
	mw := New(Config{})
	assert.Equal(t, ID, mw.ID(), "middleware ID must be llm_guardrail")
	assert.Equal(t, "1.0.0", mw.Version(), "version must be 1.0.0")
	assert.Equal(t, middleware.SlotOnRequest, mw.Slot(), "guardrail must run in SlotOnRequest")
	assert.False(t, mw.MutationsSupported(), "guardrail must not mutate requests")
	assert.Equal(t, []string{"application/json"}, mw.AcceptedContentTypes(), "guardrail accepts application/json bodies")
	assert.Equal(t,
		[]string{
			middleware.KeyLLMPolicyDecision,
			middleware.KeyLLMPolicyReason,
			middleware.KeyLLMRequestPrompt,
		},
		mw.MetadataKeys(),
		"metadata key allowlist must match the spec",
	)
	require.NoError(t, mw.Close())
}

func TestAllowlistEmptyAllowsAnyModel(t *testing.T) {
	mw := New(Config{})
	out, err := mw.Invoke(context.Background(), newInputProvider(testProvider,
		middleware.KV{Key: middleware.KeyLLMModel, Value: "gpt-4o"},
	))
	require.NoError(t, err)
	require.NotNil(t, out)
	assert.Equal(t, middleware.DecisionAllow, out.Decision, "no provider allowlists must allow any model")
	v, ok := metaValue(t, out.Metadata, middleware.KeyLLMPolicyDecision)
	require.True(t, ok, "decision metadata must be emitted")
	assert.Equal(t, "allow", v, "decision must be allow")
	r, ok := metaValue(t, out.Metadata, middleware.KeyLLMPolicyReason)
	require.True(t, ok, "reason metadata must be emitted")
	assert.Equal(t, "", r, "reason must be empty on allow")
}

func TestAllowlistMatchAllows(t *testing.T) {
	mw := New(providerCfg("gpt-4o", "claude-opus-4"))
	out, err := mw.Invoke(context.Background(), newInputProvider(testProvider,
		middleware.KV{Key: middleware.KeyLLMModel, Value: "gpt-4o"},
	))
	require.NoError(t, err)
	assert.Equal(t, middleware.DecisionAllow, out.Decision, "model in allowlist must be allowed")
}

func TestAllowlistMissDenies(t *testing.T) {
	mw := New(providerCfg("gpt-4o"))
	out, err := mw.Invoke(context.Background(), newInputProvider(testProvider,
		middleware.KV{Key: middleware.KeyLLMModel, Value: "claude-opus-4"},
	))
	require.NoError(t, err)
	require.NotNil(t, out)
	assert.Equal(t, middleware.DecisionDeny, out.Decision, "non-allowlisted model must be denied")
	assert.Equal(t, 403, out.DenyStatus, "deny status must be 403")
	require.NotNil(t, out.DenyReason, "deny reason must be populated")
	assert.Equal(t, "llm_policy.model_blocked", out.DenyReason.Code, "deny code must match spec")
	assert.Equal(t, "model is not in the policy allowlist", out.DenyReason.Message, "deny message must match spec")
	assert.Equal(t, "claude-opus-4", out.DenyReason.Details["model"], "deny details must include the offending model")

	dec, _ := metaValue(t, out.Metadata, middleware.KeyLLMPolicyDecision)
	assert.Equal(t, "deny", dec, "decision metadata must be deny")
	reason, _ := metaValue(t, out.Metadata, middleware.KeyLLMPolicyReason)
	assert.Equal(t, "model_blocked", reason, "reason metadata must be model_blocked")
}

func TestAllowlistCaseInsensitive(t *testing.T) {
	mw := New(providerCfg("  GPT-4o  ", "Claude-OPUS-4"))
	cases := []string{"gpt-4o", "GPT-4O", "  claude-opus-4 "}
	for _, model := range cases {
		out, err := mw.Invoke(context.Background(), newInputProvider(testProvider,
			middleware.KV{Key: middleware.KeyLLMModel, Value: model},
		))
		require.NoError(t, err)
		assert.Equal(t, middleware.DecisionAllow, out.Decision, "case/whitespace variants must match: %q", model)
	}
}

func TestAllowlistMissingModelKeyDenies(t *testing.T) {
	// Fail closed: with an allowlist in effect for the resolved provider, a
	// request whose model the parser could not extract (URL/path-routed
	// providers such as Bedrock or Vertex whose shape wasn't recognised) must be
	// denied, not allowed.
	mw := New(providerCfg("gpt-4o"))
	out, err := mw.Invoke(context.Background(), newInputProvider(testProvider))
	require.NoError(t, err)
	require.NotNil(t, out)
	assert.Equal(t, middleware.DecisionDeny, out.Decision, "absent model must be denied when the provider is restricted")
	assert.Equal(t, 403, out.DenyStatus, "deny status must be 403")
	require.NotNil(t, out.DenyReason, "deny reason must be populated")
	assert.Equal(t, "llm_policy.model_unknown", out.DenyReason.Code, "deny code must be model_unknown")
	dec, _ := metaValue(t, out.Metadata, middleware.KeyLLMPolicyDecision)
	assert.Equal(t, "deny", dec, "decision must be deny when model key is absent")
	reason, _ := metaValue(t, out.Metadata, middleware.KeyLLMPolicyReason)
	assert.Equal(t, "model_unknown", reason, "reason metadata must be model_unknown")
}

func TestAllowlistEmptyModelValueDenies(t *testing.T) {
	// A present-but-empty model is as undeterminable as an absent one.
	mw := New(providerCfg("gpt-4o"))
	out, err := mw.Invoke(context.Background(), newInputProvider(testProvider,
		middleware.KV{Key: middleware.KeyLLMModel, Value: "   "},
	))
	require.NoError(t, err)
	require.NotNil(t, out)
	assert.Equal(t, middleware.DecisionDeny, out.Decision, "empty model must be denied when the provider is restricted")
	require.NotNil(t, out.DenyReason, "deny reason must be populated")
	assert.Equal(t, "llm_policy.model_unknown", out.DenyReason.Code, "deny code must be model_unknown")
}

func TestAllowlistEmptyListAllowsMissingModel(t *testing.T) {
	// Without any provider allowlists there is nothing to enforce, so a missing
	// model is still allowed — the fail-closed rule only applies when a
	// restriction is in effect.
	mw := New(Config{})
	out, err := mw.Invoke(context.Background(), newInput())
	require.NoError(t, err)
	assert.Equal(t, middleware.DecisionAllow, out.Decision, "no allowlist must allow even without a model")
}

func TestUnrestrictedProviderAllowsAnyModel(t *testing.T) {
	// testProvider is restricted, but the request resolved to otherProvider,
	// which carries no allowlist. Its traffic must not be caught by the other
	// provider's restriction — this is the cross-provider-leak / false-deny
	// guard. Management owns any per-policy/group decision for otherProvider.
	mw := New(providerCfg("gpt-4o"))
	out, err := mw.Invoke(context.Background(), newInputProvider(otherProvider,
		middleware.KV{Key: middleware.KeyLLMModel, Value: "claude-opus-4"},
	))
	require.NoError(t, err)
	assert.Equal(t, middleware.DecisionAllow, out.Decision, "an unrestricted provider must not inherit another provider's allowlist")
}

func TestPerProviderAllowlistsAreIsolated(t *testing.T) {
	// gpt-4o is allowed only on testProvider; claude-opus-4 only on
	// otherProvider. A model allowlisted for one provider must not be usable on
	// the other — the fail-closed layer never unions allowlists across providers.
	mw := New(Config{ProviderAllowlists: map[string][]string{
		testProvider:  {"gpt-4o"},
		otherProvider: {"claude-opus-4"},
	}})
	out, err := mw.Invoke(context.Background(), newInputProvider(testProvider,
		middleware.KV{Key: middleware.KeyLLMModel, Value: "claude-opus-4"},
	))
	require.NoError(t, err)
	assert.Equal(t, middleware.DecisionDeny, out.Decision, "claude-opus-4 is allowed only on otherProvider, not testProvider")
	require.NotNil(t, out.DenyReason)
	assert.Equal(t, "llm_policy.model_blocked", out.DenyReason.Code, "cross-provider model must be blocked, not model_unknown")
}

func TestRestrictionsButNoResolvedProviderFailsClosed(t *testing.T) {
	// Restrictions exist for the account but the resolved provider id is absent,
	// so the request cannot be scoped to a provider. Fail closed rather than
	// wave it through.
	mw := New(providerCfg("gpt-4o"))
	out, err := mw.Invoke(context.Background(), newInput(
		middleware.KV{Key: middleware.KeyLLMModel, Value: "gpt-4o"},
	))
	require.NoError(t, err)
	require.NotNil(t, out)
	assert.Equal(t, middleware.DecisionDeny, out.Decision, "missing resolved provider must fail closed when restrictions exist")
	require.NotNil(t, out.DenyReason)
	assert.Equal(t, "llm_policy.model_unknown", out.DenyReason.Code, "deny code must be model_unknown")
}

func TestPromptCaptureDisabledEmitsNoPrompt(t *testing.T) {
	mw := New(Config{})
	out, err := mw.Invoke(context.Background(), newInput(
		middleware.KV{Key: middleware.KeyLLMRequestPromptRaw, Value: "hello world"},
	))
	require.NoError(t, err)
	_, ok := metaValue(t, out.Metadata, middleware.KeyLLMRequestPrompt)
	assert.False(t, ok, "prompt must not be emitted when capture is disabled")
}

func TestPromptCaptureNoRedactionEmitsRaw(t *testing.T) {
	mw := New(Config{PromptCapture: PromptCapture{Enabled: true}})
	raw := "hello world from user@example.com"
	out, err := mw.Invoke(context.Background(), newInput(
		middleware.KV{Key: middleware.KeyLLMRequestPromptRaw, Value: raw},
	))
	require.NoError(t, err)
	prompt, ok := metaValue(t, out.Metadata, middleware.KeyLLMRequestPrompt)
	require.True(t, ok, "prompt must be emitted when capture is enabled")
	assert.Equal(t, raw, prompt, "prompt must pass through unchanged when redaction is off")
}

func TestPromptCaptureWithRedactionRedacts(t *testing.T) {
	mw := New(Config{PromptCapture: PromptCapture{Enabled: true, RedactPii: true}})
	raw := "contact me at user@example.com or +14155551234"
	out, err := mw.Invoke(context.Background(), newInput(
		middleware.KV{Key: middleware.KeyLLMRequestPromptRaw, Value: raw},
	))
	require.NoError(t, err)
	prompt, ok := metaValue(t, out.Metadata, middleware.KeyLLMRequestPrompt)
	require.True(t, ok, "prompt must be emitted when capture is enabled")
	assert.Contains(t, prompt, "[REDACTED:email]", "email must be redacted")
	assert.Contains(t, prompt, "[REDACTED:phone]", "phone must be redacted")
	assert.NotContains(t, prompt, "user@example.com", "raw email must not leak")
}

func TestPromptCaptureRedactionTruncatesIfGrows(t *testing.T) {
	mw := New(Config{PromptCapture: PromptCapture{Enabled: true, RedactPii: true}})
	body := strings.Repeat("a", maxPromptBytes-10) + " user@example.com"
	out, err := mw.Invoke(context.Background(), newInput(
		middleware.KV{Key: middleware.KeyLLMRequestPromptRaw, Value: body},
	))
	require.NoError(t, err)
	prompt, ok := metaValue(t, out.Metadata, middleware.KeyLLMRequestPrompt)
	require.True(t, ok, "prompt must be emitted when capture is enabled")
	assert.LessOrEqual(t, len(prompt), maxPromptBytes, "prompt must be truncated to maxPromptBytes")
}

func TestPromptCaptureMissingRawNoEmit(t *testing.T) {
	mw := New(Config{PromptCapture: PromptCapture{Enabled: true, RedactPii: true}})
	out, err := mw.Invoke(context.Background(), newInput())
	require.NoError(t, err)
	_, ok := metaValue(t, out.Metadata, middleware.KeyLLMRequestPrompt)
	assert.False(t, ok, "prompt must not be emitted when raw key is missing")
}

func TestFactoryAcceptsZeroConfigs(t *testing.T) {
	cases := map[string][]byte{
		"nil":         nil,
		"empty":       []byte(""),
		"whitespace":  []byte("   \n  "),
		"null":        []byte("null"),
		"emptyObject": []byte("{}"),
	}
	f := Factory{}
	for name, raw := range cases {
		mw, err := f.New(raw)
		require.NoError(t, err, "case %s must yield a zero-value config", name)
		require.NotNil(t, mw)
		assert.Equal(t, ID, mw.ID(), "case %s must build a guardrail middleware", name)
	}
}

func TestFactoryDecodesValidConfig(t *testing.T) {
	cfg := Config{
		ProviderAllowlists: map[string][]string{testProvider: {"gpt-4o"}},
		PromptCapture:      PromptCapture{Enabled: true, RedactPii: true},
	}
	raw, err := json.Marshal(cfg)
	require.NoError(t, err, "marshalling test config must succeed")
	mw, err := Factory{}.New(raw)
	require.NoError(t, err)
	require.NotNil(t, mw)
}

func TestFactoryRejectsMalformedJSON(t *testing.T) {
	mw, err := Factory{}.New([]byte("{not-json"))
	assert.Error(t, err, "malformed JSON must surface as a factory error")
	assert.Nil(t, mw, "no middleware must be returned on malformed config")
}

func TestFactoryNormalisesAllowlist(t *testing.T) {
	raw := []byte(`{"provider_allowlists":{"prov-1":["  GPT-4o  ","",""," Claude-3 "]}}`)
	mw, err := Factory{}.New(raw)
	require.NoError(t, err)
	out, err := mw.Invoke(context.Background(), newInputProvider(testProvider,
		middleware.KV{Key: middleware.KeyLLMModel, Value: "gpt-4o"},
	))
	require.NoError(t, err)
	assert.Equal(t, middleware.DecisionAllow, out.Decision, "factory must lowercase + trim allowlist entries")
	out2, err := mw.Invoke(context.Background(), newInputProvider(testProvider,
		middleware.KV{Key: middleware.KeyLLMModel, Value: "claude-3"},
	))
	require.NoError(t, err)
	assert.Equal(t, middleware.DecisionAllow, out2.Decision, "trimmed entry must still match")
}
