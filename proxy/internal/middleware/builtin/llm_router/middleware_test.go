package llm_router

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/proxy/internal/middleware"
)

// metaValue returns the value for the first KV with the given key.
func metaValue(t *testing.T, kvs []middleware.KV, key string) (string, bool) {
	t.Helper()
	for _, kv := range kvs {
		if kv.Key == key {
			return kv.Value, true
		}
	}
	return "", false
}

// defaultTestGroup is the group id used by routes and inputs in tests
// that don't specifically exercise the group-filter logic. Pairing it
// with the same id on every test route keeps the legacy assertions
// focused on routing/path behaviour without each one having to bake in
// its own ACL.
const defaultTestGroup = "grp-test"

// newInputWithModel returns an Input carrying llm.model in its metadata
// bag, mimicking the post-llm_request_parser state the router observes
// in production. UserGroups is populated with defaultTestGroup so the
// router's group-filter pass authorises any test route whose
// AllowedGroupIDs contains the same id.
func newInputWithModel(model string) *middleware.Input {
	return &middleware.Input{
		Slot:       middleware.SlotOnRequest,
		Metadata:   []middleware.KV{{Key: middleware.KeyLLMModel, Value: model}},
		UserGroups: []string{defaultTestGroup},
	}
}

// newInputWithModelAndURL returns an Input carrying both llm.model and
// a request URL so router tests can exercise path-based disambiguation.
func newInputWithModelAndURL(model, reqURL string) *middleware.Input {
	in := newInputWithModel(model)
	in.URL = reqURL
	return in
}

func TestMiddlewareIdentity(t *testing.T) {
	mw := New(Config{})
	assert.Equal(t, ID, mw.ID(), "middleware ID must be llm_router")
	assert.Equal(t, Version, mw.Version(), "version must match the constant")
	assert.Equal(t, middleware.SlotOnRequest, mw.Slot(), "router must run in SlotOnRequest")
	assert.True(t, mw.MutationsSupported(), "router must declare mutations support")
	assert.Nil(t, mw.AcceptedContentTypes(), "router does not inspect bodies")
	assert.ElementsMatch(t,
		[]string{
			middleware.KeyLLMResolvedProviderID,
			middleware.KeyLLMAuthorisingGroups,
			middleware.KeyLLMPolicyDecision,
			middleware.KeyLLMPolicyReason,
		},
		mw.MetadataKeys(),
		"metadata key allowlist must match the spec",
	)
	require.NoError(t, mw.Close())
}

func TestRouter_HappyPath(t *testing.T) {
	route := ProviderRoute{
		ID:              "openai-prod",
		Models:          []string{"gpt-4o"},
		AllowedGroupIDs: []string{defaultTestGroup},
		UpstreamScheme:  "https",
		UpstreamHost:    "api.openai.com",
		AuthHeaderName:  "Authorization",
		AuthHeaderValue: "Bearer sk-test-123",
	}
	mw := New(Config{Providers: []ProviderRoute{route}})

	out, err := mw.Invoke(context.Background(), newInputWithModel("gpt-4o"))
	require.NoError(t, err)
	require.NotNil(t, out)
	assert.Equal(t, middleware.DecisionAllow, out.Decision, "matched model must allow")

	require.NotNil(t, out.Mutations, "matched route must emit mutations")
	rewrite := out.Mutations.RewriteUpstream
	require.NotNil(t, rewrite, "matched route must emit upstream rewrite")
	assert.Equal(t, "https", rewrite.Scheme, "rewrite scheme must come from the matched route")
	assert.Equal(t, "api.openai.com", rewrite.Host, "rewrite host must come from the matched route")

	assert.ElementsMatch(t, strippedAuthHeaders, rewrite.StripHeaders,
		"strip list rides on UpstreamRewrite (bypasses framework denylist) and must cover every known vendor auth header")
	require.NotNil(t, rewrite.AuthHeader, "router must inject the auth header via the rewrite (not HeadersAdd) so the proxy bypasses the denylist")
	assert.Equal(t, "Authorization", rewrite.AuthHeader.Name, "injected header name must come from the route")
	assert.Equal(t, "Bearer sk-test-123", rewrite.AuthHeader.Value, "injected header value must come from the route")
	assert.Empty(t, out.Mutations.HeadersAdd, "router must not use HeadersAdd; auth flows through UpstreamRewrite.AuthHeader")
	assert.Empty(t, out.Mutations.HeadersRemove, "router must not use HeadersRemove; strip flows through UpstreamRewrite.StripHeaders")

	resolved, ok := metaValue(t, out.Metadata, middleware.KeyLLMResolvedProviderID)
	require.True(t, ok, "router must emit llm.resolved_provider_id on a match")
	assert.Equal(t, "openai-prod", resolved, "resolved provider id must be the matched route's ID")
	dec, _ := metaValue(t, out.Metadata, middleware.KeyLLMPolicyDecision)
	assert.Equal(t, "allow", dec, "decision metadata must be allow on a match")
}

func TestRouter_MissingModel(t *testing.T) {
	mw := New(Config{Providers: []ProviderRoute{{
		ID:              "openai-prod",
		Models:          []string{"gpt-4o"},
		AllowedGroupIDs: []string{defaultTestGroup},
		UpstreamScheme:  "https",
		UpstreamHost:    "api.openai.com",
	}}})

	out, err := mw.Invoke(context.Background(), &middleware.Input{Slot: middleware.SlotOnRequest})
	require.NoError(t, err)
	require.NotNil(t, out)
	assert.Equal(t, middleware.DecisionDeny, out.Decision, "missing llm.model must deny")
	assert.Equal(t, 403, out.DenyStatus, "deny status must be 403")
	require.NotNil(t, out.DenyReason, "deny reason must be populated")
	assert.Equal(t, "llm_policy.model_not_routable", out.DenyReason.Code, "deny code must be model_not_routable")
	assert.Equal(t, "missing llm.model on request envelope", out.DenyReason.Message, "deny message must match spec")

	dec, _ := metaValue(t, out.Metadata, middleware.KeyLLMPolicyDecision)
	assert.Equal(t, "deny", dec, "decision metadata must be deny")
	reason, _ := metaValue(t, out.Metadata, middleware.KeyLLMPolicyReason)
	assert.Equal(t, "model_not_routable", reason, "reason metadata must be model_not_routable")
}

// newModellessInput returns an Input with no llm.model and the given
// request path, mimicking a GET /v1/models call (which carries no body
// from which a model could be parsed). UserGroups matches defaultTestGroup.
func newModellessInput(reqURL string) *middleware.Input {
	return &middleware.Input{
		Slot:       middleware.SlotOnRequest,
		URL:        reqURL,
		UserGroups: []string{defaultTestGroup},
	}
}

func TestRouter_ModelLessPath_RoutesToAuthorisedProvider(t *testing.T) {
	route := ProviderRoute{
		ID:              "openai-prod",
		Models:          []string{"gpt-4o"},
		AllowedGroupIDs: []string{defaultTestGroup},
		UpstreamScheme:  "https",
		UpstreamHost:    "api.openai.com",
	}
	mw := New(Config{Providers: []ProviderRoute{route}})

	out, err := mw.Invoke(context.Background(), newModellessInput("/v1/models?client_version=1"))
	require.NoError(t, err)
	require.NotNil(t, out)
	assert.Equal(t, middleware.DecisionAllow, out.Decision, "GET /v1/models must pass through, not deny")
	require.NotNil(t, out.Mutations, "a pass-through must rewrite the upstream")
	require.NotNil(t, out.Mutations.RewriteUpstream, "model-less route must still rewrite to the real upstream")
	assert.Equal(t, "api.openai.com", out.Mutations.RewriteUpstream.Host, "must target the authorised provider's host")

	provider, _ := metaValue(t, out.Metadata, middleware.KeyLLMResolvedProviderID)
	assert.Equal(t, "openai-prod", provider, "resolved provider must be the authorised route")
}

func TestRouter_ModelLessPath_MultiProviderDeclarationOrder(t *testing.T) {
	first := ProviderRoute{
		ID:              "openai-a",
		Models:          []string{"gpt-4o"},
		AllowedGroupIDs: []string{defaultTestGroup},
		UpstreamScheme:  "https",
		UpstreamHost:    "a.example.com",
	}
	second := ProviderRoute{
		ID:              "openai-b",
		Models:          []string{"gpt-4o-mini"},
		AllowedGroupIDs: []string{defaultTestGroup},
		UpstreamScheme:  "https",
		UpstreamHost:    "b.example.com",
	}
	mw := New(Config{Providers: []ProviderRoute{first, second}})

	out, err := mw.Invoke(context.Background(), newModellessInput("/v1/models"))
	require.NoError(t, err)
	require.NotNil(t, out)
	assert.Equal(t, middleware.DecisionAllow, out.Decision, "model-less path must pass through with multiple providers")
	provider, _ := metaValue(t, out.Metadata, middleware.KeyLLMResolvedProviderID)
	assert.Equal(t, "openai-a", provider, "no path-prefix match falls back to declaration order")
}

func TestRouter_ModelLessPath_UnauthorisedDenies(t *testing.T) {
	mw := New(Config{Providers: []ProviderRoute{{
		ID:              "openai-prod",
		Models:          []string{"gpt-4o"},
		AllowedGroupIDs: []string{"some-other-group"},
		UpstreamScheme:  "https",
		UpstreamHost:    "api.openai.com",
	}}})

	out, err := mw.Invoke(context.Background(), newModellessInput("/v1/models"))
	require.NoError(t, err)
	require.NotNil(t, out)
	assert.Equal(t, middleware.DecisionDeny, out.Decision, "no provider authorising the caller must still deny")
}

func TestRouter_NonModelLessBodilessStillDenies(t *testing.T) {
	mw := New(Config{Providers: []ProviderRoute{{
		ID:              "openai-prod",
		Models:          []string{"gpt-4o"},
		AllowedGroupIDs: []string{defaultTestGroup},
		UpstreamScheme:  "https",
		UpstreamHost:    "api.openai.com",
	}}})

	// A bodiless POST to an inference path has no model and is NOT a
	// model-less endpoint, so it must keep denying.
	out, err := mw.Invoke(context.Background(), newModellessInput("/v1/responses"))
	require.NoError(t, err)
	require.NotNil(t, out)
	assert.Equal(t, middleware.DecisionDeny, out.Decision, "bodiless inference request must still deny")
	assert.Equal(t, "llm_policy.model_not_routable", out.DenyReason.Code, "deny code stays model_not_routable")
}

// TestRouter_ExplicitModelBeatsCatchallGateway is the regression guard
// for multi-provider misrouting: a catch-all (empty Models) OpenAI-compat
// gateway declared first must NOT swallow a model an explicit provider
// claims. Anthropic's claude request must reach the Anthropic route even
// though the gateway claims every model and wins declaration order.
func TestRouter_ExplicitModelBeatsCatchallGateway(t *testing.T) {
	gateway := ProviderRoute{
		ID:              "openai-gateway",
		Models:          nil, // catch-all: claims every model
		AllowedGroupIDs: []string{defaultTestGroup},
		UpstreamScheme:  "https",
		UpstreamHost:    "api.openai.com",
	}
	anthropic := ProviderRoute{
		ID:              "anthropic-prod",
		Models:          []string{"claude-opus-4"},
		AllowedGroupIDs: []string{defaultTestGroup},
		UpstreamScheme:  "https",
		UpstreamHost:    "api.anthropic.com",
	}
	// Gateway declared first to prove explicit claim beats declaration order.
	mw := New(Config{Providers: []ProviderRoute{gateway, anthropic}})

	out, err := mw.Invoke(context.Background(), newInputWithModelAndURL("claude-opus-4", "/v1/messages"))
	require.NoError(t, err)
	require.NotNil(t, out)
	assert.Equal(t, middleware.DecisionAllow, out.Decision, "explicit-model request must route, not deny")
	require.NotNil(t, out.Mutations)
	require.NotNil(t, out.Mutations.RewriteUpstream)
	assert.Equal(t, "api.anthropic.com", out.Mutations.RewriteUpstream.Host, "claude must reach the explicit Anthropic route, not the catch-all gateway")

	provider, _ := metaValue(t, out.Metadata, middleware.KeyLLMResolvedProviderID)
	assert.Equal(t, "anthropic-prod", provider, "resolved provider must be the explicit Anthropic route")
}

// TestRouter_CatchallStillServesUnlistedModel confirms the catch-all
// gateway still wins models no explicit provider claims (its whole point).
func TestRouter_CatchallStillServesUnlistedModel(t *testing.T) {
	gateway := ProviderRoute{
		ID:              "openai-gateway",
		Models:          nil,
		AllowedGroupIDs: []string{defaultTestGroup},
		UpstreamScheme:  "https",
		UpstreamHost:    "gateway.example.com",
	}
	anthropic := ProviderRoute{
		ID:              "anthropic-prod",
		Models:          []string{"claude-opus-4"},
		AllowedGroupIDs: []string{defaultTestGroup},
		UpstreamScheme:  "https",
		UpstreamHost:    "api.anthropic.com",
	}
	mw := New(Config{Providers: []ProviderRoute{gateway, anthropic}})

	out, err := mw.Invoke(context.Background(), newInputWithModelAndURL("some-exotic-model", "/v1/chat/completions"))
	require.NoError(t, err)
	require.NotNil(t, out)
	assert.Equal(t, middleware.DecisionAllow, out.Decision, "unlisted model must still route via the catch-all")
	require.NotNil(t, out.Mutations.RewriteUpstream)
	assert.Equal(t, "gateway.example.com", out.Mutations.RewriteUpstream.Host, "unlisted model falls to the catch-all gateway")
}

// newInputVendorModelURL returns an Input carrying both the detected
// vendor (llm.provider) and the model, plus a request URL — mimicking the
// post-llm_request_parser state for a real inference call.
func newInputVendorModelURL(vendor, model, reqURL string) *middleware.Input {
	return &middleware.Input{
		Slot: middleware.SlotOnRequest,
		URL:  reqURL,
		Metadata: []middleware.KV{
			{Key: middleware.KeyLLMProvider, Value: vendor},
			{Key: middleware.KeyLLMModel, Value: model},
		},
		UserGroups: []string{defaultTestGroup},
	}
}

// TestRouter_VendorKeepsAnthropicOffOpenAIGateway is the regression guard
// for the reported multi-provider break: two catch-all providers (neither
// enumerates models), the OpenAI one declared first. Without vendor
// awareness, a claude request matches both, no path prefixes, and
// declaration order sends it to OpenAI → 502. The detected vendor must
// pin it to the Anthropic route.
func TestRouter_VendorKeepsAnthropicOffOpenAIGateway(t *testing.T) {
	openai := ProviderRoute{
		ID:              "openai-gw",
		Vendor:          "openai",
		Models:          nil, // catch-all
		AllowedGroupIDs: []string{defaultTestGroup},
		UpstreamScheme:  "https",
		UpstreamHost:    "api.openai.com",
	}
	anthropic := ProviderRoute{
		ID:              "anthropic-gw",
		Vendor:          "anthropic",
		Models:          nil, // catch-all
		AllowedGroupIDs: []string{defaultTestGroup},
		UpstreamScheme:  "https",
		UpstreamHost:    "api.anthropic.com",
	}
	mw := New(Config{Providers: []ProviderRoute{openai, anthropic}}) // openai first

	out, err := mw.Invoke(context.Background(), newInputVendorModelURL("anthropic", "claude-opus-4-8", "/v1/messages"))
	require.NoError(t, err)
	require.NotNil(t, out)
	assert.Equal(t, middleware.DecisionAllow, out.Decision, "claude request must route, not deny")
	require.NotNil(t, out.Mutations.RewriteUpstream)
	assert.Equal(t, "api.anthropic.com", out.Mutations.RewriteUpstream.Host, "anthropic vendor must pin to the anthropic route despite openai being declared first")

	provider, _ := metaValue(t, out.Metadata, middleware.KeyLLMResolvedProviderID)
	assert.Equal(t, "anthropic-gw", provider)
}

// TestRouter_VendorKeepsOpenAIOffAnthropic is the reciprocal: an OpenAI
// request must stay on the OpenAI route even when the Anthropic catch-all
// is declared first.
func TestRouter_VendorKeepsOpenAIOffAnthropic(t *testing.T) {
	anthropic := ProviderRoute{
		ID:              "anthropic-gw",
		Vendor:          "anthropic",
		Models:          nil,
		AllowedGroupIDs: []string{defaultTestGroup},
		UpstreamScheme:  "https",
		UpstreamHost:    "api.anthropic.com",
	}
	openai := ProviderRoute{
		ID:              "openai-gw",
		Vendor:          "openai",
		Models:          nil,
		AllowedGroupIDs: []string{defaultTestGroup},
		UpstreamScheme:  "https",
		UpstreamHost:    "api.openai.com",
	}
	mw := New(Config{Providers: []ProviderRoute{anthropic, openai}}) // anthropic first

	out, err := mw.Invoke(context.Background(), newInputVendorModelURL("openai", "gpt-5.5", "/v1/responses"))
	require.NoError(t, err)
	require.NotNil(t, out)
	require.NotNil(t, out.Mutations.RewriteUpstream)
	assert.Equal(t, "api.openai.com", out.Mutations.RewriteUpstream.Host, "openai vendor must pin to the openai route despite anthropic being declared first")
}

// TestRouter_VendorAbsentFallsBackToModelPath confirms vendor filtering is
// inert when the request carries no detected vendor: routing then relies on
// model/path as before.
func TestRouter_VendorAbsentFallsBackToModelPath(t *testing.T) {
	openai := ProviderRoute{
		ID:              "openai-gw",
		Vendor:          "openai",
		Models:          []string{"gpt-5.5"},
		AllowedGroupIDs: []string{defaultTestGroup},
		UpstreamScheme:  "https",
		UpstreamHost:    "api.openai.com",
	}
	mw := New(Config{Providers: []ProviderRoute{openai}})

	// No llm.provider in metadata — only the model.
	out, err := mw.Invoke(context.Background(), newInputWithModel("gpt-5.5"))
	require.NoError(t, err)
	require.NotNil(t, out)
	assert.Equal(t, middleware.DecisionAllow, out.Decision, "explicit-model match must still route with no vendor present")
}

func TestRouter_UnknownModel(t *testing.T) {
	mw := New(Config{Providers: []ProviderRoute{{
		ID:              "openai-prod",
		Models:          []string{"gpt-4o"},
		AllowedGroupIDs: []string{defaultTestGroup},
		UpstreamScheme:  "https",
		UpstreamHost:    "api.openai.com",
	}}})

	out, err := mw.Invoke(context.Background(), newInputWithModel("claude-opus-4"))
	require.NoError(t, err)
	require.NotNil(t, out)
	assert.Equal(t, middleware.DecisionDeny, out.Decision, "unrouted model must deny")
	assert.Equal(t, 403, out.DenyStatus, "deny status must be 403")
	require.NotNil(t, out.DenyReason, "deny reason must be populated")
	assert.Equal(t, "llm_policy.model_not_routable", out.DenyReason.Code, "deny code must be model_not_routable")
	assert.Equal(t, "no provider configured for model claude-opus-4", out.DenyReason.Message, "deny message must reference the offending model")
	assert.Equal(t, "claude-opus-4", out.DenyReason.Details["model"], "deny details must include the offending model")
}

func TestRouter_HeaderStripList(t *testing.T) {
	mw := New(Config{Providers: []ProviderRoute{{
		ID:              "openai-prod",
		Models:          []string{"gpt-4o"},
		AllowedGroupIDs: []string{defaultTestGroup},
		UpstreamScheme:  "https",
		UpstreamHost:    "api.openai.com",
		AuthHeaderName:  "Authorization",
		AuthHeaderValue: "Bearer sk-test-123",
	}}})

	out, err := mw.Invoke(context.Background(), newInputWithModel("gpt-4o"))
	require.NoError(t, err)
	require.NotNil(t, out)
	require.NotNil(t, out.Mutations, "matched route must emit mutations")

	expected := []string{
		"Authorization",
		"Proxy-Authorization",
		"x-api-key",
		"api-key",
	}
	require.NotNil(t, out.Mutations.RewriteUpstream, "matched route must emit upstream rewrite")
	for _, header := range expected {
		assert.Contains(t, out.Mutations.RewriteUpstream.StripHeaders, header,
			"strip list (on UpstreamRewrite) must include the well-known vendor auth header %s", header)
	}

	// Vendor metadata headers MUST NOT be stripped: the client SDK sets them
	// and the upstream requires them. Anthropic returns 400 "anthropic-version:
	// header is required" if we drop it. Lock the regression.
	preserved := []string{"anthropic-version", "openai-organization", "openai-project"}
	for _, header := range preserved {
		assert.NotContains(t, out.Mutations.RewriteUpstream.StripHeaders, header,
			"vendor metadata header %s must NOT be stripped — upstreams require it", header)
	}
}

func TestRouter_FirstMatchWins(t *testing.T) {
	first := ProviderRoute{
		ID:              "first",
		Models:          []string{"gpt-4o"},
		AllowedGroupIDs: []string{defaultTestGroup},
		UpstreamScheme:  "https",
		UpstreamHost:    "first.test",
		AuthHeaderName:  "Authorization",
		AuthHeaderValue: "Bearer first",
	}
	second := ProviderRoute{
		ID:              "second",
		Models:          []string{"gpt-4o"},
		AllowedGroupIDs: []string{defaultTestGroup},
		UpstreamScheme:  "https",
		UpstreamHost:    "second.test",
		AuthHeaderName:  "Authorization",
		AuthHeaderValue: "Bearer second",
	}
	mw := New(Config{Providers: []ProviderRoute{first, second}})

	out, err := mw.Invoke(context.Background(), newInputWithModel("gpt-4o"))
	require.NoError(t, err)
	require.NotNil(t, out)
	assert.Equal(t, middleware.DecisionAllow, out.Decision, "duplicate-model match must still allow")
	require.NotNil(t, out.Mutations, "matched route must emit mutations")
	require.NotNil(t, out.Mutations.RewriteUpstream, "matched route must emit upstream rewrite")
	assert.Equal(t, "first.test", out.Mutations.RewriteUpstream.Host, "first-match-wins must pick the earlier route")

	resolved, _ := metaValue(t, out.Metadata, middleware.KeyLLMResolvedProviderID)
	assert.Equal(t, "first", resolved, "resolved provider id must be the earlier route's ID")
}

// TestRouter_PathDisambiguation_PrefixWinsOverCatchall locks in the
// rule the user nailed down: two providers claim the same model, one
// has an UpstreamPath that prefixes the incoming URL, the other has
// no path. The path-prefixed provider wins because the path is a
// strictly more specific match than the empty catchall.
func TestRouter_PathDisambiguation_PrefixWinsOverCatchall(t *testing.T) {
	corp := ProviderRoute{
		ID:              "corp-openai-compat",
		Models:          []string{"gpt-5"},
		AllowedGroupIDs: []string{defaultTestGroup},
		UpstreamScheme:  "https",
		UpstreamHost:    "corp.example.com",
		UpstreamPath:    "/openai",
		AuthHeaderName:  "Authorization",
		AuthHeaderValue: "Bearer corp",
	}
	openai := ProviderRoute{
		ID:              "openai",
		Models:          []string{"gpt-5"},
		AllowedGroupIDs: []string{defaultTestGroup},
		UpstreamScheme:  "https",
		UpstreamHost:    "api.openai.com",
		AuthHeaderName:  "Authorization",
		AuthHeaderValue: "Bearer openai",
	}
	mw := New(Config{Providers: []ProviderRoute{openai, corp}}) // openai listed first to prove path beats declaration order

	out, err := mw.Invoke(context.Background(), newInputWithModelAndURL("gpt-5", "/openai/v1/chat/completions"))
	require.NoError(t, err)
	require.NotNil(t, out)
	require.Equal(t, middleware.DecisionAllow, out.Decision, "path-prefix match must allow")
	require.NotNil(t, out.Mutations.RewriteUpstream)
	assert.Equal(t, "corp.example.com", out.Mutations.RewriteUpstream.Host,
		"path-prefixed provider must beat the catchall when its UpstreamPath is a prefix of the request path")
	resolved, _ := metaValue(t, out.Metadata, middleware.KeyLLMResolvedProviderID)
	assert.Equal(t, "corp-openai-compat", resolved, "resolved provider id must reflect the path-prefix winner, not the first declared")
}

// TestRouter_PathDisambiguation_CatchallWhenNoPrefixMatches is the
// inverse: the path-prefixed provider does NOT match the incoming
// path, so the empty-path catchall takes the request.
func TestRouter_PathDisambiguation_CatchallWhenNoPrefixMatches(t *testing.T) {
	corp := ProviderRoute{
		ID:              "corp-openai-compat",
		Models:          []string{"gpt-5"},
		AllowedGroupIDs: []string{defaultTestGroup},
		UpstreamScheme:  "https",
		UpstreamHost:    "corp.example.com",
		UpstreamPath:    "/openai",
		AuthHeaderName:  "Authorization",
		AuthHeaderValue: "Bearer corp",
	}
	openai := ProviderRoute{
		ID:              "openai",
		Models:          []string{"gpt-5"},
		AllowedGroupIDs: []string{defaultTestGroup},
		UpstreamScheme:  "https",
		UpstreamHost:    "api.openai.com",
		AuthHeaderName:  "Authorization",
		AuthHeaderValue: "Bearer openai",
	}
	mw := New(Config{Providers: []ProviderRoute{corp, openai}})

	out, err := mw.Invoke(context.Background(), newInputWithModelAndURL("gpt-5", "/v1/chat/completions"))
	require.NoError(t, err)
	require.NotNil(t, out)
	require.Equal(t, middleware.DecisionAllow, out.Decision, "catchall must allow when no path prefix matches")
	require.NotNil(t, out.Mutations.RewriteUpstream)
	assert.Equal(t, "api.openai.com", out.Mutations.RewriteUpstream.Host,
		"empty-path catchall must win when the path-prefixed provider's UpstreamPath does not match the request")
	resolved, _ := metaValue(t, out.Metadata, middleware.KeyLLMResolvedProviderID)
	assert.Equal(t, "openai", resolved, "resolved provider id must be the catchall")
}

// TestRouter_PathDisambiguation_LongestPrefixWins covers the case
// where multiple providers have non-empty UpstreamPath values that
// both prefix the request — the longer (more specific) one wins.
func TestRouter_PathDisambiguation_LongestPrefixWins(t *testing.T) {
	short := ProviderRoute{
		ID:              "short-prefix",
		Models:          []string{"gpt-5"},
		AllowedGroupIDs: []string{defaultTestGroup},
		UpstreamScheme:  "https",
		UpstreamHost:    "short.example.com",
		UpstreamPath:    "/openai",
	}
	long := ProviderRoute{
		ID:              "long-prefix",
		Models:          []string{"gpt-5"},
		AllowedGroupIDs: []string{defaultTestGroup},
		UpstreamScheme:  "https",
		UpstreamHost:    "long.example.com",
		UpstreamPath:    "/openai/v1",
	}
	mw := New(Config{Providers: []ProviderRoute{short, long}})

	out, err := mw.Invoke(context.Background(), newInputWithModelAndURL("gpt-5", "/openai/v1/chat/completions"))
	require.NoError(t, err)
	require.NotNil(t, out)
	require.NotNil(t, out.Mutations.RewriteUpstream)
	assert.Equal(t, "long.example.com", out.Mutations.RewriteUpstream.Host,
		"longest matching UpstreamPath must win — most specific match")
}

// TestRouter_SingleMatchIgnoresPath proves the path-prefix rule is a
// disambiguation pass, not a gate: when only one provider claims the
// model, it wins regardless of UpstreamPath. Otherwise a path-scoped
// provider would 403 every request whose URL doesn't include the
// path, which would break SDKs configured to hit the gateway root.
func TestRouter_SingleMatchIgnoresPath(t *testing.T) {
	only := ProviderRoute{
		ID:              "only",
		Models:          []string{"gpt-5"},
		AllowedGroupIDs: []string{defaultTestGroup},
		UpstreamScheme:  "https",
		UpstreamHost:    "only.example.com",
		UpstreamPath:    "/openai",
		AuthHeaderName:  "Authorization",
		AuthHeaderValue: "Bearer only",
	}
	mw := New(Config{Providers: []ProviderRoute{only}})

	out, err := mw.Invoke(context.Background(), newInputWithModelAndURL("gpt-5", "/v1/chat/completions"))
	require.NoError(t, err)
	require.NotNil(t, out)
	assert.Equal(t, middleware.DecisionAllow, out.Decision,
		"single model-matching provider must serve the request even when UpstreamPath doesn't prefix the URL — path is a tiebreaker, not a gate")
	require.NotNil(t, out.Mutations.RewriteUpstream)
	assert.Equal(t, "only.example.com", out.Mutations.RewriteUpstream.Host, "the only model-matching provider should be selected")
}

// TestRouter_PathDisambiguation_FallbackWhenNoPrefixMatches covers
// the multi-candidate edge case where every candidate has a
// non-matching non-empty UpstreamPath. The router falls back to
// declaration order so the model is still routable rather than 403'd.
func TestRouter_PathDisambiguation_FallbackWhenNoPrefixMatches(t *testing.T) {
	first := ProviderRoute{
		ID:              "first",
		Models:          []string{"gpt-5"},
		AllowedGroupIDs: []string{defaultTestGroup},
		UpstreamScheme:  "https",
		UpstreamHost:    "first.example.com",
		UpstreamPath:    "/openai",
	}
	second := ProviderRoute{
		ID:              "second",
		Models:          []string{"gpt-5"},
		AllowedGroupIDs: []string{defaultTestGroup},
		UpstreamScheme:  "https",
		UpstreamHost:    "second.example.com",
		UpstreamPath:    "/anthropic",
	}
	mw := New(Config{Providers: []ProviderRoute{first, second}})

	out, err := mw.Invoke(context.Background(), newInputWithModelAndURL("gpt-5", "/v1/chat/completions"))
	require.NoError(t, err)
	require.NotNil(t, out)
	assert.Equal(t, middleware.DecisionAllow, out.Decision, "no path match among multi-candidates must still allow")
	require.NotNil(t, out.Mutations.RewriteUpstream)
	assert.Equal(t, "first.example.com", out.Mutations.RewriteUpstream.Host,
		"when no candidate's UpstreamPath prefix-matches the request, fall back to declaration order")
}

func TestRouter_FactoryRejectsBadJSON(t *testing.T) {
	_, err := Factory{}.New([]byte("{not json"))
	require.Error(t, err, "malformed JSON config must be rejected at chain build time")
}

func TestRouter_FactoryAcceptsEmptyShapes(t *testing.T) {
	cases := [][]byte{nil, []byte(""), []byte(" "), []byte("null"), []byte("{}"), []byte("[]")}
	for _, raw := range cases {
		mw, err := Factory{}.New(raw)
		require.NoError(t, err, "empty-shaped config must yield a router with an empty Providers slice")
		require.NotNil(t, mw, "factory must return a non-nil middleware on empty config")

		out, invErr := mw.Invoke(context.Background(), newInputWithModel("gpt-4o"))
		require.NoError(t, invErr)
		assert.Equal(t, middleware.DecisionDeny, out.Decision,
			"router with no providers must deny every model as not-routable")
	}
}

// newInputWithModelAndGroups returns an Input carrying llm.model + the
// caller's UserGroups, mimicking the post-auth, post-llm_request_parser
// state the router observes.
func newInputWithModelAndGroups(model string, groups []string) *middleware.Input {
	in := newInputWithModel(model)
	in.UserGroups = append([]string(nil), groups...)
	return in
}

// TestRouter_GroupFilter_PicksAuthorisedAmongDuplicates pins the Fix A
// behaviour: when two providers claim the same model but each
// authorises a different group, the router must pick the route the
// caller's groups intersect, regardless of declaration order.
func TestRouter_GroupFilter_PicksAuthorisedAmongDuplicates(t *testing.T) {
	mw := New(Config{Providers: []ProviderRoute{
		{
			ID:              "openai-marketing",
			Models:          []string{"gpt-4o-mini"},
			UpstreamScheme:  "https",
			UpstreamHost:    "mkt-openai.example.com",
			AllowedGroupIDs: []string{"grp-mkt"},
		},
		{
			ID:              "openai-engineering",
			Models:          []string{"gpt-4o-mini"},
			UpstreamScheme:  "https",
			UpstreamHost:    "eng-openai.example.com",
			AllowedGroupIDs: []string{"grp-eng"},
		},
	}})

	out, err := mw.Invoke(context.Background(),
		newInputWithModelAndGroups("gpt-4o-mini", []string{"grp-eng"}))
	require.NoError(t, err)
	require.NotNil(t, out)
	assert.Equal(t, middleware.DecisionAllow, out.Decision,
		"authorised candidate exists; must allow")

	resolved, ok := metaValue(t, out.Metadata, middleware.KeyLLMResolvedProviderID)
	require.True(t, ok)
	assert.Equal(t, "openai-engineering", resolved,
		"router must pick the route whose AllowedGroupIDs intersects the caller's groups, ignoring declaration order")
}

// TestRouter_GroupFilter_NoIntersection_DeniesNoAuthorisedRoute pins
// the dedicated deny code that fires when the model is known to a
// provider but no candidate is authorised for the caller's groups.
func TestRouter_GroupFilter_NoIntersection_DeniesNoAuthorisedRoute(t *testing.T) {
	mw := New(Config{Providers: []ProviderRoute{{
		ID:              "openai-marketing",
		Models:          []string{"gpt-4o-mini"},
		UpstreamScheme:  "https",
		UpstreamHost:    "mkt-openai.example.com",
		AllowedGroupIDs: []string{"grp-mkt"},
	}}})

	out, err := mw.Invoke(context.Background(),
		newInputWithModelAndGroups("gpt-4o-mini", []string{"grp-eng"}))
	require.NoError(t, err)
	require.NotNil(t, out)
	assert.Equal(t, middleware.DecisionDeny, out.Decision,
		"model exists but no route authorises grp-eng; must deny")
	require.NotNil(t, out.DenyReason)
	assert.Equal(t, "llm_policy.no_authorised_provider", out.DenyReason.Code,
		"deny code must be no_authorised_provider, not model_not_routable")
	assert.Equal(t, "gpt-4o-mini", out.DenyReason.Details["model"],
		"deny details must reference the offending model")

	dec, _ := metaValue(t, out.Metadata, middleware.KeyLLMPolicyDecision)
	assert.Equal(t, "deny", dec)
	reason, _ := metaValue(t, out.Metadata, middleware.KeyLLMPolicyReason)
	assert.Equal(t, "no_authorised_provider", reason)
}

// TestRouter_GroupFilter_EmptyAllowedGroupsIsUnreachable pins the
// strict semantics: a route with no AllowedGroupIDs is unreachable.
// The synthesiser only emits policy-bound routes, so an empty ACL
// signals a misconfiguration that must not silently fall through.
func TestRouter_GroupFilter_EmptyAllowedGroupsIsUnreachable(t *testing.T) {
	mw := New(Config{Providers: []ProviderRoute{{
		ID:             "openai-shared",
		Models:         []string{"gpt-4o"},
		UpstreamScheme: "https",
		UpstreamHost:   "api.openai.com",
		// AllowedGroupIDs intentionally left empty.
	}}})

	out, err := mw.Invoke(context.Background(), newInputWithModel("gpt-4o"))
	require.NoError(t, err)
	require.NotNil(t, out)
	assert.Equal(t, middleware.DecisionDeny, out.Decision,
		"empty AllowedGroupIDs must deny — there is no catch-all for routes without an authorising policy")
	require.NotNil(t, out.DenyReason)
	assert.Equal(t, "llm_policy.no_authorised_provider", out.DenyReason.Code,
		"empty ACL fails the group-filter pass; deny code must reflect that")
}

// TestRouter_GroupFilter_OverlapTiebreakUnchanged pins that when more
// than one route is authorised for the caller's groups, the existing
// path-prefix tiebreak still decides. Group filtering is a hard gate
// before the tiebreak; it does not change the tiebreak semantics.
func TestRouter_GroupFilter_OverlapTiebreakUnchanged(t *testing.T) {
	mw := New(Config{Providers: []ProviderRoute{
		{
			ID:              "openai-a",
			Models:          []string{"gpt-4o-mini"},
			UpstreamScheme:  "https",
			UpstreamHost:    "a.example.com",
			UpstreamPath:    "",
			AllowedGroupIDs: []string{"grp-eng"},
		},
		{
			ID:              "openai-b",
			Models:          []string{"gpt-4o-mini"},
			UpstreamScheme:  "https",
			UpstreamHost:    "b.example.com",
			UpstreamPath:    "/v1/chat",
			AllowedGroupIDs: []string{"grp-eng"},
		},
	}})

	in := newInputWithModelAndURL("gpt-4o-mini", "/v1/chat/completions")
	in.UserGroups = []string{"grp-eng"}
	out, err := mw.Invoke(context.Background(), in)
	require.NoError(t, err)
	require.NotNil(t, out)
	assert.Equal(t, middleware.DecisionAllow, out.Decision)

	resolved, _ := metaValue(t, out.Metadata, middleware.KeyLLMResolvedProviderID)
	assert.Equal(t, "openai-b", resolved,
		"longest-prefix path tiebreak still wins among group-authorised candidates")
}

// TestRouter_AuthorisingGroups_EmitsIntersection pins that the router
// emits llm.authorising_groups containing only the intersection of the
// caller's UserGroups with the resolved route's AllowedGroupIDs — not
// every group the peer happens to be in.
func TestRouter_AuthorisingGroups_EmitsIntersection(t *testing.T) {
	mw := New(Config{Providers: []ProviderRoute{{
		ID:              "openai-eng",
		Models:          []string{"gpt-4o-mini"},
		UpstreamScheme:  "https",
		UpstreamHost:    "eng-openai.example.com",
		AllowedGroupIDs: []string{"grp-eng", "grp-shared"},
	}}})

	in := newInputWithModelAndGroups("gpt-4o-mini",
		[]string{"grp-eng", "grp-it", "grp-shared", "grp-oncall"})

	out, err := mw.Invoke(context.Background(), in)
	require.NoError(t, err)
	require.Equal(t, middleware.DecisionAllow, out.Decision)

	csv, ok := metaValue(t, out.Metadata, middleware.KeyLLMAuthorisingGroups)
	require.True(t, ok, "router must emit llm.authorising_groups on a match")
	assert.Equal(t, "grp-eng,grp-shared", csv,
		"only groups in BOTH UserGroups AND AllowedGroupIDs may appear; result must be sorted and unique")
}

// TestRouter_EmptyModelsClaimsAnyModel pins that a route with no
// configured Models matches every model — used by gateway-style
// providers (LiteLLM, custom OpenAI-compatible endpoints) where the
// operator can't enumerate the upstream's model catalog in NetBird.
func TestRouter_EmptyModelsClaimsAnyModel(t *testing.T) {
	mw := New(Config{Providers: []ProviderRoute{{
		ID:              "litellm",
		Models:          nil, // catch-all
		UpstreamScheme:  "https",
		UpstreamHost:    "litellm.example.com",
		AllowedGroupIDs: []string{defaultTestGroup},
	}}})

	out, err := mw.Invoke(context.Background(), newInputWithModel("gpt-5.5"))
	require.NoError(t, err)
	require.NotNil(t, out)
	assert.Equal(t, middleware.DecisionAllow, out.Decision,
		"a route with empty Models must claim any model so gateway-style providers can route open-ended sets")
	resolved, _ := metaValue(t, out.Metadata, middleware.KeyLLMResolvedProviderID)
	assert.Equal(t, "litellm", resolved)
}
