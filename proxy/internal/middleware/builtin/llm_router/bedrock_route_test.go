package llm_router

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/proxy/internal/middleware"
)

// TestRouteClaimsModel_BedrockNormalizesCandidate guards the fix for the native
// Bedrock routing gap: the request model reaches the router already normalized
// (the parser strips the region/inference-profile prefix and version suffix),
// so a provider registered with the raw inference-profile id must still match.
func TestRouteClaimsModel_BedrockNormalizesCandidate(t *testing.T) {
	route := ProviderRoute{Bedrock: true, Models: []string{"us.anthropic.claude-haiku-4-5"}}
	assert.True(t, routeClaimsModel(route, "anthropic.claude-haiku-4-5"),
		"raw region-prefixed Bedrock model must match the normalized request model")
	assert.False(t, routeClaimsModel(route, "anthropic.claude-opus-4-8"),
		"a model outside the provider's list must not match")

	// A provider registered with the already-normalized id also matches.
	normalized := ProviderRoute{Bedrock: true, Models: []string{"anthropic.claude-haiku-4-5"}}
	assert.True(t, routeClaimsModel(normalized, "anthropic.claude-haiku-4-5"),
		"normalized Bedrock model must match")

	// Non-Bedrock routes keep exact matching (no prefix stripping).
	openai := ProviderRoute{Models: []string{"gpt-4o"}}
	assert.True(t, routeClaimsModel(openai, "gpt-4o"), "exact model must match")
	assert.False(t, routeClaimsModel(openai, "us.gpt-4o"),
		"non-Bedrock routes must not strip a us. prefix")
}

// TestRouter_BedrockCountTokensRoutes pins that the token-counting action
// reaches the Bedrock route instead of denying as not-routable.
func TestRouter_BedrockCountTokensRoutes(t *testing.T) {
	mw := New(Config{Providers: []ProviderRoute{{
		ID:              "bedrock-prod",
		Bedrock:         true,
		Models:          []string{"anthropic.claude-sonnet-4-5"},
		AllowedGroupIDs: []string{defaultTestGroup},
		UpstreamScheme:  "https",
		UpstreamHost:    "bedrock-runtime.eu-central-1.amazonaws.com",
	}}})

	in := newInputWithModelAndURL("anthropic.claude-sonnet-4-5",
		"/model/anthropic.claude-sonnet-4-5-20250929-v1:0/count-tokens")
	in.Metadata = append(in.Metadata, middleware.KV{Key: middleware.KeyLLMProvider, Value: "bedrock"})

	out, err := mw.Invoke(context.Background(), in)
	require.NoError(t, err)
	require.NotNil(t, out)
	assert.Equal(t, middleware.DecisionAllow, out.Decision, "count-tokens must route, not deny")
	require.NotNil(t, out.Mutations)
	require.NotNil(t, out.Mutations.RewriteUpstream)
	assert.Equal(t, "bedrock-runtime.eu-central-1.amazonaws.com", out.Mutations.RewriteUpstream.Host)
}

// TestRouter_BedrockInferenceProfilesRoutes covers the startup lookups a
// client makes to resolve a configured inference profile. They carry no
// model, so before they were recognised they denied and wrote a policy
// rejection into the access log on every session start.
func TestRouter_BedrockInferenceProfilesRoutes(t *testing.T) {
	bedrock := ProviderRoute{
		ID:              "bedrock-prod",
		Bedrock:         true,
		AllowedGroupIDs: []string{defaultTestGroup},
		UpstreamScheme:  "https",
		UpstreamHost:    "bedrock-runtime.eu-central-1.amazonaws.com",
	}
	openai := ProviderRoute{
		ID:              "openai-prod",
		Models:          []string{"gpt-4o"},
		AllowedGroupIDs: []string{defaultTestGroup},
		UpstreamScheme:  "https",
		UpstreamHost:    "api.openai.com",
	}
	mw := New(Config{Providers: []ProviderRoute{openai, bedrock}})

	for _, path := range []string{
		"/inference-profiles?type=SYSTEM_DEFINED",
		"/inference-profiles/us.anthropic.claude-sonnet-5",
	} {
		out, err := mw.Invoke(context.Background(), newModellessInput(path))
		require.NoError(t, err)
		require.NotNil(t, out)
		assert.Equal(t, middleware.DecisionAllow, out.Decision, "%s must route", path)
		require.NotNil(t, out.Mutations)
		require.NotNil(t, out.Mutations.RewriteUpstream)
		assert.Equal(t, "bedrock-runtime.eu-central-1.amazonaws.com", out.Mutations.RewriteUpstream.Host,
			"%s must reach the Bedrock provider, not the first authorised one", path)

		nonInference, _ := metaValue(t, out.Metadata, middleware.KeyLLMNonInference)
		assert.Equal(t, "true", nonInference, "%s carries no model to gate on", path)
	}
}

// TestRouter_BedrockNamespacedInferenceProfilesStripsPrefix pins that the
// optional gateway namespace is removed before the request goes upstream.
func TestRouter_BedrockNamespacedInferenceProfilesStripsPrefix(t *testing.T) {
	mw := New(Config{Providers: []ProviderRoute{{
		ID:              "bedrock-prod",
		Bedrock:         true,
		AllowedGroupIDs: []string{defaultTestGroup},
		UpstreamScheme:  "https",
		UpstreamHost:    "bedrock-runtime.eu-central-1.amazonaws.com",
	}}})

	out, err := mw.Invoke(context.Background(), newModellessInput("/bedrock/inference-profiles"))
	require.NoError(t, err)
	require.NotNil(t, out.Mutations)
	require.NotNil(t, out.Mutations.RewriteUpstream)
	assert.Equal(t, "/bedrock", out.Mutations.RewriteUpstream.StripPathPrefix,
		"the namespace prefix must not reach the real Bedrock endpoint")
}
