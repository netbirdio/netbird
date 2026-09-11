package llm_router

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/proxy/internal/middleware"
)

// pathRoutedInput builds an Input mimicking the post-llm_request_parser state
// for a path-routed (Vertex/Bedrock) request: a request URL plus the model and
// (optionally) provider/vendor metadata the parser emits.
func pathRoutedInput(url, provider, model string) *middleware.Input {
	md := []middleware.KV{{Key: middleware.KeyLLMModel, Value: model}}
	if provider != "" {
		md = append(md, middleware.KV{Key: middleware.KeyLLMProvider, Value: provider})
	}
	return &middleware.Input{
		Slot:       middleware.SlotOnRequest,
		URL:        url,
		Metadata:   md,
		UserGroups: []string{defaultTestGroup},
	}
}

func vertexRoute() ProviderRoute {
	return ProviderRoute{
		ID: "vertex-prod", Vertex: true,
		AllowedGroupIDs: []string{defaultTestGroup},
		UpstreamScheme:  "https",
		UpstreamHost:    "europe-west1-aiplatform.googleapis.com",
		AuthHeaderName:  "Authorization",
		AuthHeaderValue: "Bearer x",
	}
}

// A Vertex publisher with no parser surface (google/gemini emits no
// llm.provider) must be denied, not forwarded unmetered.
func TestRouter_VertexUnmeterablePublisherDenied(t *testing.T) {
	mw := New(Config{Providers: []ProviderRoute{vertexRoute()}})
	in := pathRoutedInput(
		"/v1/projects/p/locations/global/publishers/google/models/gemini-2.5-pro:generateContent",
		"", // google -> request parser emits NO llm.provider
		"gemini-2.5-pro",
	)
	out, err := mw.Invoke(context.Background(), in)
	require.NoError(t, err)
	assert.Equal(t, middleware.DecisionDeny, out.Decision, "unmeterable Vertex publisher must deny")
	assert.Equal(t, 403, out.DenyStatus, "unmeterable deny is a 403")
	require.NotNil(t, out.DenyReason)
	assert.Equal(t, denyCodeUnmeterable, out.DenyReason.Code, "deny code must flag the unmeterable publisher")
}

// A Vertex publisher with a parser surface (anthropic) is allowed.
func TestRouter_VertexMeterablePublisherAllowed(t *testing.T) {
	mw := New(Config{Providers: []ProviderRoute{vertexRoute()}})
	in := pathRoutedInput(
		"/v1/projects/p/locations/global/publishers/anthropic/models/claude-sonnet-4-5:rawPredict",
		"anthropic",
		"claude-sonnet-4-5",
	)
	out, err := mw.Invoke(context.Background(), in)
	require.NoError(t, err)
	assert.Equal(t, middleware.DecisionAllow, out.Decision, "meterable Vertex publisher must allow")
}

// A path-routed provider with an explicit Models list must reject models not in
// the list (the provider credential can't be used for unauthorised models).
func TestRouter_PathRoutedModelAllowlistEnforced(t *testing.T) {
	route := ProviderRoute{
		ID: "bedrock-prod", Bedrock: true,
		Models:          []string{"anthropic.claude-sonnet-4-5"},
		AllowedGroupIDs: []string{defaultTestGroup},
		UpstreamScheme:  "https",
		UpstreamHost:    "bedrock-runtime.eu-central-1.amazonaws.com",
		AuthHeaderName:  "Authorization",
		AuthHeaderValue: "Bearer x",
	}
	mw := New(Config{Providers: []ProviderRoute{route}})

	allowed := pathRoutedInput(
		"/model/eu.anthropic.claude-sonnet-4-5-20250929-v1:0/invoke",
		"bedrock", "anthropic.claude-sonnet-4-5",
	)
	out, err := mw.Invoke(context.Background(), allowed)
	require.NoError(t, err)
	assert.Equal(t, middleware.DecisionAllow, out.Decision, "model in the allowlist must be served")

	denied := pathRoutedInput(
		"/model/amazon.nova-pro-v1:0/invoke",
		"bedrock", "amazon.nova-pro",
	)
	out, err = mw.Invoke(context.Background(), denied)
	require.NoError(t, err)
	assert.Equal(t, middleware.DecisionDeny, out.Decision, "model outside the allowlist must deny")
	require.NotNil(t, out.DenyReason)
	assert.Equal(t, denyCodeNotRoutable, out.DenyReason.Code, "unlisted model denies as not-routable")
}

// A "/bedrock" gateway-namespace prefix routes the same as the native path and
// records the prefix on the rewrite so the proxy strips it before forwarding.
func TestRouter_BedrockNamespacePrefixStripped(t *testing.T) {
	route := ProviderRoute{
		ID: "bedrock-prod", Bedrock: true,
		AllowedGroupIDs: []string{defaultTestGroup},
		UpstreamScheme:  "https",
		UpstreamHost:    "bedrock-runtime.eu-central-1.amazonaws.com",
		AuthHeaderName:  "Authorization",
		AuthHeaderValue: "Bearer x",
	}
	mw := New(Config{Providers: []ProviderRoute{route}})

	prefixed := pathRoutedInput(
		"/bedrock/model/eu.anthropic.claude-sonnet-4-5-20250929-v1:0/invoke-with-response-stream",
		"bedrock", "anthropic.claude-sonnet-4-5",
	)
	out, err := mw.Invoke(context.Background(), prefixed)
	require.NoError(t, err)
	require.Equal(t, middleware.DecisionAllow, out.Decision, "prefixed Bedrock path must route")
	require.NotNil(t, out.Mutations)
	require.NotNil(t, out.Mutations.RewriteUpstream)
	assert.Equal(t, "/bedrock", out.Mutations.RewriteUpstream.StripPathPrefix,
		"namespace prefix must be recorded so the proxy strips it before forwarding")

	native := pathRoutedInput(
		"/model/eu.anthropic.claude-sonnet-4-5-20250929-v1:0/invoke",
		"bedrock", "anthropic.claude-sonnet-4-5",
	)
	out, err = mw.Invoke(context.Background(), native)
	require.NoError(t, err)
	require.Equal(t, middleware.DecisionAllow, out.Decision, "native Bedrock path must route")
	require.NotNil(t, out.Mutations.RewriteUpstream)
	assert.Empty(t, out.Mutations.RewriteUpstream.StripPathPrefix,
		"native path carries no namespace prefix to strip")
}

// A path-routed provider with no configured Models is catch-all: any model the
// credential can reach is served (preserves the zero-config behaviour).
func TestRouter_PathRoutedCatchAllServesAnyModel(t *testing.T) {
	route := ProviderRoute{
		ID: "bedrock-catchall", Bedrock: true,
		AllowedGroupIDs: []string{defaultTestGroup},
		UpstreamScheme:  "https",
		UpstreamHost:    "bedrock-runtime.eu-central-1.amazonaws.com",
		AuthHeaderName:  "Authorization",
		AuthHeaderValue: "Bearer x",
	}
	mw := New(Config{Providers: []ProviderRoute{route}})
	in := pathRoutedInput(
		"/model/amazon.nova-pro-v1:0/invoke",
		"bedrock", "amazon.nova-pro",
	)
	out, err := mw.Invoke(context.Background(), in)
	require.NoError(t, err)
	assert.Equal(t, middleware.DecisionAllow, out.Decision, "catch-all path-routed provider serves any model")
}
