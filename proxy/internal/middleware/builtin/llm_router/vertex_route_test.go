package llm_router

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/proxy/internal/middleware"
)

// A Vertex route registered with the raw "@version" id must match the
// version-stripped request model; non-Vertex routes stay exact.
func TestRouteClaimsModel_VertexNormalizesCandidate(t *testing.T) {
	route := ProviderRoute{Vertex: true, Models: []string{"claude-opus-4-6@20250514"}}
	assert.True(t, routeClaimsModel(route, "claude-opus-4-6"))
	assert.False(t, routeClaimsModel(route, "claude-haiku-4-5"))

	bare := ProviderRoute{Vertex: true, Models: []string{"claude-opus-4-6"}}
	assert.True(t, routeClaimsModel(bare, "claude-opus-4-6"))

	direct := ProviderRoute{Models: []string{"claude-opus-4-6@20250514"}}
	assert.False(t, routeClaimsModel(direct, "claude-opus-4-6"),
		"non-Vertex routes must not normalize @version candidates")
}

// TestRouter_VertexUnversionedModelRoutes replays the customer-reported request:
// an unversioned model id must route on a provider registered with "@version" ids.
func TestRouter_VertexUnversionedModelRoutes(t *testing.T) {
	route := vertexRoute()
	route.Models = []string{"claude-opus-4-6@20250514", "claude-sonnet-4-5@20250929"}
	mw := New(Config{Providers: []ProviderRoute{route}})

	in := pathRoutedInput(
		"/v1/projects/corp-gcp-it-all-claude/locations/global/publishers/anthropic/models/claude-opus-4-6:rawPredict",
		"anthropic",
		"claude-opus-4-6",
	)
	out, err := mw.Invoke(context.Background(), in)
	require.NoError(t, err)
	assert.Equal(t, middleware.DecisionAllow, out.Decision,
		"unversioned request model must route on a provider registered with @version ids")

	denied := pathRoutedInput(
		"/v1/projects/corp-gcp-it-all-claude/locations/global/publishers/anthropic/models/claude-haiku-4-5:rawPredict",
		"anthropic",
		"claude-haiku-4-5",
	)
	out, err = mw.Invoke(context.Background(), denied)
	require.NoError(t, err)
	assert.Equal(t, middleware.DecisionDeny, out.Decision,
		"a model outside the registered list must still deny")
	require.NotNil(t, out.DenyReason)
	assert.Equal(t, denyCodeNotRoutable, out.DenyReason.Code)
}
