package llm_router

import (
	"testing"

	"github.com/stretchr/testify/assert"
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
