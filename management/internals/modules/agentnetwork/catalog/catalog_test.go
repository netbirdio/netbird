package catalog

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/shared/management/http/api"
)

// TestClaudeLineupSelectable pins the models Claude Code resolves to by
// default. A model absent from the lineup can't be ticked on a provider
// record, so llm_router denies it as not-routable and the operator has no
// way to authorise the client's own default.
func TestClaudeLineupSelectable(t *testing.T) {
	for providerID, wanted := range map[string][]string{
		"anthropic_api": {"claude-opus-5", "claude-sonnet-5", "claude-haiku-4-5"},
		"bedrock_api":   {"anthropic.claude-opus-5", "anthropic.claude-sonnet-5", "anthropic.claude-haiku-4-5"},
		"vertex_ai_api": {"claude-opus-5", "claude-sonnet-5", "claude-haiku-4-5"},
	} {
		provider, ok := Lookup(providerID)
		require.True(t, ok, "catalog must define %s", providerID)

		selectable := make(map[string]Model, len(provider.Models))
		for _, m := range provider.Models {
			selectable[m.ID] = m
		}
		for _, id := range wanted {
			model, found := selectable[id]
			require.True(t, found, "%s must offer %s", providerID, id)
			assert.NotEmpty(t, model.Label, "%s/%s needs a label for the picker", providerID, id)
			assert.Positive(t, model.InputPer1k, "%s/%s needs an input rate", providerID, id)
			assert.Positive(t, model.OutputPer1k, "%s/%s needs an output rate", providerID, id)
			assert.Positive(t, model.ContextWindow, "%s/%s needs a context window", providerID, id)
		}
	}
}

func TestAgentgatewayCatalogEntry(t *testing.T) {
	entry, ok := Lookup("agentgateway")
	require.True(t, ok, "agentgateway must be available in the provider catalog")

	assert.Equal(t, KindGateway, entry.Kind, "agentgateway must be grouped with AI gateways")
	assert.Empty(t, entry.DefaultHost, "operators must provide their agentgateway proxy URL")
	assert.Equal(t, "Authorization", entry.AuthHeaderName)
	assert.Equal(t, "Bearer ${API_KEY}", entry.AuthHeaderTemplate)
	assert.Equal(t, "application/json", entry.DefaultContentType)
	assert.Empty(t, entry.ParserID, "URL detection must select the OpenAI or Anthropic parser")
	assert.Equal(t, []string{"openai", "anthropic"}, entry.RouterVendors,
		"agentgateway must accept both parser surfaces")
	assert.Equal(t, []string{"openai", "anthropic"}, entry.PricingSurfaces,
		"agentgateway models can use either pricing surface")
	assert.Empty(t, entry.Models, "an empty model list makes agentgateway a catch-all route")
	require.NotNil(t, entry.Discovery)
	assert.Empty(t, entry.Discovery.Host, "discovery must use the configured proxy URL")
	assert.Equal(t, "/v1/models", entry.Discovery.Path)
	assert.Equal(t, ShapeOpenAIData, entry.Discovery.Shape)
	assert.True(t, entry.Discovery.ExactModelsOnly,
		"wildcard model semantics are not supported by NetBird")

	require.NotNil(t, entry.IdentityInjection)
	require.NotNil(t, entry.IdentityInjection.HeaderPair)
	assert.Nil(t, entry.IdentityInjection.JSONMetadata)
	assert.False(t, entry.IdentityInjection.HeaderPair.Customizable,
		"NetBird identity header names are part of the integration contract")
	assert.Equal(t, "x-netbird-user-id", entry.IdentityInjection.HeaderPair.EndUserIDHeader)
	assert.Equal(t, "x-netbird-groups", entry.IdentityInjection.HeaderPair.TagsHeader)
	assert.False(t, entry.IdentityInjection.HeaderPair.EndUserIDInBody)
	assert.False(t, entry.IdentityInjection.HeaderPair.TagsInBody)
}

func TestAgentgatewayCatalogAPIResponse(t *testing.T) {
	entry, ok := Lookup("agentgateway")
	require.True(t, ok)

	resp := entry.ToAPIResponse()
	assert.Equal(t, "agentgateway", resp.Id)
	assert.Equal(t, api.AgentNetworkCatalogProviderKindGateway, resp.Kind)
	assert.Empty(t, resp.Models)
	require.NotNil(t, resp.IdentityInjection)
	require.NotNil(t, resp.IdentityInjection.HeaderPair)
	assert.False(t, resp.IdentityInjection.HeaderPair.Customizable)
	assert.Equal(t, "x-netbird-user-id", resp.IdentityInjection.HeaderPair.EndUserIdHeader)
	assert.Equal(t, "x-netbird-groups", resp.IdentityInjection.HeaderPair.TagsHeader)
}
