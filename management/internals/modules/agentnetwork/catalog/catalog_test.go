package catalog

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/shared/management/http/api"
)

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
	assert.Empty(t, entry.Models, "an empty model list makes agentgateway a catch-all route")

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
