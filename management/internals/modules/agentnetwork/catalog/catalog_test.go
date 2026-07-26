package catalog

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/shared/management/http/api"
)

func TestOllamaCatalogEntry(t *testing.T) {
	entry, ok := Lookup("ollama")
	require.True(t, ok, "Ollama must be available as a dedicated catalog provider")

	assert.Equal(t, KindCustom, entry.Kind)
	assert.Equal(t, AuthModeOptional, entry.EffectiveAuthMode())
	assert.Equal(t, "Ollama", entry.Name)
	assert.Equal(t, "Self-hosted Ollama (OpenAI-compatible)", entry.Description)
	assert.Empty(t, entry.DefaultHost, "the dashboard owns Ollama's scheme-aware HTTP placeholder")
	assert.Equal(t, "Authorization", entry.AuthHeaderName)
	assert.Equal(t, "Bearer ${API_KEY}", entry.AuthHeaderTemplate)
	assert.Equal(t, "application/json", entry.DefaultContentType)
	assert.Empty(t, entry.ParserID, "Ollama preserves the untagged vLLM/custom routing behavior")
	assert.Empty(t, entry.Models, "Ollama models are installed dynamically on the configured endpoint")
	require.NotNil(t, entry.ModelDiscovery)
	assert.True(t, entry.ModelDiscovery.OllamaFallback)

	wire := entry.ToAPIResponse()
	assert.Equal(t, "ollama", wire.Id)
	assert.Equal(t, api.AgentNetworkCatalogProviderKindCustom, wire.Kind)
	assert.Equal(t, api.AgentNetworkCatalogProviderAuthModeOptional, wire.AuthMode)
	assert.True(t, wire.SupportsModelDiscovery)
	assert.NotNil(t, wire.Models)
	assert.Empty(t, wire.Models)
}

func TestOnlyOllamaSupportsModelDiscovery(t *testing.T) {
	for _, entry := range All() {
		supportsDiscovery := entry.ModelDiscovery != nil
		assert.Equal(t, entry.ID == "ollama", supportsDiscovery, entry.ID)
		assert.Equal(t, supportsDiscovery, entry.ToAPIResponse().SupportsModelDiscovery, entry.ID)
	}
}

func TestCatalogAuthenticationModes(t *testing.T) {
	openAI, ok := Lookup("openai_api")
	require.True(t, ok)
	assert.Empty(t, openAI.AuthMode, "existing entries use the fail-closed default")
	assert.Equal(t, AuthModeRequired, openAI.EffectiveAuthMode())
	assert.Equal(t, api.AgentNetworkCatalogProviderAuthModeRequired, openAI.ToAPIResponse().AuthMode)

	for _, entry := range All() {
		switch entry.EffectiveAuthMode() {
		case AuthModeRequired, AuthModeOptional:
			assert.NotEmpty(t, entry.AuthHeaderName, "%s must declare an auth header name", entry.ID)
			assert.NotEmpty(t, entry.AuthHeaderTemplate, "%s must declare an auth header template", entry.ID)
		case AuthModeNone:
			assert.Empty(t, entry.AuthHeaderName, "%s must not declare an auth header name", entry.ID)
			assert.Empty(t, entry.AuthHeaderTemplate, "%s must not declare an auth header template", entry.ID)
		default:
			t.Errorf("%s has invalid auth mode %q", entry.ID, entry.AuthMode)
		}
	}
}
