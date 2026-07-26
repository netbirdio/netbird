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
	assert.Equal(t, "Ollama", entry.Name)
	assert.Equal(t, "Self-hosted Ollama (OpenAI-compatible)", entry.Description)
	assert.Empty(t, entry.DefaultHost, "the dashboard owns Ollama's scheme-aware HTTP placeholder")
	assert.Equal(t, "Authorization", entry.AuthHeaderName)
	assert.Equal(t, "Bearer ${API_KEY}", entry.AuthHeaderTemplate)
	assert.Equal(t, "application/json", entry.DefaultContentType)
	assert.Empty(t, entry.ParserID, "phase one must preserve the untagged vLLM/custom routing behavior")
	assert.Empty(t, entry.Models, "Ollama models are installed dynamically on the configured endpoint")

	wire := entry.ToAPIResponse()
	assert.Equal(t, "ollama", wire.Id)
	assert.Equal(t, api.AgentNetworkCatalogProviderKindCustom, wire.Kind)
	assert.NotNil(t, wire.Models)
	assert.Empty(t, wire.Models)
}
