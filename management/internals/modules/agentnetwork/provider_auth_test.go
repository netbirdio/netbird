package agentnetwork

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/internals/modules/agentnetwork/catalog"
	"github.com/netbirdio/netbird/management/internals/modules/agentnetwork/types"
)

func TestPrepareProviderAPIKey(t *testing.T) {
	t.Run("required create rejects an empty key", func(t *testing.T) {
		provider := &types.Provider{ProviderID: "openai_api"}
		err := prepareProviderAPIKey(provider, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "api_key is required")
	})

	t.Run("optional create accepts an empty key", func(t *testing.T) {
		provider := &types.Provider{ProviderID: "ollama"}
		require.NoError(t, prepareProviderAPIKey(provider, nil))
		assert.Empty(t, provider.APIKey)
	})

	t.Run("optional update omission preserves the existing key", func(t *testing.T) {
		existing := &types.Provider{ProviderID: "ollama", APIKey: "existing"}
		provider := &types.Provider{ProviderID: "ollama"}
		require.NoError(t, prepareProviderAPIKey(provider, existing))
		assert.Equal(t, "existing", provider.APIKey)
	})

	t.Run("optional update explicit empty clears the existing key", func(t *testing.T) {
		existing := &types.Provider{ProviderID: "ollama", APIKey: "existing"}
		provider := &types.Provider{ProviderID: "ollama", APIKeyProvided: true}
		require.NoError(t, prepareProviderAPIKey(provider, existing))
		assert.Empty(t, provider.APIKey)
	})

	t.Run("changing to optional without a key does not carry the old secret", func(t *testing.T) {
		existing := &types.Provider{ProviderID: "openai_api", APIKey: "sk-old-provider"}
		provider := &types.Provider{ProviderID: "ollama"}
		require.NoError(t, prepareProviderAPIKey(provider, existing))
		assert.Empty(t, provider.APIKey)
	})

	t.Run("changing to required without a key fails", func(t *testing.T) {
		existing := &types.Provider{ProviderID: "ollama", APIKey: "old-optional-key"}
		provider := &types.Provider{ProviderID: "openai_api"}
		err := prepareProviderAPIKey(provider, existing)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "api_key is required")
		assert.Empty(t, provider.APIKey)
	})

	t.Run("required update omission preserves the existing key", func(t *testing.T) {
		existing := &types.Provider{ProviderID: "openai_api", APIKey: "sk-existing"}
		provider := &types.Provider{ProviderID: "openai_api"}
		require.NoError(t, prepareProviderAPIKey(provider, existing))
		assert.Equal(t, "sk-existing", provider.APIKey)
	})

	t.Run("required update rejects a preserved whitespace-only key", func(t *testing.T) {
		existing := &types.Provider{ProviderID: "openai_api", APIKey: "   "}
		provider := &types.Provider{ProviderID: "openai_api"}
		err := prepareProviderAPIKey(provider, existing)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "api_key is required")
		assert.Empty(t, provider.APIKey)
	})

	t.Run("required update explicit empty is rejected", func(t *testing.T) {
		existing := &types.Provider{ProviderID: "openai_api", APIKey: "sk-existing"}
		provider := &types.Provider{ProviderID: "openai_api", APIKeyProvided: true}
		err := prepareProviderAPIKey(provider, existing)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "api_key is required")
	})

	t.Run("unknown catalog provider is rejected", func(t *testing.T) {
		provider := &types.Provider{ProviderID: "unknown", APIKey: "secret"}
		err := prepareProviderAPIKey(provider, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not a known catalog provider")
	})

	t.Run("none mode clears a stale key", func(t *testing.T) {
		entry := catalog.Provider{ID: "authless", AuthMode: catalog.AuthModeNone}
		existing := &types.Provider{ProviderID: "authless", APIKey: "stale-secret"}
		provider := &types.Provider{ProviderID: "authless"}
		require.NoError(t, prepareProviderAPIKeyForEntry(provider, existing, entry))
		assert.Empty(t, provider.APIKey)
	})

	t.Run("none mode rejects a supplied key", func(t *testing.T) {
		entry := catalog.Provider{ID: "authless", AuthMode: catalog.AuthModeNone}
		provider := &types.Provider{
			ProviderID:     "authless",
			APIKey:         "unexpected-secret",
			APIKeyProvided: true,
		}
		err := prepareProviderAPIKeyForEntry(provider, nil, entry)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not supported")
	})
}
