package agentnetwork

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/server/permissions/modules"
	"github.com/netbirdio/netbird/management/server/permissions/operations"
	"github.com/netbirdio/netbird/management/server/store"
)

// These tests pin the provider read surface per grant: a caller holding
// providers read together with update (managers) gets the full record,
// while read-only viewers (usage_viewer) get the display surface only —
// connection configuration is redacted before it reaches the wire layer.

func TestGetAllProviders_RedactsConnectionConfigForReadOnlyViewer(t *testing.T) {
	ctx := context.Background()
	f := newBootstrapFixture(t)

	saved := newSynthTestProvider()
	saved.ExtraValues = map[string]string{"x-portkey-config": "cfg-123"}
	saved.IdentityHeaderUserID = "X-User"
	saved.IdentityHeaderGroups = "X-Groups"
	saved.SkipTLSVerification = true
	require.NoError(t, f.store.SaveAgentNetworkProvider(ctx, saved))

	f.expectPermission(testAccountID, "viewer", modules.AgentNetworkProviders, operations.Read, true)
	f.expectPermission(testAccountID, "viewer", modules.AgentNetworkProviders, operations.Update, false)

	providers, err := f.manager.GetAllProviders(ctx, testAccountID, "viewer")
	require.NoError(t, err)
	require.Len(t, providers, 1)
	p := providers[0]
	assert.Equal(t, saved.ID, p.ID, "identity survives redaction")
	assert.Equal(t, saved.Name, p.Name)
	assert.Equal(t, saved.ProviderID, p.ProviderID)
	assert.Equal(t, saved.Models, p.Models, "the model list backs the usage filters and stays")
	assert.True(t, p.Enabled)
	assert.Empty(t, p.UpstreamURL, "upstream URL is connection config")
	assert.Empty(t, p.ExtraValues, "operator-typed header values are connection config")
	assert.Empty(t, p.IdentityHeaderUserID)
	assert.Empty(t, p.IdentityHeaderGroups)
	assert.False(t, p.SkipTLSVerification)
	assert.Empty(t, p.APIKey)
	assert.Empty(t, p.SessionPrivateKey)

	stored, err := f.store.GetAgentNetworkProviderByID(ctx, store.LockingStrengthNone, testAccountID, saved.ID)
	require.NoError(t, err)
	assert.NotEmpty(t, stored.UpstreamURL, "redaction must not write back to the store")
}

func TestGetProvider_FullConfigForManagingCaller(t *testing.T) {
	ctx := context.Background()
	f := newBootstrapFixture(t)

	saved := newSynthTestProvider()
	saved.ExtraValues = map[string]string{"x-portkey-config": "cfg-123"}
	require.NoError(t, f.store.SaveAgentNetworkProvider(ctx, saved))

	f.expectPermission(testAccountID, "admin", modules.AgentNetworkProviders, operations.Read, true)
	f.expectPermission(testAccountID, "admin", modules.AgentNetworkProviders, operations.Update, true)

	p, err := f.manager.GetProvider(ctx, testAccountID, "admin", saved.ID)
	require.NoError(t, err)
	assert.Equal(t, saved.UpstreamURL, p.UpstreamURL, "a caller who can edit the provider sees its config")
	assert.Equal(t, saved.ExtraValues, p.ExtraValues)
}

func TestGetProvider_RedactsForReadOnlyViewer(t *testing.T) {
	ctx := context.Background()
	f := newBootstrapFixture(t)

	saved := newSynthTestProvider()
	require.NoError(t, f.store.SaveAgentNetworkProvider(ctx, saved))

	f.expectPermission(testAccountID, "viewer", modules.AgentNetworkProviders, operations.Read, true)
	f.expectPermission(testAccountID, "viewer", modules.AgentNetworkProviders, operations.Update, false)

	p, err := f.manager.GetProvider(ctx, testAccountID, "viewer", saved.ID)
	require.NoError(t, err)
	assert.Equal(t, saved.ID, p.ID)
	assert.Empty(t, p.UpstreamURL)
}
