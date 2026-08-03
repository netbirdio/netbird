package agentnetwork

import (
	"context"
	"runtime"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/internals/modules/agentnetwork/types"
	"github.com/netbirdio/netbird/management/server/account"
	"github.com/netbirdio/netbird/management/server/permissions"
	"github.com/netbirdio/netbird/management/server/permissions/modules"
	"github.com/netbirdio/netbird/management/server/permissions/operations"
	"github.com/netbirdio/netbird/management/server/store"
	nbtypes "github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/status"
)

// bootstrapFixture wires a real sqlite store to a gomock permissions manager
// so tests can grant the provider permission while denying (or never
// expecting) the settings one.
type bootstrapFixture struct {
	manager Manager
	store   store.Store
	perms   *permissions.MockManager
}

func newBootstrapFixture(t *testing.T) *bootstrapFixture {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("sqlite store not properly supported on Windows yet")
	}
	t.Setenv("NETBIRD_STORE_ENGINE", string(nbtypes.SqliteStoreEngine))

	st, cleanUp, err := store.NewTestStoreFromSQL(context.Background(), "", t.TempDir())
	require.NoError(t, err, "test store setup must succeed")
	t.Cleanup(cleanUp)

	ctrl := gomock.NewController(t)
	perms := permissions.NewMockManager(ctrl)

	accounts := account.NewMockManager(ctrl)
	accounts.EXPECT().StoreEvent(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()
	accounts.EXPECT().UpdateAccountPeers(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()
	accounts.EXPECT().BufferUpdateAccountPeers(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()

	return &bootstrapFixture{
		manager: NewManager(st, perms, accounts, nil, ""),
		store:   st,
		perms:   perms,
	}
}

func (f *bootstrapFixture) expectPermission(accountID, userID string, module modules.Module, op operations.Operation, allowed bool) {
	f.perms.EXPECT().
		ValidateUserPermissions(gomock.Any(), accountID, userID, module, op).
		Return(allowed, context.Background(), nil)
}

func newBootstrapProvider(accountID string) *types.Provider {
	p := types.NewProvider(accountID)
	p.Name = "openai"
	p.UpstreamURL = "https://api.openai.com"
	p.APIKey = "sk-test"
	p.Enabled = true
	return p
}

// TestCreateProviderBootstrapRequiresSettingsPermission pins the gate on the
// one-time settings bootstrap: creating the first provider with a
// bootstrap_cluster pins the account's cluster and subdomain, which is a
// settings write and must not ride on the providers permission alone.
func TestCreateProviderBootstrapRequiresSettingsPermission(t *testing.T) {
	ctx := context.Background()

	t.Run("denied without settings permission", func(t *testing.T) {
		f := newBootstrapFixture(t)
		f.expectPermission("account1", "user1", modules.AgentNetworkProviders, operations.Create, true)
		f.expectPermission("account1", "user1", modules.AgentNetworkSettings, operations.Create, false)

		_, err := f.manager.CreateProvider(ctx, "user1", newBootstrapProvider("account1"), "cluster1.example.com")
		require.Error(t, err, "bootstrap without settings permission must fail")
		var sErr *status.Error
		require.ErrorAs(t, err, &sErr)
		assert.Equal(t, status.PermissionDenied, sErr.Type(), "denial should surface as permission denied")

		providers, err := f.store.GetAccountAgentNetworkProviders(ctx, store.LockingStrengthNone, "account1")
		require.NoError(t, err)
		assert.Empty(t, providers, "provider must not be persisted when bootstrap is denied")
		_, err = f.store.GetAgentNetworkSettings(ctx, store.LockingStrengthNone, "account1")
		assert.Error(t, err, "settings row must not be created when bootstrap is denied")
	})

	t.Run("allowed with settings permission", func(t *testing.T) {
		f := newBootstrapFixture(t)
		f.expectPermission("account1", "user1", modules.AgentNetworkProviders, operations.Create, true)
		f.expectPermission("account1", "user1", modules.AgentNetworkSettings, operations.Create, true)

		created, err := f.manager.CreateProvider(ctx, "user1", newBootstrapProvider("account1"), "cluster1.example.com")
		require.NoError(t, err, "bootstrap with both permissions must succeed")
		require.NotNil(t, created)

		settings, err := f.store.GetAgentNetworkSettings(ctx, store.LockingStrengthNone, "account1")
		require.NoError(t, err, "bootstrap must create the settings row")
		assert.Equal(t, "cluster1.example.com", settings.Cluster, "settings should pin the bootstrap cluster")
	})

	t.Run("existing settings need no settings permission", func(t *testing.T) {
		f := newBootstrapFixture(t)
		require.NoError(t, f.store.SaveAgentNetworkSettings(ctx, &types.Settings{
			AccountID: "account1",
			Cluster:   "cluster1.example.com",
			Subdomain: "existing",
		}), "pre-existing settings row setup must succeed")

		// Only the providers permission may be consulted: gomock fails the
		// test on any unexpected settings-permission call.
		f.expectPermission("account1", "user1", modules.AgentNetworkProviders, operations.Create, true)

		_, err := f.manager.CreateProvider(ctx, "user1", newBootstrapProvider("account1"), "cluster1.example.com")
		require.NoError(t, err, "create with existing settings must not require the settings permission")
	})

	t.Run("no bootstrap cluster needs no settings permission", func(t *testing.T) {
		f := newBootstrapFixture(t)
		f.expectPermission("account1", "user1", modules.AgentNetworkProviders, operations.Create, true)

		_, err := f.manager.CreateProvider(ctx, "user1", newBootstrapProvider("account1"), "")
		require.NoError(t, err, "create without bootstrap must not require the settings permission")
	})
}
