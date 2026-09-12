package manager

import (
	"context"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/metric/noop"

	agentNetworkTypes "github.com/netbirdio/netbird/management/internals/modules/agentnetwork/types"
	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy/proxy"
	nbstore "github.com/netbirdio/netbird/management/server/store"
	nbtypes "github.com/netbirdio/netbird/management/server/types"
)

// newStoreBackedManager wires the manager to a real sqlite store, for the
// cases where what matters is how the store's own queries answer the
// post-write re-read — which the function-field mock cannot say.
func newStoreBackedManager(t *testing.T) (*Manager, nbstore.Store) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("sqlite store not properly supported on Windows yet")
	}
	t.Setenv("NETBIRD_STORE_ENGINE", string(nbtypes.SqliteStoreEngine))

	st, cleanUp, err := nbstore.NewTestStoreFromSQL(context.Background(), "", t.TempDir())
	require.NoError(t, err, "test store setup must succeed")
	t.Cleanup(cleanUp)

	mgr, err := NewManager(st, noop.NewMeterProvider().Meter("test"))
	require.NoError(t, err)
	return mgr, st
}

// TestConnect_RealStore_ConfirmsOwnClaims drives the post-write re-read
// through the real queries. Every account-scoped connect now reads its own
// just-written row back, so the whole path depends on the store excluding the
// account's own claims: its own proxy row on a reconnect, and its own gateway
// pin when the account deploys a proxy at the address it pinned first.
func TestConnect_RealStore_ConfirmsOwnClaims(t *testing.T) {
	ctx := context.Background()
	accountID := "account1"
	const host = "byop.account1.example.com"

	t.Run("a reconnect keeps the proxy's own row", func(t *testing.T) {
		mgr, st := newStoreBackedManager(t)

		_, err := mgr.Connect(ctx, "proxy-1", "session-1", host, "10.0.0.1", &accountID, nil)
		require.NoError(t, err, "first connect must succeed")
		_, err = mgr.Connect(ctx, "proxy-1", "session-2", host, "10.0.0.1", &accountID, nil)
		require.NoError(t, err, "a reconnect must not be refused by the row it is replacing")

		rows, err := st.GetAllProxies(ctx)
		require.NoError(t, err)
		require.Len(t, rows, 1, "a reconnect upserts the same row")
		assert.Equal(t, "session-2", rows[0].SessionID, "the row must carry the new session")
		assert.Equal(t, proxy.StatusConnected, rows[0].Status)
	})

	t.Run("the account's own gateway pin is not a competing claim", func(t *testing.T) {
		mgr, st := newStoreBackedManager(t)
		settings := agentNetworkTypes.DefaultSettings(accountID)
		settings.Domain = host
		settings.ProxyAddress = host
		require.NoError(t, st.CreateAgentNetworkSettings(ctx, settings), "seeding the account's own pin must succeed")

		_, err := mgr.Connect(ctx, "proxy-1", "session-1", host, "10.0.0.1", &accountID, nil)
		require.NoError(t, err, "pin first, deploy the proxy after is the documented order")

		rows, err := st.GetAllProxies(ctx)
		require.NoError(t, err)
		assert.Len(t, rows, 1, "the proxy's row must stand next to the account's own pin")
	})

	t.Run("another account's gateway pin withdraws the row", func(t *testing.T) {
		mgr, st := newStoreBackedManager(t)
		settings := agentNetworkTypes.DefaultSettings("account2")
		settings.Domain = host
		settings.ProxyAddress = host
		require.NoError(t, st.CreateAgentNetworkSettings(ctx, settings), "seeding the other account's pin must succeed")

		_, err := mgr.Connect(ctx, "proxy-1", "session-1", host, "10.0.0.1", &accountID, nil)
		require.ErrorIs(t, err, proxy.ErrClusterAddressUnavailable)

		rows, err := st.GetAllProxies(ctx)
		require.NoError(t, err)
		assert.Empty(t, rows, "a withdrawn registration must leave no row behind")
	})
}
