package store

import (
	"context"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	rpproxy "github.com/netbirdio/netbird/management/internals/modules/reverseproxy/proxy"
)

// TestSqlStore_DisconnectAllProxies guards the administrative
// force-disconnect helper:
//
//  1. Every proxy that is not already disconnected is marked
//     disconnected regardless of its session ID (unlike
//     DisconnectProxy, which is session-guarded).
//  2. Rows that are already disconnected are left untouched, so their
//     original disconnected_at is preserved and the returned count
//     reflects only the rows that actually changed.
//  3. last_seen is not modified — the stale-proxy reaper keeps working
//     off the real last heartbeat.
func TestSqlStore_DisconnectAllProxies(t *testing.T) {
	if (os.Getenv("CI") == "true" && runtime.GOOS == "darwin") || runtime.GOOS == "windows" {
		t.Skip("skip CI tests on darwin and windows")
	}

	runTestForAllEngines(t, "", func(t *testing.T, store Store) {
		ctx := context.Background()

		lastSeenFresh := time.Now().Add(-30 * time.Second)
		lastSeenStale := time.Now().Add(-30 * time.Minute)
		oldDisconnectedAt := time.Now().Add(-time.Hour)

		accountID := "acct-disconnect"
		proxies := []*rpproxy.Proxy{
			{
				ID:             "p-connected-fresh",
				SessionID:      "sess-1",
				ClusterAddress: "cluster-a.example.com",
				IPAddress:      "10.0.0.1",
				LastSeen:       lastSeenFresh,
				Status:         rpproxy.StatusConnected,
			},
			{
				ID:             "p-connected-stale",
				SessionID:      "sess-2",
				ClusterAddress: "cluster-b.example.com",
				IPAddress:      "10.0.0.2",
				AccountID:      &accountID,
				LastSeen:       lastSeenStale,
				Status:         rpproxy.StatusConnected,
			},
			{
				ID:             "p-already-disconnected",
				SessionID:      "sess-3",
				ClusterAddress: "cluster-a.example.com",
				IPAddress:      "10.0.0.3",
				LastSeen:       lastSeenStale,
				Status:         rpproxy.StatusDisconnected,
				DisconnectedAt: &oldDisconnectedAt,
			},
		}
		for _, p := range proxies {
			require.NoError(t, store.SaveProxy(ctx, p))
		}

		all, err := store.GetAllProxies(ctx)
		require.NoError(t, err)
		require.Len(t, all, 3)

		disconnected, err := store.DisconnectAllProxies(ctx)
		require.NoError(t, err)
		assert.Equal(t, int64(2), disconnected)

		all, err = store.GetAllProxies(ctx)
		require.NoError(t, err)
		require.Len(t, all, 3)

		byID := make(map[string]*rpproxy.Proxy, len(all))
		for _, p := range all {
			byID[p.ID] = p
		}

		for id, p := range byID {
			assert.Equal(t, rpproxy.StatusDisconnected, p.Status, "proxy %s should be disconnected", id)
			require.NotNil(t, p.DisconnectedAt, "proxy %s should have disconnected_at set", id)
		}

		// force-marked rows carry a fresh disconnected_at; the untouched row keeps its original one
		assert.WithinDuration(t, time.Now(), *byID["p-connected-fresh"].DisconnectedAt, 10*time.Second)
		assert.WithinDuration(t, time.Now(), *byID["p-connected-stale"].DisconnectedAt, 10*time.Second)
		assert.WithinDuration(t, oldDisconnectedAt, *byID["p-already-disconnected"].DisconnectedAt, time.Second)

		// last_seen is preserved so the stale reaper schedule is unaffected
		assert.WithinDuration(t, lastSeenFresh, byID["p-connected-fresh"].LastSeen, time.Second)
		assert.WithinDuration(t, lastSeenStale, byID["p-connected-stale"].LastSeen, time.Second)

		// idempotent: a second run has nothing left to update
		disconnected, err = store.DisconnectAllProxies(ctx)
		require.NoError(t, err)
		assert.Equal(t, int64(0), disconnected)
	})
}

func TestSqlStore_UpdateProxyHeartbeatRestoresDisconnectedCurrentSession(t *testing.T) {
	if (os.Getenv("CI") == "true" && runtime.GOOS == "darwin") || runtime.GOOS == "windows" {
		t.Skip("skip CI tests on darwin and windows")
	}

	runTestForAllEngines(t, "", func(t *testing.T, store Store) {
		ctx := context.Background()
		proxy := &rpproxy.Proxy{
			ID:             "p-heartbeat",
			SessionID:      "sess-heartbeat",
			ClusterAddress: "cluster-heartbeat.example.com",
			IPAddress:      "10.0.0.10",
			LastSeen:       time.Now().Add(-30 * time.Second),
			Status:         rpproxy.StatusConnected,
		}
		require.NoError(t, store.SaveProxy(ctx, proxy))

		disconnected, err := store.DisconnectAllProxies(ctx)
		require.NoError(t, err)
		require.Equal(t, int64(1), disconnected)

		require.NoError(t, store.UpdateProxyHeartbeat(ctx, &rpproxy.Proxy{ID: proxy.ID, SessionID: proxy.SessionID}))

		all, err := store.GetAllProxies(ctx)
		require.NoError(t, err)
		require.Len(t, all, 1)
		assert.Equal(t, rpproxy.StatusConnected, all[0].Status)
		assert.Nil(t, all[0].DisconnectedAt)
		assert.WithinDuration(t, time.Now(), all[0].LastSeen, 10*time.Second)

		addresses, err := store.GetActiveProxyClusterAddresses(ctx)
		require.NoError(t, err)
		assert.Contains(t, addresses, proxy.ClusterAddress)
	})
}

func TestSqlStore_GetAllProxies_Empty(t *testing.T) {
	if (os.Getenv("CI") == "true" && runtime.GOOS == "darwin") || runtime.GOOS == "windows" {
		t.Skip("skip CI tests on darwin and windows")
	}

	runTestForAllEngines(t, "", func(t *testing.T, store Store) {
		all, err := store.GetAllProxies(context.Background())
		require.NoError(t, err)
		assert.Empty(t, all)
	})
}
