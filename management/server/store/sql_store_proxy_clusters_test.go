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

// TestSqlStore_GetProxyClusters_DerivesOnlineAndType guards the
// account-visible cluster list against silent regressions in two
// dimensions:
//
//  1. Online derivation: a cluster with one stale and one fresh proxy
//     is online and counts only the fresh proxy; a cluster whose
//     proxies all heartbeated outside the 2-min window appears offline
//     with connected_proxies = 0 (rather than disappearing, which is
//     what the old query did).
//  2. Type derivation: a cluster scoped to the calling account is
//     reported as `account`; a cluster with account_id IS NULL is
//     reported as `shared`. Clusters scoped to other accounts must not
//     leak into the result.
//
// Capability flags are intentionally not asserted here — they're filled
// by the manager (handler) layer from the per-cluster capability
// lookups, not by the store query.
func TestSqlStore_GetProxyClusters_DerivesOnlineAndType(t *testing.T) {
	if (os.Getenv("CI") == "true" && runtime.GOOS == "darwin") || runtime.GOOS == "windows" {
		t.Skip("skip CI tests on darwin and windows")
	}

	runTestForAllEngines(t, "", func(t *testing.T, store Store) {
		ctx := context.Background()
		accountID := "acct-clusters"
		require.NoError(t, store.SaveAccount(ctx, newAccountWithId(ctx, accountID, "user-1", "")))

		otherAccountID := "acct-other"
		require.NoError(t, store.SaveAccount(ctx, newAccountWithId(ctx, otherAccountID, "user-2", "")))

		acctID := accountID
		otherID := otherAccountID

		fresh := time.Now().Add(-30 * time.Second)
		stale := time.Now().Add(-30 * time.Minute)

		mustSave := func(id, cluster string, accID *string, status string, lastSeen time.Time) {
			require.NoError(t, store.SaveProxy(ctx, &rpproxy.Proxy{
				ID:             id,
				SessionID:      id + "-sess",
				ClusterAddress: cluster,
				IPAddress:      "10.0.0.1",
				AccountID:      accID,
				LastSeen:       lastSeen,
				Status:         status,
			}))
		}

		// shared-mixed: one fresh + one stale proxy → online, connected=1
		mustSave("p-shared-fresh", "shared-mixed.netbird.io", nil, rpproxy.StatusConnected, fresh)
		mustSave("p-shared-stale", "shared-mixed.netbird.io", nil, rpproxy.StatusConnected, stale)

		// shared-offline: only stale proxies → offline, connected=0,
		// but row must still appear (this is the new semantic — old
		// query would have dropped it entirely).
		mustSave("p-shared-off", "shared-offline.netbird.io", nil, rpproxy.StatusConnected, stale)

		// account-online: BYOP cluster owned by acctID, fresh
		mustSave("p-acct-fresh", "byop.acct.example", &acctID, rpproxy.StatusConnected, fresh)

		// other-account: must not surface for acctID
		mustSave("p-other", "byop.other.example", &otherID, rpproxy.StatusConnected, fresh)

		clusters, err := store.GetProxyClusters(ctx, accountID)
		require.NoError(t, err)

		byAddr := map[string]rpproxy.Cluster{}
		for _, c := range clusters {
			byAddr[c.Address] = c
		}

		assert.NotContains(t, byAddr, "byop.other.example",
			"another account's BYOP cluster must not leak into this account's listing")

		require.Contains(t, byAddr, "shared-mixed.netbird.io")
		mixed := byAddr["shared-mixed.netbird.io"]
		assert.Equal(t, rpproxy.ClusterTypeShared, mixed.Type, "shared cluster (account_id IS NULL) must be reported as Type=shared")
		assert.True(t, mixed.Online, "cluster with a fresh proxy must be online")
		assert.Equal(t, 1, mixed.ConnectedProxies, "connected_proxies must count only fresh proxies; the stale one should not bump the count")

		require.Contains(t, byAddr, "shared-offline.netbird.io",
			"offline clusters must still appear so the dashboard can render them — the old GetActiveProxyClusters would have dropped this row, which is the regression this test guards against")
		offline := byAddr["shared-offline.netbird.io"]
		assert.Equal(t, rpproxy.ClusterTypeShared, offline.Type)
		assert.False(t, offline.Online, "no fresh heartbeat → offline")
		assert.Equal(t, 0, offline.ConnectedProxies, "no fresh proxies → connected_proxies=0")

		require.Contains(t, byAddr, "byop.acct.example")
		acct := byAddr["byop.acct.example"]
		assert.Equal(t, rpproxy.ClusterTypeAccount, acct.Type, "BYOP cluster owned by the account must be reported as Type=account")
		assert.True(t, acct.Online)
		assert.Equal(t, 1, acct.ConnectedProxies)
	})
}
