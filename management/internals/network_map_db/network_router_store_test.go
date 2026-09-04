package networkmapdb_test

import (
	"context"
	"net/netip"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	networkmapdb "github.com/netbirdio/netbird/management/internals/network_map_db"
	networkmap_pgsql "github.com/netbirdio/netbird/management/internals/network_map_db/pgsql"
	networkmap_sqlite "github.com/netbirdio/netbird/management/internals/network_map_db/sqlite"
	routerTypes "github.com/netbirdio/netbird/management/server/networks/routers/types"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/testutil"
	"github.com/netbirdio/netbird/management/server/types"
)

// newEngineStores opens both stores on the selected engine's database.
func newEngineStores(t *testing.T) (store.Store, networkmapdb.NetworkMapDBStore) {
	t.Helper()
	ctx := context.Background()

	switch engine := types.Engine(os.Getenv("NETBIRD_STORE_ENGINE")); engine {
	case types.PostgresStoreEngine:
		cleanup, dsn, err := testutil.CreatePostgresTestContainer()
		require.NoError(t, err, "start postgres test container")
		t.Cleanup(cleanup)

		accountStore, err := store.NewPostgresqlStore(ctx, dsn, nil, false)
		require.NoError(t, err, "connect account store")
		t.Cleanup(func() { _ = accountStore.Close(ctx) })

		nmStore, err := networkmap_pgsql.NewPostgresqlStore(ctx, dsn)
		require.NoError(t, err, "connect networkmap store")
		t.Cleanup(func() { nmStore.Pool.Close() })
		return accountStore, nmStore
	case types.SqliteStoreEngine, "":
		dataDir := t.TempDir()
		accountStore, err := store.NewSqliteStore(ctx, dataDir, nil, false)
		require.NoError(t, err, "open account store")
		t.Cleanup(func() { _ = accountStore.Close(ctx) })

		nmStore, err := networkmap_sqlite.NewSqliteStore("store.db", dataDir)
		require.NoError(t, err, "open networkmap store")
		t.Cleanup(func() { _ = nmStore.Db.Close() })
		return accountStore, nmStore
	default:
		t.Skipf("networkmap store does not support engine %q", engine)
		return nil, nil
	}
}

// Peer-based routers must survive the network-map read on every engine.
func TestGetNetworkRouters_ServesPeerBasedRouters(t *testing.T) {
	ctx := context.Background()
	accountStore, nmStore := newEngineStores(t)

	const (
		accountID = "acc-nmap-routers"
		groupID   = "grp-router-members"
		memberID  = "peer-member"
	)

	// Postgres enforces the groups-to-accounts FK that SQLite ignores.
	require.NoError(t, accountStore.SaveAccount(ctx, &types.Account{
		Id: accountID,
		Peers: map[string]*nbpeer.Peer{
			memberID: {
				ID:        memberID,
				AccountID: accountID,
				Key:       memberID + "-key",
				IP:        netip.MustParseAddr("100.64.0.10"),
				Status:    &nbpeer.PeerStatus{},
			},
		},
		Groups: map[string]*types.Group{
			groupID: {
				ID:        groupID,
				AccountID: accountID,
				Name:      "router members",
				Issued:    types.GroupIssuedAPI,
				Peers:     []string{memberID},
			},
		},
	}), "seed the account the routers belong to")

	routers := []*routerTypes.NetworkRouter{
		{ID: "router-peer-nil", AccountID: accountID, NetworkID: "net-peer-nil", PublicID: "pub-peer-nil", Peer: "peer-direct-nil", Enabled: true, Metric: 9999},
		{ID: "router-peer-empty", AccountID: accountID, NetworkID: "net-peer-empty", PublicID: "pub-peer-empty", Peer: "peer-direct-empty", PeerGroups: []string{}, Enabled: true, Metric: 9999},
		{ID: "router-group", AccountID: accountID, NetworkID: "net-group", PublicID: "pub-group", PeerGroups: []string{groupID}, Enabled: true, Metric: 9999},
	}
	for _, router := range routers {
		require.NoError(t, accountStore.CreateNetworkRouter(ctx, router))
	}

	tx, err := nmStore.BeginTx(ctx)
	require.NoError(t, err, "begin networkmap read transaction")
	t.Cleanup(func() { _ = tx.RollbackTx(ctx) })

	got, err := tx.GetNetworkRouters(ctx, accountID)
	require.NoError(t, err, "read network routers")

	assert.Contains(t, got, "net-peer-nil",
		"a router referencing an individual peer (peer_groups stored as NULL) must reach the network map")
	assert.Contains(t, got["net-peer-nil"], "peer-direct-nil",
		"the individual-peer router must be keyed by its peer")

	assert.Contains(t, got, "net-peer-empty",
		"a router referencing an individual peer (peer_groups stored as '[]') must reach the network map")
	assert.Contains(t, got["net-peer-empty"], "peer-direct-empty",
		"the individual-peer router must be keyed by its peer")

	assert.Contains(t, got, "net-group", "a group router must reach the network map")
	assert.Contains(t, got["net-group"], memberID,
		"the group router must fan out to the group's member peers")
}
