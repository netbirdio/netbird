package server

import (
	"context"
	"net/netip"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	networkmapdbfactory "github.com/netbirdio/netbird/management/internals/network_map_db/factory"
	networkmap_sqlite "github.com/netbirdio/netbird/management/internals/network_map_db/sqlite"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/route"
)

// TestNetworkMapStore_LoadsRouteCountries covers the network map store, which reads routes
// with its own query: a route saved through the account store must keep its countries there.
func TestNetworkMapStore_LoadsRouteCountries(t *testing.T) {
	if engine := os.Getenv("NETBIRD_STORE_ENGINE"); engine != "" && !strings.EqualFold(engine, string(types.SqliteStoreEngine)) {
		t.Skipf("network map store test needs the sqlite engine, got %s", engine)
	}

	ctx := context.Background()
	dataDir := t.TempDir()
	accountStore, cleanUp, err := store.NewTestStoreFromSQL(ctx, "testdata/extended-store.sql", dataDir)
	require.NoError(t, err)
	t.Cleanup(cleanUp)

	accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"
	require.NoError(t, accountStore.SaveRoute(ctx, &route.Route{
		ID:          "country-route",
		AccountID:   accountID,
		Network:     netip.MustParsePrefix("192.0.2.0/32"),
		Countries:   []string{"CA", "US"},
		NetID:       "us-exit",
		NetworkType: route.CountryNetwork,
		Metric:      9999,
		Enabled:     true,
	}))

	nmdataStore, err := networkmapdbfactory.NewNetworkMapDBStore(ctx, types.SqliteStoreEngine, dataDir, MockIntegratedValidator{}, newSettingsMockManager(t), nil, nil)
	require.NoError(t, err)
	sqliteStore, ok := nmdataStore.Store.(*networkmap_sqlite.SqliteStore)
	require.True(t, ok, "network map store is %T, want *networkmap_sqlite.SqliteStore", nmdataStore.Store)
	t.Cleanup(func() { assert.NoError(t, sqliteStore.Db.Close()) })

	routes, err := sqliteStore.UsingConn().GetRoutes(ctx, accountID)
	require.NoError(t, err)

	var loaded bool
	for _, r := range routes {
		if r.ID != "country-route" {
			continue
		}
		loaded = true
		assert.Equal(t, []string{"CA", "US"}, r.Countries, "the network map store must load the countries")
		assert.True(t, r.IsCountry(), "the route should keep its country network type")
	}
	assert.True(t, loaded, "the country route should be loaded")
}
