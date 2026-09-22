package networkmap_sqlite_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	networkmap_sqlite "github.com/netbirdio/netbird/management/internals/network_map_db/sqlite"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
)

// GetPoliciesQuery names its columns explicitly, while the schema they live in
// comes from AutoMigrate over types.PolicyRule. Nothing makes the compiler
// relate the two, so a column added to the query without a matching model field
// only fails at runtime, on every policy read. Run the real query against a
// real migrated store.
func TestGetPolicies_QueryMatchesMigratedSchema(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("NETBIRD_STORE_ENGINE", string(types.SqliteStoreEngine))

	_, cleanup, err := store.NewTestStoreFromSQL(context.Background(), "", dir)
	require.NoError(t, err)
	t.Cleanup(cleanup)

	conn, err := networkmap_sqlite.NewSqliteStore("store.db", dir)
	require.NoError(t, err)

	_, _, _, err = conn.UsingConn().GetPolicies(context.Background(), "nonexistent-account")
	require.NoError(t, err, "every column GetPoliciesQuery selects must exist in the migrated schema")
}
