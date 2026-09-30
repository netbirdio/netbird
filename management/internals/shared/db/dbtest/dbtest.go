package dbtest

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/internals/shared/db"
	"github.com/netbirdio/netbird/management/internals/shared/db/migrate"
	"github.com/netbirdio/netbird/management/server/store"
)

// NewConn opens a fresh SQLite database in a temporary directory, applies the
// management store migrations and closes the connection when the test ends.
// It ignores NB_STORE_ENGINE_SQLITE_FILE, so a developer's configured database
// is never touched, and is safe to call from parallel tests.
func NewConn(t testing.TB) *db.Conn {
	t.Helper()
	conn, err := db.OpenSqliteFile(context.Background(), t.TempDir(), db.SqliteFileName)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	runner, err := migrate.New(conn.DB(nil), conn.Engine(), store.MigrationSet())
	require.NoError(t, err)
	require.NoError(t, runner.Run(context.Background(), migrate.ModeAuto))
	return conn
}
