package dbtest

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/internals/shared/db"
)

// NewConn opens a fresh SQLite database in a temporary directory, migrates the
// given models and closes the connection when the test ends. It ignores
// NB_STORE_ENGINE_SQLITE_FILE, so a developer's configured database is never
// touched, and is safe to call from parallel tests.
func NewConn(t testing.TB, models ...any) *db.Conn {
	t.Helper()
	conn, err := db.OpenSqliteFile(context.Background(), t.TempDir(), db.SqliteFileName)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	require.NoError(t, conn.AutoMigrate(models...))
	return conn
}
