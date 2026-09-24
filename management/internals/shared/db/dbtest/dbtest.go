package dbtest

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/internals/shared/db"
)

// NewConn opens a fresh SQLite database in a temporary directory, migrates the
// given models and closes the connection when the test ends. The
// NB_STORE_ENGINE_SQLITE_FILE override is cleared so a developer's configured
// database is never touched.
func NewConn(t testing.TB, models ...any) *db.Conn {
	t.Helper()
	t.Setenv("NB_STORE_ENGINE_SQLITE_FILE", "")
	conn, err := db.OpenSqlite(context.Background(), t.TempDir())
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	require.NoError(t, conn.AutoMigrate(models...))
	return conn
}
