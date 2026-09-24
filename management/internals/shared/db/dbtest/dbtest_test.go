package dbtest

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/internals/shared/db"
)

func TestNewConn_IgnoresSqliteFileOverride(t *testing.T) {
	override := filepath.Join(t.TempDir(), "configured.db")
	t.Setenv("NB_STORE_ENGINE_SQLITE_FILE", override)

	conn := NewConn(t)

	assert.Equal(t, db.SqliteStoreEngine, conn.Engine())
	_, err := os.Stat(override)
	require.ErrorIs(t, err, os.ErrNotExist)
}
