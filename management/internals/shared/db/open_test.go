package db

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMysqlDSN(t *testing.T) {
	assert.Equal(t, "user:pw@tcp(host:3306)/db?charset=utf8&parseTime=True&loc=Local", MysqlDSN("user:pw@tcp(host:3306)/db"))
	assert.Equal(t, "user:pw@tcp(host:3306)/db?tls=true&charset=utf8&parseTime=True&loc=Local", MysqlDSN("user:pw@tcp(host:3306)/db?tls=true"))
}

func TestOpenSqlite_InMemoryIsNotJoinedToDataDir(t *testing.T) {
	t.Setenv("NB_STORE_ENGINE_SQLITE_FILE", ":memory:")
	dataDir := t.TempDir()

	conn, err := OpenSqlite(context.Background(), dataDir)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	require.NoError(t, conn.DB(nil).Exec("SELECT 1").Error)
	_, err = os.Stat(filepath.Join(dataDir, ":memory:"))
	require.ErrorIs(t, err, os.ErrNotExist)
}
