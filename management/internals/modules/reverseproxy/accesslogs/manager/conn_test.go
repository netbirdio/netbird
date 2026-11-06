package manager

import (
	"context"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rs/xid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy/accesslogs"
	"github.com/netbirdio/netbird/management/internals/shared/db"
	"github.com/netbirdio/netbird/management/internals/shared/db/migrate"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/testutil"
)

func unsetStoreEnv(t *testing.T) {
	t.Helper()
	for _, key := range []string{StoreEngineEnv, PostgresDSNEnv, SqliteFileEnv, MaxOpenConnsEnv, store.PostgresDsnEnv, store.PostgresDsnEnvLegacy} {
		t.Setenv(key, "")
		require.NoError(t, os.Unsetenv(key))
	}
}

func openTestConn(t *testing.T, dataDir string, mainEngine db.Engine) *db.Conn {
	t.Helper()
	conn, err := OpenConn(context.Background(), dataDir, mainEngine, migrate.ModeAuto)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func assertStoresEntries(t *testing.T, conn *db.Conn) {
	t.Helper()
	ctx := context.Background()
	repo := NewRepository(conn)
	require.NoError(t, repo.Create(ctx, newEntry("entry", "acc", "GET", time.Minute)))

	logs, total, err := repo.ListByAccount(ctx, db.LockingStrengthNone, "acc", accesslogs.AccessLogFilter{Page: 1, PageSize: 10})
	require.NoError(t, err)
	assert.EqualValues(t, 1, total, "the stored entry should be listed")
	require.Len(t, logs, 1)
	assert.Equal(t, "entry", logs[0].ID)
}

func TestOpenConn_SqliteUsesItsOwnFile(t *testing.T) {
	unsetStoreEnv(t)
	dataDir := t.TempDir()

	conn := openTestConn(t, dataDir, db.SqliteStoreEngine)

	assert.Equal(t, db.SqliteStoreEngine, conn.Engine())
	assert.FileExists(t, filepath.Join(dataDir, sqliteFileName))
	assert.NoFileExists(t, filepath.Join(dataDir, db.SqliteFileName), "the main store file must not be opened")
	assertStoresEntries(t, conn)
}

func TestOpenConn_SqliteFileFromEnv(t *testing.T) {
	unsetStoreEnv(t)
	dataDir := t.TempDir()
	t.Setenv(SqliteFileEnv, "custom_logs.db")

	conn := openTestConn(t, dataDir, db.SqliteStoreEngine)

	assert.FileExists(t, filepath.Join(dataDir, "custom_logs.db"))
	assert.NoFileExists(t, filepath.Join(dataDir, sqliteFileName))
	assertStoresEntries(t, conn)
}

func TestOpenConn_EngineFromEnvOverridesMainEngine(t *testing.T) {
	unsetStoreEnv(t)
	t.Setenv(StoreEngineEnv, "SQLite")

	conn := openTestConn(t, t.TempDir(), db.PostgresStoreEngine)

	assert.Equal(t, db.SqliteStoreEngine, conn.Engine(), "the configured engine should win over the main store engine")
}

func TestOpenConn_PostgresWithoutDSNFails(t *testing.T) {
	unsetStoreEnv(t)

	_, err := OpenConn(context.Background(), t.TempDir(), db.PostgresStoreEngine, migrate.ModeAuto)

	require.Error(t, err)
	assert.Contains(t, err.Error(), PostgresDSNEnv)
}

func TestOpenConn_UnsupportedEngineFails(t *testing.T) {
	unsetStoreEnv(t)
	t.Setenv(StoreEngineEnv, "mysql")

	_, err := OpenConn(context.Background(), t.TempDir(), db.SqliteStoreEngine, migrate.ModeAuto)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "mysql")
}

func TestOpenConn_PostgresReusesMainDSNWithItsOwnPool(t *testing.T) {
	if os.Getenv("NETBIRD_STORE_ENGINE") != string(db.PostgresStoreEngine) {
		t.Skip("requires NETBIRD_STORE_ENGINE=postgres")
	}
	unsetStoreEnv(t)
	cleanup, dsn, err := testutil.CreatePostgresTestContainer()
	require.NoError(t, err)
	t.Cleanup(cleanup)
	t.Setenv(store.PostgresDsnEnv, dsn)
	t.Setenv(MaxOpenConnsEnv, "3")

	conn := openTestConn(t, t.TempDir(), db.PostgresStoreEngine)

	assert.Equal(t, db.PostgresStoreEngine, conn.Engine())
	assert.Nil(t, conn.Pool(nil), "access logs never take the pgx read paths, so no pgx pool should be opened")
	sqlDB, err := conn.DB(nil).DB()
	require.NoError(t, err)
	assert.Equal(t, 3, sqlDB.Stats().MaxOpenConnections, "the pool should be sized by %s", MaxOpenConnsEnv)
	assertStoresEntries(t, conn)
}

func TestConnOptions_SizesPoolFromEnv(t *testing.T) {
	// Invalid values fall back to the store-wide setting instead of failing boot.
	cases := map[string]int{"3": 3, "": 7, "zero": 7, "0": 7, "-1": 7}
	for value, want := range cases {
		t.Run(value, func(t *testing.T) {
			t.Setenv("NB_SQL_MAX_OPEN_CONNS", "7")
			t.Setenv(MaxOpenConnsEnv, value)

			gormDB, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "pool.db")), db.GormConfig())
			require.NoError(t, err)
			conn, err := db.NewConn(context.Background(), gormDB, db.PostgresStoreEngine, nil, connOptions(context.Background())...)
			require.NoError(t, err)
			t.Cleanup(func() { _ = conn.Close() })

			sqlDB, err := conn.DB(nil).DB()
			require.NoError(t, err)
			assert.Equal(t, want, sqlDB.Stats().MaxOpenConnections, "max open connections for %s=%q", MaxOpenConnsEnv, value)
		})
	}
}

// TestMigrationsMatchAutoMigrate fails when the access log model changes
// without a migration: the schema the versioned migrations build on an empty
// database must equal the one gorm derives from the model.
func TestMigrationsMatchAutoMigrate(t *testing.T) {
	open := func(t *testing.T, dir string) *db.Conn {
		conn, err := db.OpenSqliteFile(context.Background(), dir, sqliteFileName)
		require.NoError(t, err)
		t.Cleanup(func() { _ = conn.Close() })
		return conn
	}
	if os.Getenv("NETBIRD_STORE_ENGINE") == string(db.PostgresStoreEngine) {
		open = func(t *testing.T, _ string) *db.Conn {
			cleanup, dsn, err := testutil.CreatePostgresTestContainer()
			require.NoError(t, err)
			t.Cleanup(cleanup)
			admin, err := db.OpenPostgres(context.Background(), dsn, db.DefaultPoolConfig)
			require.NoError(t, err)
			t.Cleanup(func() { _ = admin.Close() })

			name := "accesslogs_" + xid.New().String()
			require.NoError(t, admin.DB(nil).Exec("CREATE DATABASE "+name).Error)
			t.Cleanup(func() { _ = admin.DB(nil).Exec("DROP DATABASE IF EXISTS " + name + " WITH (FORCE)").Error })
			u, err := url.Parse(dsn)
			require.NoError(t, err)
			u.Path = "/" + name

			conn, err := db.OpenPostgres(context.Background(), u.String(), db.DefaultPoolConfig)
			require.NoError(t, err)
			t.Cleanup(func() { _ = conn.Close() })
			return conn
		}
	}

	migrated := open(t, t.TempDir())
	runner, err := migrate.New(migrated.DB(nil), migrated.Engine(), MigrationSet())
	require.NoError(t, err)
	require.NoError(t, runner.Run(context.Background(), migrate.ModeAuto))

	legacy := open(t, t.TempDir())
	require.NoError(t, legacy.DB(nil).AutoMigrate(&accesslogs.AccessLogEntry{}))

	want, err := migrate.SchemaSnapshot(legacy.DB(nil))
	require.NoError(t, err)
	got, err := migrate.SchemaSnapshot(migrated.DB(nil), MigrationTable)
	require.NoError(t, err)
	assert.Equal(t, want, got)
}
