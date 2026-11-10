package store

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/internals/shared/db"
	"github.com/netbirdio/netbird/management/internals/shared/db/migrate"
	"github.com/netbirdio/netbird/management/server/testutil"
	"github.com/netbirdio/netbird/management/server/types"
)

// TestMigrationsMatchAutoMigrate fails when a model changes without a
// migration: the schema the versioned migrations build on an empty database
// must equal the one gorm derives from the models.
func TestMigrationsMatchAutoMigrate(t *testing.T) {
	ctx := context.Background()

	t.Run("sqlite", func(t *testing.T) {
		migrated, err := db.OpenSqliteFile(ctx, t.TempDir(), db.SqliteFileName)
		require.NoError(t, err)
		t.Cleanup(func() { _ = migrated.Close() })
		legacy, err := db.OpenSqliteFile(ctx, t.TempDir(), db.SqliteFileName)
		require.NoError(t, err)
		t.Cleanup(func() { _ = legacy.Close() })

		assertMigrationsMatchLegacy(t, ctx, migrated, legacy)
	})

	t.Run("postgres", func(t *testing.T) {
		if getStoreEngineFromEnv() != types.PostgresStoreEngine {
			t.Skip("NETBIRD_STORE_ENGINE is not postgres")
		}
		dsn, ok := lookupDSNEnv(PostgresDsnEnv, PostgresDsnEnvLegacy)
		if !ok || dsn == "" {
			cleanup, containerDSN, err := testutil.CreatePostgresTestContainer()
			require.NoError(t, err)
			t.Cleanup(cleanup)
			dsn = containerDSN
		}
		admin, err := openDBWithRetry(dsn, 5)
		require.NoError(t, err)
		t.Cleanup(func() { closeGormDB(admin) })

		open := func() *db.Conn {
			randomDSN, cleanup, err := createRandomDB(dsn, admin, "")
			require.NoError(t, err)
			t.Cleanup(cleanup)
			conn, err := db.OpenPostgres(ctx, randomDSN, testPoolConfig)
			require.NoError(t, err)
			t.Cleanup(func() { _ = conn.Close() })
			return conn
		}

		assertMigrationsMatchLegacy(t, ctx, open(), open())
	})
}

func assertMigrationsMatchLegacy(t *testing.T, ctx context.Context, migrated, legacy *db.Conn) {
	t.Helper()
	runner, err := migrate.New(migrated.DB(nil), migrated.Engine(), MigrationSet())
	require.NoError(t, err)
	require.NoError(t, runner.Run(ctx, migrate.ModeAuto))
	require.NoError(t, legacyMigrate(ctx, legacy.DB(nil)))

	want, err := migrate.SchemaSnapshot(legacy.DB(nil))
	require.NoError(t, err)
	got, err := migrate.SchemaSnapshot(migrated.DB(nil), MigrationTable)
	require.NoError(t, err)
	require.Equal(t, want, got)
}

func assertSqliteSchemaEmpty(t *testing.T, dataDir string) {
	t.Helper()
	conn, err := db.OpenSqliteFile(context.Background(), dataDir, db.SqliteFileName)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	tables, err := conn.DB(nil).Migrator().GetTables()
	require.NoError(t, err)
	assert.Empty(t, tables, "no table, version table included, may exist")
}

func TestStoreMigrationMode_CheckFailsOnEmptyDatabase(t *testing.T) {
	t.Setenv("NB_STORE_ENGINE_SQLITE_FILE", "")
	ctx := context.Background()

	t.Run("NewStore", func(t *testing.T) {
		dataDir := t.TempDir()

		_, err := NewStore(ctx, types.SqliteStoreEngine, dataDir, nil, migrate.ModeCheck)

		require.Error(t, err)
		assertSqliteSchemaEmpty(t, dataDir)
	})

	t.Run("NewSqlStore", func(t *testing.T) {
		dataDir := t.TempDir()
		conn, err := db.OpenSqliteFile(ctx, dataDir, db.SqliteFileName)
		require.NoError(t, err)

		_, err = NewSqlStore(ctx, conn, nil, migrate.ModeCheck)

		require.Error(t, err)
		require.NoError(t, conn.Close())
		assertSqliteSchemaEmpty(t, dataDir)
	})
}

func TestStoreMigrationMode_SkipLeavesSchemaEmpty(t *testing.T) {
	t.Setenv("NB_STORE_ENGINE_SQLITE_FILE", "")
	ctx := context.Background()

	t.Run("NewStore", func(t *testing.T) {
		dataDir := t.TempDir()

		store, err := NewStore(ctx, types.SqliteStoreEngine, dataDir, nil, migrate.ModeSkip)

		require.NoError(t, err)
		require.NoError(t, store.Close(ctx))
		assertSqliteSchemaEmpty(t, dataDir)
	})

	t.Run("NewSqlStore", func(t *testing.T) {
		dataDir := t.TempDir()
		conn, err := db.OpenSqliteFile(ctx, dataDir, db.SqliteFileName)
		require.NoError(t, err)

		store, err := NewSqlStore(ctx, conn, nil, migrate.ModeSkip)

		require.NoError(t, err)
		require.NoError(t, store.Close(ctx))
		assertSqliteSchemaEmpty(t, dataDir)
	})
}
