package store

import (
	"context"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/rs/xid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/netbirdio/netbird/management/internals/shared/db"
	"github.com/netbirdio/netbird/management/internals/shared/db/migrate"
	"github.com/netbirdio/netbird/management/server/testutil"
	"github.com/netbirdio/netbird/util/crypt"
)

func newFieldEncrypt(t *testing.T) *crypt.FieldEncrypt {
	t.Helper()
	key, err := crypt.GenerateKey()
	require.NoError(t, err)
	fieldEncrypt, err := crypt.NewFieldEncrypt(key)
	require.NoError(t, err)
	return fieldEncrypt
}

func openGorm(t *testing.T, dialector gorm.Dialector) *gorm.DB {
	t.Helper()
	gormDB, err := gorm.Open(dialector, &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	require.NoError(t, err)
	t.Cleanup(func() {
		if sqlDB, err := gormDB.DB(); err == nil {
			_ = sqlDB.Close()
		}
	})
	return gormDB
}

// TestMigrationsMatchAutoMigrate fails when an activity model changes without
// a migration: the schema the versioned migrations build on an empty database
// must equal the one the legacy bootstrap derives from the models.
func TestMigrationsMatchAutoMigrate(t *testing.T) {
	ctx := context.Background()
	fieldEncrypt := newFieldEncrypt(t)

	assertMatches := func(t *testing.T, engine db.Engine, migrated, legacy *gorm.DB) {
		runner, err := migrate.New(migrated, engine, MigrationSet(fieldEncrypt))
		require.NoError(t, err)
		require.NoError(t, runner.Run(ctx, migrate.ModeAuto))
		require.NoError(t, legacyMigrate(ctx, fieldEncrypt, legacy))

		want, err := migrate.SchemaSnapshot(legacy)
		require.NoError(t, err)
		got, err := migrate.SchemaSnapshot(migrated, MigrationTable)
		require.NoError(t, err)
		assert.Equal(t, want, got)
	}

	t.Run("sqlite", func(t *testing.T) {
		open := func() *gorm.DB {
			return openGorm(t, sqlite.Open(filepath.Join(t.TempDir(), eventSinkDB)))
		}
		assertMatches(t, db.SqliteStoreEngine, open(), open())
	})

	t.Run("postgres", func(t *testing.T) {
		if os.Getenv("NETBIRD_STORE_ENGINE") != string(db.PostgresStoreEngine) {
			t.Skip("NETBIRD_STORE_ENGINE is not postgres")
		}
		cleanup, dsn, err := testutil.CreatePostgresTestContainer()
		require.NoError(t, err)
		t.Cleanup(cleanup)
		admin := openGorm(t, postgres.Open(dsn))

		open := func() *gorm.DB {
			name := "activity_" + xid.New().String()
			require.NoError(t, admin.Exec("CREATE DATABASE "+name).Error)
			t.Cleanup(func() { _ = admin.Exec("DROP DATABASE IF EXISTS " + name + " WITH (FORCE)").Error })
			u, err := url.Parse(dsn)
			require.NoError(t, err)
			u.Path = "/" + name
			return openGorm(t, postgres.Open(u.String()))
		}
		assertMatches(t, db.PostgresStoreEngine, open(), open())
	})
}

func assertEventsDatabaseEmpty(t *testing.T, dataDir string) {
	t.Helper()
	gormDB := openGorm(t, sqlite.Open(filepath.Join(dataDir, eventSinkDB)))
	tables, err := gormDB.Migrator().GetTables()
	require.NoError(t, err)
	assert.Empty(t, tables, "no table, version table included, may exist")
}

func TestNewSqlStore_ModeCheckFailsOnEmptyDatabase(t *testing.T) {
	t.Setenv(storeEngineEnv, "sqlite")
	dataDir := t.TempDir()
	key, err := crypt.GenerateKey()
	require.NoError(t, err)

	_, err = NewSqlStore(context.Background(), dataDir, key, migrate.ModeCheck)

	require.Error(t, err)
	assertEventsDatabaseEmpty(t, dataDir)
}

func TestNewSqlStore_ModeSkipLeavesSchemaEmpty(t *testing.T) {
	t.Setenv(storeEngineEnv, "sqlite")
	dataDir := t.TempDir()
	key, err := crypt.GenerateKey()
	require.NoError(t, err)

	store, err := NewSqlStore(context.Background(), dataDir, key, migrate.ModeSkip)

	require.NoError(t, err)
	require.NoError(t, store.Close(context.Background()))
	assertEventsDatabaseEmpty(t, dataDir)
}
