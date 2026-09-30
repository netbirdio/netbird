package sqlc

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/internals/shared/db"
	"github.com/netbirdio/netbird/management/internals/shared/db/dbtest"
	"github.com/netbirdio/netbird/management/internals/shared/db/migrate"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/testutil"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/status"
)

// openConns returns a migrated SQLite connection and, when NETBIRD_STORE_ENGINE
// is postgres, a migrated Postgres one, so every case runs the same code on
// both engines.
func openConns(t *testing.T) map[string]*db.Conn {
	t.Helper()
	conns := map[string]*db.Conn{"sqlite": dbtest.NewConn(t)}
	if os.Getenv("NETBIRD_STORE_ENGINE") != string(db.PostgresStoreEngine) {
		return conns
	}
	cleanup, dsn, err := testutil.CreatePostgresTestContainer()
	require.NoError(t, err)
	t.Cleanup(cleanup)
	conn, err := db.OpenPostgres(context.Background(), dsn, db.DefaultPoolConfig)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	runner, err := migrate.New(conn.DB(nil), conn.Engine(), store.MigrationSet())
	require.NoError(t, err)
	require.NoError(t, runner.Run(context.Background(), migrate.ModeAuto))
	conns["postgres"] = conn
	return conns
}

func TestSetupKeyRepository(t *testing.T) {
	for engine, conn := range openConns(t) {
		t.Run(engine, func(t *testing.T) {
			ctx := context.Background()
			require.NoError(t, conn.DB(nil).Exec("INSERT INTO accounts (id, created_by) VALUES ('acc', 'user')").Error)
			repo := NewSetupKeyRepository(conn)

			expires := time.Date(2027, 1, 2, 3, 4, 5, 0, time.UTC)
			created := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
			key := &types.SetupKey{
				Id:         "key-1",
				AccountID:  "acc",
				Key:        "plain",
				KeySecret:  "hashed",
				Name:       "laptops",
				Type:       types.SetupKeyReusable,
				CreatedAt:  created,
				UpdatedAt:  created,
				ExpiresAt:  &expires,
				AutoGroups: []string{"grp-a", "grp-b"},
				UsageLimit: 5,
				Ephemeral:  true,
			}
			require.NoError(t, repo.Create(ctx, key))
			require.NoError(t, repo.Create(ctx, &types.SetupKey{Id: "key-2", AccountID: "acc", KeySecret: "other", Type: types.SetupKeyOneOff, CreatedAt: created.Add(time.Minute), UpdatedAt: created.Add(time.Minute)}))

			got, err := repo.Get(ctx, db.LockingStrengthNone, "acc", "key-1")
			require.NoError(t, err)
			assert.Equal(t, key.Name, got.Name)
			assert.Equal(t, key.AutoGroups, got.AutoGroups)
			assert.True(t, got.Ephemeral)
			assert.Equal(t, 5, got.UsageLimit)
			assert.True(t, expires.Equal(*got.ExpiresAt))
			assert.Nil(t, got.LastUsed)

			bySecret, err := repo.GetBySecret(ctx, "hashed")
			require.NoError(t, err)
			assert.Equal(t, "key-1", bySecret.Id)

			listed, err := repo.List(ctx, "acc")
			require.NoError(t, err)
			require.Len(t, listed, 2)
			assert.Equal(t, "key-1", listed[0].Id)
			assert.Empty(t, listed[1].AutoGroups)

			usedAt := time.Date(2026, 10, 1, 8, 0, 0, 0, time.UTC)
			require.NoError(t, conn.RunInTx(ctx, func(tx *db.Tx) error {
				locked, err := repo.WithTx(tx).Get(ctx, db.LockingStrengthUpdate, "acc", "key-1")
				if err != nil {
					return err
				}
				return repo.WithTx(tx).IncrementUsage(ctx, "acc", locked.Id, usedAt)
			}))
			used, err := repo.Get(ctx, db.LockingStrengthNone, "acc", "key-1")
			require.NoError(t, err)
			assert.Equal(t, 1, used.UsedTimes)
			require.NotNil(t, used.LastUsed)
			assert.True(t, usedAt.Equal(*used.LastUsed))

			// The gorm store reads what the generated queries wrote, so both
			// paths can coexist during the migration of the store.
			legacy, err := store.NewSqlStore(ctx, conn, nil, migrate.ModeSkip)
			require.NoError(t, err)
			fromGorm, err := legacy.GetSetupKeyByID(ctx, store.LockingStrengthNone, "acc", "key-1")
			require.NoError(t, err)
			assert.Equal(t, used.AutoGroups, fromGorm.AutoGroups)
			assert.Equal(t, used.UsedTimes, fromGorm.UsedTimes)
			assert.True(t, used.LastUsed.Equal(*fromGorm.LastUsed))

			_, err = repo.Get(ctx, db.LockingStrengthNone, "other", "key-1")
			assert.Equal(t, status.NotFound, statusType(t, err))

			require.NoError(t, repo.Delete(ctx, "acc", "key-1"))
			assert.Equal(t, status.NotFound, statusType(t, repo.Delete(ctx, "acc", "key-1")))
		})
	}
}

func TestSqliteRewrite(t *testing.T) {
	pool := sqliteConnPool{}
	assert.Equal(t, "SELECT * FROM t WHERE a = ?1 AND b = ?2", pool.rewrite("SELECT * FROM t WHERE a = $1 AND b = $2\nFOR UPDATE\n"))
	assert.Equal(t, "UPDATE t SET a = ?3, b = ?3 WHERE id = ?1", pool.rewrite("UPDATE t SET a = $3, b = $3 WHERE id = $1"))
	assert.Equal(t, "SELECT * FROM t FOR SHARE_HOLDERS", pool.rewrite("SELECT * FROM t FOR SHARE_HOLDERS"))
}

func statusType(t *testing.T, err error) status.Type {
	t.Helper()
	statusErr, ok := status.FromError(err)
	require.True(t, ok, "expected status error, got %v", err)
	return statusErr.Type()
}
