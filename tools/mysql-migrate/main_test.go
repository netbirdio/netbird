package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	dexstorage "github.com/dexidp/dex/storage"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/xid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"

	"github.com/netbirdio/netbird/idp/dex"
	"github.com/netbirdio/netbird/management/internals/shared/db"
	"github.com/netbirdio/netbird/management/server/activity"
	activitystore "github.com/netbirdio/netbird/management/server/activity/store"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/testutil"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/util/crypt"
)

const testAccountID = "bf1c8084-ba50-4ce7-9439-34653001fc3b"

func TestRun(t *testing.T) {
	if os.Getenv("CI") == "true" && runtime.GOOS != "linux" {
		t.Skip("needs Docker for the MySQL and Postgres containers")
	}
	// Seed in UTC to match the --mysql-timezone default.
	time.Local = time.UTC
	ctx := context.Background()
	dir := t.TempDir()
	key, err := crypt.GenerateKey()
	require.NoError(t, err)

	mysqlDSN := newMySQLDatabase(t, "run_src")
	pgDSN := newPostgresDatabase(t, ctx, "run_dst")
	mysqlStore := seedMySQL(t, ctx, mysqlDSN)
	eventID := seedEvents(t, ctx, dir, key)
	seedIdP(t, ctx, filepath.Join(dir, "idp.db"))

	cfg, err := parseFlags([]string{
		"--mysql-dsn", mysqlDSN,
		"--postgres-dsn", pgDSN,
		"--events-db", filepath.Join(dir, "events.db"),
		"--auth-db", filepath.Join(dir, "idp.db"),
	})
	require.NoError(t, err)
	require.NoError(t, run(ctx, cfg))

	t.Run("management", func(t *testing.T) {
		pgStore, err := store.NewPostgresqlStore(ctx, pgDSN, nil, true)
		require.NoError(t, err)
		t.Cleanup(func() { _ = pgStore.Close(ctx) })

		assert.JSONEq(t, accountJSON(t, ctx, mysqlStore), accountJSON(t, ctx, pgStore),
			"the account read from Postgres must match the one in MySQL")
	})

	t.Run("activity", func(t *testing.T) {
		t.Setenv("NB_ACTIVITY_EVENT_STORE_ENGINE", "postgres")
		t.Setenv("NB_ACTIVITY_EVENT_POSTGRES_DSN", pgDSN)
		events, err := activitystore.NewSqlStore(ctx, dir, key)
		require.NoError(t, err)
		t.Cleanup(func() { _ = events.Close(ctx) })

		got, err := events.Get(ctx, testAccountID, 0, 10, false)
		require.NoError(t, err)
		require.Len(t, got, 1, "the migrated event must be readable")
		assert.Equal(t, eventID, got[0].ID, "the event must keep its id")

		next, err := events.Save(ctx, &activity.Event{Timestamp: time.Now(), AccountID: testAccountID, InitiatorID: "u", TargetID: "p"})
		require.NoError(t, err)
		assert.Greater(t, next.ID, eventID, "new events must continue after the migrated ids")
	})

	t.Run("auth", func(t *testing.T) {
		idp := dex.Storage{Type: "postgres", Config: map[string]any{"dsn": pgDSN}}
		s, err := idp.OpenStorage(slog.New(slog.DiscardHandler))
		require.NoError(t, err)
		t.Cleanup(func() { _ = s.Close() })

		pw, err := s.GetPassword(ctx, "admin@example.com")
		require.NoError(t, err)
		assert.Equal(t, []byte("hash"), pw.Hash, "the IdP password must survive the migration")
	})

	t.Run("refuses a target that holds data", func(t *testing.T) {
		assert.ErrorContains(t, run(ctx, cfg), "target already holds data")
	})
}

func seedMySQL(t *testing.T, ctx context.Context, dsn string) *store.SqlStore {
	t.Helper()
	t.Setenv("NETBIRD_STORE_ENGINE", string(types.SqliteStoreEngine))
	seed, cleanup, err := store.NewTestStoreFromSQL(ctx, "../../management/server/testdata/extended-store.sql", t.TempDir())
	require.NoError(t, err)
	t.Cleanup(cleanup)

	mysqlStore, err := store.NewMysqlStoreFromSqlStore(ctx, seed.(*store.SqlStore), dsn, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = mysqlStore.Close(ctx) })
	return mysqlStore
}

func seedEvents(t *testing.T, ctx context.Context, dir, key string) uint64 {
	t.Helper()
	events, err := activitystore.NewSqlStore(ctx, dir, key)
	require.NoError(t, err)
	defer events.Close(ctx)

	event, err := events.Save(ctx, &activity.Event{
		Timestamp: time.Now(), Activity: activity.PeerAddedByUser,
		AccountID: testAccountID, InitiatorID: "user", TargetID: "peer",
		Meta: map[string]any{"name": "peer"},
	})
	require.NoError(t, err)
	return event.ID
}

func seedIdP(t *testing.T, ctx context.Context, file string) {
	t.Helper()
	idp := dex.Storage{Type: "sqlite3", Config: map[string]any{"file": file}}
	s, err := idp.OpenStorage(slog.New(slog.DiscardHandler))
	require.NoError(t, err)
	defer s.Close()

	require.NoError(t, s.CreatePassword(ctx, dexstorage.Password{
		Email: "admin@example.com", Hash: []byte("hash"), Username: "admin", UserID: "admin-id",
	}))
}

func accountJSON(t *testing.T, ctx context.Context, s store.Store) string {
	t.Helper()
	var account *types.Account
	require.NoError(t, s.ExecuteInTransaction(ctx, func(tx store.Store) error {
		var err error
		account, err = tx.GetAccount(ctx, testAccountID)
		return err
	}))
	out, err := json.Marshal(account)
	require.NoError(t, err)
	return string(out)
}

func TestMySQLTimezone(t *testing.T) {
	if os.Getenv("CI") == "true" && runtime.GOOS != "linux" {
		t.Skip("needs Docker for the MySQL and Postgres containers")
	}
	ctx := context.Background()
	mysqlDSN := newMySQLDatabase(t, "tz_src")
	pgDSN := newPostgresDatabase(t, ctx, "tz_dst")
	ms := seedMySQL(t, ctx, mysqlDSN)
	require.NoError(t, ms.GetDB().Exec("UPDATE accounts SET created_at = '2026-01-02 03:04:05' WHERE id = ?", testAccountID).Error)

	cfg, err := parseFlags([]string{
		"--mysql-dsn", mysqlDSN,
		"--postgres-dsn", pgDSN,
		"--mysql-timezone", "Asia/Tokyo",
		"--events-db", filepath.Join(t.TempDir(), "none.db"),
		"--auth-db", filepath.Join(t.TempDir(), "none.db"),
	})
	require.NoError(t, err)
	require.NoError(t, run(ctx, cfg))

	pool, err := pgxpool.New(ctx, pgDSN)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	var got time.Time
	require.NoError(t, pool.QueryRow(ctx, "SELECT created_at FROM accounts WHERE id = $1", testAccountID).Scan(&got))
	want := time.Date(2026, 1, 1, 18, 4, 5, 0, time.UTC)
	assert.True(t, want.Equal(got), "created_at must keep the instant the server wrote, got %s", got.UTC())
}

func TestParseFlagsRejectsUnknownTimezone(t *testing.T) {
	_, err := parseFlags([]string{"--mysql-dsn", "m", "--postgres-dsn", "p", "--mysql-timezone", "Mars/Base"})
	assert.ErrorContains(t, err, "--mysql-timezone")
}

// newMySQLDatabase creates a database unique to this run in the shared
// container, so repeated runs (-count) don't collide, and drops it afterwards.
func newMySQLDatabase(t *testing.T, prefix string) string {
	t.Helper()
	_, base, err := testutil.CreateMysqlTestContainer()
	require.NoError(t, err)
	admin, err := gorm.Open(mysql.Open(db.MysqlDSN(base)), &gorm.Config{})
	require.NoError(t, err)
	name := prefix + "_" + xid.New().String()
	require.NoError(t, admin.Exec("CREATE DATABASE "+name).Error)
	t.Cleanup(func() {
		_ = admin.Exec("DROP DATABASE IF EXISTS " + name).Error
		if sqlDB, err := admin.DB(); err == nil {
			_ = sqlDB.Close()
		}
	})
	return base[:strings.LastIndex(base, "/")] + "/" + name
}

// newPostgresDatabase is the Postgres counterpart of newMySQLDatabase.
func newPostgresDatabase(t *testing.T, ctx context.Context, prefix string) string {
	t.Helper()
	_, base, err := testutil.CreatePostgresTestContainer()
	require.NoError(t, err)
	// Dex connects through lib/pq, which requires TLS unless told otherwise.
	base = strings.TrimSuffix(base, "?")
	admin, err := pgxpool.New(ctx, base+"?sslmode=disable")
	require.NoError(t, err)
	name := prefix + "_" + xid.New().String()
	_, err = admin.Exec(ctx, "CREATE DATABASE "+name)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = admin.Exec(context.Background(), "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)")
		admin.Close()
	})
	return base[:strings.LastIndex(base, "/")] + "/" + name + "?sslmode=disable"
}
