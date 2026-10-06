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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/idp/dex"
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
	// MySQL returns times in the local zone and Postgres in UTC.
	time.Local = time.UTC
	ctx := context.Background()
	dir := t.TempDir()
	key, err := crypt.GenerateKey()
	require.NoError(t, err)

	mysqlDSN, mysqlStore := seedMySQL(t, ctx)
	eventID := seedEvents(t, ctx, dir, key)
	seedIdP(t, ctx, filepath.Join(dir, "idp.db"))

	_, pgDSN, err := testutil.CreatePostgresTestContainer()
	require.NoError(t, err)
	// Dex connects through lib/pq, which requires TLS unless told otherwise.
	pgDSN = strings.TrimSuffix(pgDSN, "?") + "?sslmode=disable"

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

func seedMySQL(t *testing.T, ctx context.Context) (string, store.Store) {
	t.Helper()
	t.Setenv("NETBIRD_STORE_ENGINE", string(types.SqliteStoreEngine))
	seed, cleanup, err := store.NewTestStoreFromSQL(ctx, "../../management/server/testdata/extended-store.sql", t.TempDir())
	require.NoError(t, err)
	t.Cleanup(cleanup)

	_, dsn, err := testutil.CreateMysqlTestContainer()
	require.NoError(t, err)
	mysqlStore, err := store.NewMysqlStoreFromSqlStore(ctx, seed.(*store.SqlStore), dsn, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = mysqlStore.Close(ctx) })
	return dsn, mysqlStore
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
