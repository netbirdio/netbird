package manager

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy/accesslogs"
	"github.com/netbirdio/netbird/management/internals/shared/db"
	"github.com/netbirdio/netbird/management/internals/shared/db/dbtest"
	"github.com/netbirdio/netbird/management/server/testutil"
)

func newTestRepository(t *testing.T) (accesslogs.Repository, *db.Conn) {
	conn := dbtest.NewConn(t, &accesslogs.AccessLogEntry{})
	return NewRepository(conn), conn
}

func newEntry(id, accountID, method string, age time.Duration) *accesslogs.AccessLogEntry {
	return &accesslogs.AccessLogEntry{
		ID:         id,
		AccountID:  accountID,
		Method:     method,
		Host:       "app.example.com",
		Path:       "/",
		StatusCode: 200,
		Timestamp:  time.Now().Add(-age),
	}
}

func TestSqlRepository_ListByAccount(t *testing.T) {
	repo, _ := newTestRepository(t)
	ctx := context.Background()
	for _, entry := range []*accesslogs.AccessLogEntry{
		newEntry("a1", "acc-a", "GET", 3*time.Hour),
		newEntry("a2", "acc-a", "POST", 2*time.Hour),
		newEntry("a3", "acc-a", "GET", time.Hour),
		newEntry("b1", "acc-b", "GET", time.Hour),
	} {
		require.NoError(t, repo.Create(ctx, entry))
	}

	logs, total, err := repo.ListByAccount(ctx, db.LockingStrengthNone, "acc-a", accesslogs.AccessLogFilter{Page: 1, PageSize: 2})
	require.NoError(t, err)
	assert.EqualValues(t, 3, total)
	require.Len(t, logs, 2)
	assert.Equal(t, "a3", logs[0].ID)
	assert.Equal(t, "a2", logs[1].ID)

	method := "GET"
	logs, total, err = repo.ListByAccount(ctx, db.LockingStrengthNone, "acc-a", accesslogs.AccessLogFilter{Page: 1, PageSize: 10, Method: &method, SortOrder: "asc"})
	require.NoError(t, err)
	assert.EqualValues(t, 2, total)
	require.Len(t, logs, 2)
	assert.Equal(t, "a1", logs[0].ID)
	assert.Equal(t, "a3", logs[1].ID)
}

func TestSqlRepository_DeleteOlderThan(t *testing.T) {
	repo, _ := newTestRepository(t)
	ctx := context.Background()
	require.NoError(t, repo.Create(ctx, newEntry("old", "acc", "GET", 48*time.Hour)))
	require.NoError(t, repo.Create(ctx, newEntry("new", "acc", "GET", time.Hour)))

	deleted, err := repo.DeleteOlderThan(ctx, time.Now().Add(-24*time.Hour))
	require.NoError(t, err)
	assert.EqualValues(t, 1, deleted)

	logs, total, err := repo.ListByAccount(ctx, db.LockingStrengthNone, "acc", accesslogs.AccessLogFilter{Page: 1, PageSize: 10})
	require.NoError(t, err)
	assert.EqualValues(t, 1, total)
	require.Len(t, logs, 1)
	assert.Equal(t, "new", logs[0].ID)
}

func TestSqlRepository_CreateInsideTransactionRollsBack(t *testing.T) {
	repo, conn := newTestRepository(t)
	ctx := context.Background()
	failure := errors.New("abort")

	err := conn.RunInTx(ctx, func(tx *db.Tx) error {
		txRepo := repo.WithTx(tx)
		require.NoError(t, txRepo.Create(ctx, newEntry("tx", "acc", "GET", 0)))
		_, total, err := txRepo.ListByAccount(ctx, db.LockingStrengthNone, "acc", accesslogs.AccessLogFilter{Page: 1, PageSize: 10})
		require.NoError(t, err)
		assert.EqualValues(t, 1, total)
		return failure
	})
	require.ErrorIs(t, err, failure)

	_, total, err := repo.ListByAccount(ctx, db.LockingStrengthNone, "acc", accesslogs.AccessLogFilter{Page: 1, PageSize: 10})
	require.NoError(t, err)
	assert.Zero(t, total)
}

func TestSqlRepository_ListByAccount_StatusFilter(t *testing.T) {
	repo, _ := newTestRepository(t)
	ctx := context.Background()
	statusCodes := map[string]int{"l4": 0, "info": 101, "ok": 200, "notfound": 404}
	for id, code := range statusCodes {
		entry := newEntry(id, "acc", "GET", time.Hour)
		entry.StatusCode = code
		require.NoError(t, repo.Create(ctx, entry))
	}
	foreign := newEntry("foreign", "other", "GET", time.Hour)
	foreign.StatusCode = 500
	require.NoError(t, repo.Create(ctx, foreign))

	listIDs := func(status string) []string {
		logs, total, err := repo.ListByAccount(ctx, db.LockingStrengthNone, "acc", accesslogs.AccessLogFilter{Page: 1, PageSize: 10, Status: &status, SortBy: "status_code", SortOrder: "asc"})
		require.NoError(t, err)
		require.EqualValues(t, len(logs), total)
		ids := make([]string, 0, len(logs))
		for _, entry := range logs {
			ids = append(ids, entry.ID)
		}
		return ids
	}

	assert.Equal(t, []string{"info", "notfound"}, listIDs("failed"))
	assert.Equal(t, []string{"ok"}, listIDs("success"))
}

func TestSqlRepository_ListByAccount_Search(t *testing.T) {
	repo, _ := newTestRepository(t)
	ctx := context.Background()
	api := newEntry("req-api", "acc", "GET", time.Hour)
	api.Host = "api.example.com"
	api.Path = "/v1/peers"
	web := newEntry("req-web", "acc", "GET", 2*time.Hour)
	web.Host = "web.example.com"
	web.Path = "/login"
	foreign := newEntry("foreign", "other", "GET", time.Hour)
	foreign.Host = "api.example.com"
	for _, entry := range []*accesslogs.AccessLogEntry{api, web, foreign} {
		require.NoError(t, repo.Create(ctx, entry))
	}

	search := func(term string) []string {
		logs, total, err := repo.ListByAccount(ctx, db.LockingStrengthNone, "acc", accesslogs.AccessLogFilter{Page: 1, PageSize: 10, Search: &term})
		require.NoError(t, err)
		require.EqualValues(t, len(logs), total)
		ids := make([]string, 0, len(logs))
		for _, entry := range logs {
			ids = append(ids, entry.ID)
		}
		return ids
	}

	assert.Equal(t, []string{"req-api"}, search("api.example"), "search should match the host")
	assert.Equal(t, []string{"req-web"}, search("/login"), "search should match the path")
	assert.Equal(t, []string{"req-api"}, search("example.com/v1"), "search should match host and path joined")
	assert.Equal(t, []string{"req-web"}, search("req-web"), "search should match the log ID")
	assert.Equal(t, []string{"req-api", "req-web"}, search("example.com"), "search should list every match newest first")
	assert.Empty(t, search("nothing-matches"))
}

func TestSqlRepository_DeleteOlderThan_DeletesInBatches(t *testing.T) {
	cases := map[string]struct{ old, recent int }{
		"partial last batch":      {old: 5, recent: 2},
		"exact multiple of batch": {old: 4, recent: 1},
		"nothing to delete":       {old: 0, recent: 3},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			repo, _ := newTestRepository(t)
			assertBatchedDelete(t, repo, tc.old, tc.recent)
		})
	}
}

func TestSqlRepository_DeleteOlderThan_DeletesInBatchesOnPostgres(t *testing.T) {
	if os.Getenv("NETBIRD_STORE_ENGINE") != string(db.PostgresStoreEngine) {
		t.Skip("requires NETBIRD_STORE_ENGINE=postgres")
	}
	cleanup, dsn, err := testutil.CreatePostgresTestContainer()
	require.NoError(t, err)
	t.Cleanup(cleanup)
	conn, err := db.OpenPostgres(context.Background(), dsn, db.DefaultPoolConfig)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	require.NoError(t, conn.AutoMigrate(&accesslogs.AccessLogEntry{}))
	require.NoError(t, conn.DB(nil).Exec("DELETE FROM access_log_entries").Error)

	assertBatchedDelete(t, NewRepository(conn), 5, 2)
}

func TestSqlRepository_DeleteOlderThan_StopsWhenContextDone(t *testing.T) {
	repo, _ := newTestRepository(t)
	require.NoError(t, repo.Create(context.Background(), newEntry("old", "acc", "GET", 48*time.Hour)))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	deleted, err := repo.DeleteOlderThan(ctx, time.Now().Add(-24*time.Hour))

	require.ErrorIs(t, err, context.Canceled)
	assert.Zero(t, deleted)
	assert.EqualValues(t, 1, countEntries(t, repo), "nothing should be deleted once the context is done")
}

func assertBatchedDelete(t *testing.T, repo accesslogs.Repository, old, recent int) {
	t.Helper()
	repo.(*sqlRepository).deleteBatchSize = 2
	ctx := context.Background()
	for i := 0; i < old; i++ {
		require.NoError(t, repo.Create(ctx, newEntry(fmt.Sprintf("old-%d", i), "acc", "GET", 48*time.Hour)))
	}
	for i := 0; i < recent; i++ {
		require.NoError(t, repo.Create(ctx, newEntry(fmt.Sprintf("new-%d", i), "acc", "GET", time.Hour)))
	}

	deleted, err := repo.DeleteOlderThan(ctx, time.Now().Add(-24*time.Hour))
	require.NoError(t, err)
	assert.EqualValues(t, old, deleted, "every old entry should be deleted across batches")
	assert.EqualValues(t, recent, countEntries(t, repo), "recent entries should be kept")
}

func countEntries(t *testing.T, repo accesslogs.Repository) int64 {
	t.Helper()
	_, total, err := repo.ListByAccount(context.Background(), db.LockingStrengthNone, "acc", accesslogs.AccessLogFilter{Page: 1, PageSize: 10})
	require.NoError(t, err)
	return total
}
