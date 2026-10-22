package manager

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy/accesslogs"
	"github.com/netbirdio/netbird/management/internals/shared/db"
	"github.com/netbirdio/netbird/management/internals/shared/db/dbtest"
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
	api := newEntry("api", "acc", "GET", time.Hour)
	api.Host = "api.example.com"
	api.Path = "/v1/peers"
	web := newEntry("web", "acc", "GET", 2*time.Hour)
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

	assert.Equal(t, []string{"api"}, search("api.example"), "search should match the host")
	assert.Equal(t, []string{"web"}, search("/login"), "search should match the path")
	assert.Equal(t, []string{"api"}, search("example.com/v1"), "search should match host and path joined")
	assert.Equal(t, []string{"web"}, search("we"), "search should match the log ID")
	assert.Equal(t, []string{"api", "web"}, search("example.com"), "search should list every match newest first")
	assert.Empty(t, search("nothing-matches"))
}
