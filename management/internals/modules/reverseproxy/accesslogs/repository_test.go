package accesslogs

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/internals/shared/db"
)

func newTestRepository(t *testing.T) (Repository, *db.Conn) {
	t.Helper()
	conn, err := db.OpenSqlite(context.Background(), t.TempDir())
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	require.NoError(t, conn.AutoMigrate(&AccessLogEntry{}))
	return NewRepository(conn), conn
}

func newEntry(id, accountID, method string, age time.Duration) *AccessLogEntry {
	return &AccessLogEntry{
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
	for _, entry := range []*AccessLogEntry{
		newEntry("a1", "acc-a", "GET", 3*time.Hour),
		newEntry("a2", "acc-a", "POST", 2*time.Hour),
		newEntry("a3", "acc-a", "GET", time.Hour),
		newEntry("b1", "acc-b", "GET", time.Hour),
	} {
		require.NoError(t, repo.Create(ctx, nil, entry))
	}

	logs, total, err := repo.ListByAccount(ctx, nil, db.LockingStrengthNone, "acc-a", AccessLogFilter{Page: 1, PageSize: 2})
	require.NoError(t, err)
	assert.EqualValues(t, 3, total)
	require.Len(t, logs, 2)
	assert.Equal(t, "a3", logs[0].ID)
	assert.Equal(t, "a2", logs[1].ID)

	method := "GET"
	logs, total, err = repo.ListByAccount(ctx, nil, db.LockingStrengthNone, "acc-a", AccessLogFilter{Page: 1, PageSize: 10, Method: &method, SortOrder: "asc"})
	require.NoError(t, err)
	assert.EqualValues(t, 2, total)
	require.Len(t, logs, 2)
	assert.Equal(t, "a1", logs[0].ID)
	assert.Equal(t, "a3", logs[1].ID)
}

func TestSqlRepository_DeleteOlderThan(t *testing.T) {
	repo, _ := newTestRepository(t)
	ctx := context.Background()
	require.NoError(t, repo.Create(ctx, nil, newEntry("old", "acc", "GET", 48*time.Hour)))
	require.NoError(t, repo.Create(ctx, nil, newEntry("new", "acc", "GET", time.Hour)))

	deleted, err := repo.DeleteOlderThan(ctx, nil, time.Now().Add(-24*time.Hour))
	require.NoError(t, err)
	assert.EqualValues(t, 1, deleted)

	logs, total, err := repo.ListByAccount(ctx, nil, db.LockingStrengthNone, "acc", AccessLogFilter{Page: 1, PageSize: 10})
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
		require.NoError(t, repo.Create(ctx, tx, newEntry("tx", "acc", "GET", 0)))
		return failure
	})
	require.ErrorIs(t, err, failure)

	_, total, err := repo.ListByAccount(ctx, nil, db.LockingStrengthNone, "acc", AccessLogFilter{Page: 1, PageSize: 10})
	require.NoError(t, err)
	assert.Zero(t, total)
}
