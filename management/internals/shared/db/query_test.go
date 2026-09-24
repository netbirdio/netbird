package db

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

func seedRows(t *testing.T, table *Table[testRow], names ...string) {
	t.Helper()
	for _, name := range names {
		require.NoError(t, table.Create(context.Background(), nil, &testRow{Name: name}))
	}
}

func names(rows []*testRow) []string {
	out := make([]string, 0, len(rows))
	for _, row := range rows {
		out = append(out, row.Name)
	}
	return out
}

func TestTable_FindAppliesConditionsOrderAndPaging(t *testing.T) {
	conn := openTestConn(t)
	table := NewTable[testRow](conn)
	seedRows(t, table, "a", "b", "c", "d")
	ctx := context.Background()

	rows, err := table.Find(ctx, nil, nil)
	require.NoError(t, err)
	assert.Len(t, rows, 4)

	rows, err = table.Find(ctx, nil, NewQuery().Where("name <> ?", "a").Order("name DESC").Limit(2).Offset(1))
	require.NoError(t, err)
	assert.Equal(t, []string{"c", "b"}, names(rows))
}

func TestTable_CountIgnoresPaging(t *testing.T) {
	conn := openTestConn(t)
	table := NewTable[testRow](conn)
	seedRows(t, table, "a", "b", "c")

	count, err := table.Count(context.Background(), nil, NewQuery().Where("name IN ?", []string{"a", "b"}).Limit(1))
	require.NoError(t, err)
	assert.EqualValues(t, 2, count)
}

func TestTable_DeleteReturnsAffectedRows(t *testing.T) {
	conn := openTestConn(t)
	table := NewTable[testRow](conn)
	seedRows(t, table, "a", "b", "c")
	ctx := context.Background()

	deleted, err := table.Delete(ctx, nil, NewQuery().Where("name = ?", "b"))
	require.NoError(t, err)
	assert.EqualValues(t, 1, deleted)

	_, err = table.Delete(ctx, nil, NewQuery())
	require.ErrorIs(t, err, gorm.ErrMissingWhereClause)
	assert.EqualValues(t, 2, countRows(t, conn))
}

func TestTable_WritesThroughTransaction(t *testing.T) {
	conn := openTestConn(t)
	table := NewTable[testRow](conn)

	err := conn.RunInTx(context.Background(), func(tx *Tx) error {
		require.NoError(t, table.Create(context.Background(), tx, &testRow{Name: "a"}))
		rows, err := table.Find(context.Background(), tx, nil)
		require.NoError(t, err)
		assert.Len(t, rows, 1)
		return assert.AnError
	})
	require.ErrorIs(t, err, assert.AnError)
	assert.EqualValues(t, 0, countRows(t, conn))
}

func TestQuery_LockAddsRowLockClause(t *testing.T) {
	conn := openTestConn(t)

	statement := NewQuery().applyRead(conn.DB(nil)).Statement
	_, locked := statement.Clauses["FOR"]
	assert.False(t, locked)

	statement = NewQuery().Lock(LockingStrengthUpdate).applyRead(conn.DB(nil)).Statement
	assert.Equal(t, clause.Locking{Strength: "UPDATE"}, statement.Clauses["FOR"].Expression)
}
