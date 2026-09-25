package db

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type testRow struct {
	ID   uint `gorm:"primaryKey"`
	Name string
}

func openTestConn(t *testing.T) *Conn {
	t.Helper()
	conn, err := OpenSqliteFile(context.Background(), t.TempDir(), SqliteFileName)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, conn.Close()) })
	require.NoError(t, conn.AutoMigrate(&testRow{}))
	return conn
}

func countRows(t *testing.T, conn *Conn) int64 {
	t.Helper()
	var count int64
	require.NoError(t, conn.DB(nil).Model(&testRow{}).Count(&count).Error)
	return count
}

func TestNewConn_ReadsTransactionTimeoutFromEnv(t *testing.T) {
	t.Setenv("NB_STORE_TRANSACTION_TIMEOUT", "1s")
	conn := openTestConn(t)
	assert.Equal(t, time.Second, conn.txTimeout)
	assert.Equal(t, SqliteStoreEngine, conn.Engine())
}

func TestRunInTx_CommitsOnSuccess(t *testing.T) {
	conn := openTestConn(t)

	err := conn.RunInTx(context.Background(), func(tx *Tx) error {
		return conn.DB(tx).Create(&testRow{Name: "a"}).Error
	})
	require.NoError(t, err)
	assert.EqualValues(t, 1, countRows(t, conn))
}

func TestRunInTx_RollsBackOnError(t *testing.T) {
	conn := openTestConn(t)
	failure := errors.New("boom")

	err := conn.RunInTx(context.Background(), func(tx *Tx) error {
		require.NoError(t, conn.DB(tx).Create(&testRow{Name: "a"}).Error)
		return failure
	})
	require.ErrorIs(t, err, failure)
	assert.EqualValues(t, 0, countRows(t, conn))
}

func TestRunInTx_RollsBackOnPanic(t *testing.T) {
	conn := openTestConn(t)

	require.Panics(t, func() {
		_ = conn.RunInTx(context.Background(), func(tx *Tx) error {
			require.NoError(t, conn.DB(tx).Create(&testRow{Name: "a"}).Error)
			panic("boom")
		})
	})
	assert.EqualValues(t, 0, countRows(t, conn))
}

func TestRunInTx_FailsWhenTimeoutExceeded(t *testing.T) {
	t.Setenv("NB_STORE_TRANSACTION_TIMEOUT", "50ms")
	conn := openTestConn(t)

	err := conn.RunInTx(context.Background(), func(tx *Tx) error {
		time.Sleep(100 * time.Millisecond)
		return conn.DB(tx).Create(&testRow{Name: "a"}).Error
	})
	require.ErrorIs(t, err, context.DeadlineExceeded)
	assert.EqualValues(t, 0, countRows(t, conn))
}

func TestRunInTx_ReportsDurationToMetrics(t *testing.T) {
	conn := openTestConn(t)
	metrics := &recordingMetrics{}
	conn.SetTxMetrics(metrics)

	require.NoError(t, conn.RunInTx(context.Background(), func(*Tx) error { return nil }))
	assert.Equal(t, 1, metrics.calls)
}

func TestConn_DBSelectsTransactionHandle(t *testing.T) {
	conn := openTestConn(t)
	assert.Same(t, conn.db, conn.DB(nil))

	err := conn.RunInTx(context.Background(), func(tx *Tx) error {
		assert.Same(t, tx.db, conn.DB(tx))
		assert.NotSame(t, conn.db, conn.DB(tx))
		return nil
	})
	require.NoError(t, err)
}

func TestConn_PoolIsUnavailableInsideTransaction(t *testing.T) {
	conn := openTestConn(t)
	conn.pool = &pgxpool.Pool{}
	defer func() { conn.pool = nil }()

	assert.Same(t, conn.pool, conn.Pool(nil))
	err := conn.RunInTx(context.Background(), func(tx *Tx) error {
		assert.Nil(t, conn.Pool(tx))
		return nil
	})
	require.NoError(t, err)
}

func TestTransaction_NestedCallBecomesSavepoint(t *testing.T) {
	conn := openTestConn(t)
	failure := errors.New("inner")

	err := conn.RunInTx(context.Background(), func(tx *Tx) error {
		if err := conn.DB(tx).Create(&testRow{Name: "outer"}).Error; err != nil {
			return err
		}
		err := conn.Transaction(conn.DB(tx), func(inner *gorm.DB) error {
			require.NoError(t, inner.Create(&testRow{Name: "inner"}).Error)
			return failure
		})
		require.ErrorIs(t, err, failure)
		return nil
	})
	require.NoError(t, err)

	var names []string
	require.NoError(t, conn.DB(nil).Model(&testRow{}).Pluck("name", &names).Error)
	assert.Equal(t, []string{"outer"}, names)
}

type recordingMetrics struct {
	calls int
}

func (m *recordingMetrics) CountTransactionDuration(time.Duration) {
	m.calls++
}

func TestNewConn_MaxOpenConnsFromEnv(t *testing.T) {
	t.Setenv("NB_SQL_MAX_OPEN_CONNS", "7")

	gormDB, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "store.db")), GormConfig())
	require.NoError(t, err)
	conn, err := NewConn(context.Background(), gormDB, PostgresStoreEngine, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	sqlDB, err := conn.DB(nil).DB()
	require.NoError(t, err)
	assert.Equal(t, 7, sqlDB.Stats().MaxOpenConnections)

	sqliteDB, err := openTestConn(t).DB(nil).DB()
	require.NoError(t, err)
	assert.Equal(t, 1, sqliteDB.Stats().MaxOpenConnections)
}
