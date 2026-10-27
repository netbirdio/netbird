package db

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/netbirdio/netbird/management/server/testutil"
)

// queryCanceledCode is the SQLSTATE Postgres reports when statement_timeout fires.
const queryCanceledCode = "57014"

func TestPostgresMillis(t *testing.T) {
	cases := map[time.Duration]string{
		time.Minute:             "60000",
		1500 * time.Microsecond: "2",
		500 * time.Microsecond:  "1",
		720 * time.Hour:         "2147483647",
	}
	for d, want := range cases {
		assert.Equal(t, want, postgresMillis(d), "milliseconds for %v", d)
	}
}

func TestSessionTimeouts_NothingToApply(t *testing.T) {
	t.Setenv(statementTimeoutEnv, "0")
	t.Setenv(transactionTimeoutEnv, "0")
	ctx := context.Background()

	assert.NoError(t, sessionTimeouts()(ctx, nil), "the hook should not touch the session when both timeouts are disabled")
}

func TestOpenPostgres_BoundsEverySession(t *testing.T) {
	t.Setenv(statementTimeoutEnv, "500ms")
	t.Setenv(transactionTimeoutEnv, "3m")
	conn := openPostgresTestConn(t)
	ctx := context.Background()

	requireStatementTimeout(t, conn.DB(nil).Exec("SELECT pg_sleep(1)").Error)

	_, err := conn.Pool(nil).Exec(ctx, "SELECT pg_sleep(1)")
	requireStatementTimeout(t, err)

	err = conn.RunInTx(ctx, func(tx *Tx) error {
		return conn.DB(tx).Exec("SELECT pg_sleep(1)").Error
	})
	requireStatementTimeout(t, err)

	assert.Equal(t, "3min", showSetting(t, conn.DB(nil), "idle_in_transaction_session_timeout"),
		"the idle transaction timeout should follow the transaction timeout")
}

func TestOpenPostgres_ZeroStatementTimeoutKeepsServerSetting(t *testing.T) {
	t.Setenv(statementTimeoutEnv, "0")
	conn := openPostgresTestConn(t)

	assert.Equal(t, "0", showSetting(t, conn.DB(nil), "statement_timeout"), "the server default should be left in place")
	require.NoError(t, conn.DB(nil).Exec("SELECT pg_sleep(0.6)").Error)
}

func TestOpenPostgres_CapsTimeoutsAtServerMaximum(t *testing.T) {
	t.Setenv(transactionTimeoutEnv, "720h")
	conn := openPostgresTestConn(t)

	assert.Equal(t, "2147483647ms", showSetting(t, conn.DB(nil), "idle_in_transaction_session_timeout"),
		"a timeout above the server maximum should be capped instead of failing the connection")
}

func TestOpenPostgresWithoutPool_BoundsSessions(t *testing.T) {
	t.Setenv(statementTimeoutEnv, "500ms")
	conn, err := OpenPostgresWithoutPool(context.Background(), postgresTestDSN(t))
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	requireStatementTimeout(t, conn.DB(nil).Exec("SELECT pg_sleep(1)").Error)
}

func TestOpenPgxPool_BoundsSessions(t *testing.T) {
	t.Setenv(statementTimeoutEnv, "500ms")
	ctx := context.Background()
	pool, err := OpenPgxPool(ctx, postgresTestDSN(t), DefaultPoolConfig)
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	_, err = pool.Exec(ctx, "SELECT pg_sleep(1)")
	requireStatementTimeout(t, err)
}

func postgresTestDSN(t *testing.T) string {
	t.Helper()
	if os.Getenv("NETBIRD_STORE_ENGINE") != string(PostgresStoreEngine) {
		t.Skip("requires NETBIRD_STORE_ENGINE=postgres")
	}
	cleanup, dsn, err := testutil.CreatePostgresTestContainer()
	require.NoError(t, err)
	t.Cleanup(cleanup)
	return dsn
}

func openPostgresTestConn(t *testing.T) *Conn {
	t.Helper()
	conn, err := OpenPostgres(context.Background(), postgresTestDSN(t), DefaultPoolConfig)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func requireStatementTimeout(t *testing.T, err error) {
	t.Helper()
	var pgErr *pgconn.PgError
	require.True(t, errors.As(err, &pgErr), "expected a Postgres error, got %v", err)
	assert.Equal(t, queryCanceledCode, pgErr.Code, "the statement should be cancelled by statement_timeout")
}

func showSetting(t *testing.T, db *gorm.DB, name string) string {
	t.Helper()
	var value string
	require.NoError(t, db.Raw("SHOW "+name).Scan(&value).Error)
	return value
}
