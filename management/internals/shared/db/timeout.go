package db

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/netbirdio/netbird/util"
)

const (
	transactionTimeoutEnv = "NB_STORE_TRANSACTION_TIMEOUT"
	// statementTimeoutEnv bounds every Postgres statement; zero keeps the server setting.
	statementTimeoutEnv     = "NB_STORE_STATEMENT_TIMEOUT"
	defaultStatementTimeout = time.Minute
)

// sessionTimeouts sets the configured timeouts on each new Postgres session with
// SET, since poolers such as PgBouncer reject them as startup parameters.
func sessionTimeouts() func(context.Context, *pgx.Conn) error {
	var settings []string
	if d := util.DurationFromEnv(statementTimeoutEnv, defaultStatementTimeout); d > 0 {
		settings = append(settings, "SET statement_timeout = "+postgresMillis(d))
	}
	if d := util.DurationFromEnv(transactionTimeoutEnv, defaultTransactionTimeout); d > 0 {
		settings = append(settings, "SET idle_in_transaction_session_timeout = "+postgresMillis(d))
	}
	query := strings.Join(settings, "; ")

	return func(ctx context.Context, conn *pgx.Conn) error {
		if query == "" {
			return nil
		}
		if _, err := conn.Exec(ctx, query); err != nil {
			return fmt.Errorf("set session timeouts: %w", err)
		}
		return nil
	}
}

// postgresMillis rounds up to 1ms, since a zero timeout disables it.
func postgresMillis(d time.Duration) string {
	return strconv.FormatInt(max(d.Milliseconds(), 1), 10)
}
