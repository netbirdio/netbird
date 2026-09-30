// Package sqlc binds the generated queries to the shared database connection
// and makes one set of generated code serve Postgres and SQLite.
package sqlc

//go:generate go run github.com/sqlc-dev/sqlc/cmd/sqlc@v1.31.1 generate

import (
	"context"
	"database/sql"
	"regexp"

	"gorm.io/gorm"

	"github.com/netbirdio/netbird/management/internals/shared/db"
	"github.com/netbirdio/netbird/management/internals/shared/db/sqlc/gen"
)

// New returns the generated queries on the handle gormDB uses, which is the
// pool outside a transaction and the transaction inside one, so a repository
// shares db.Conn and RunInTx with the rest of the store.
func New(gormDB *gorm.DB, engine db.Engine) gen.Querier {
	pool := gormDB.Statement.ConnPool
	if engine == db.SqliteStoreEngine {
		return gen.New(sqliteConnPool{inner: pool})
	}
	return gen.New(pool)
}

var (
	placeholder = regexp.MustCompile(`\$(\d+)`)
	lockClause  = regexp.MustCompile(`(?is)\s+FOR (NO KEY UPDATE|UPDATE|KEY SHARE|SHARE)\s*;?\s*$`)
)

// sqliteConnPool adapts queries written for Postgres to SQLite: numbered
// placeholders become SQLite's `?N` form, and a trailing row lock clause is
// dropped because SQLite serialises writers on the whole database anyway.
type sqliteConnPool struct {
	inner gorm.ConnPool
}

func (p sqliteConnPool) rewrite(query string) string {
	query = lockClause.ReplaceAllString(query, "")
	return placeholder.ReplaceAllString(query, "?$1")
}

func (p sqliteConnPool) ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	return p.inner.ExecContext(ctx, p.rewrite(query), args...)
}

func (p sqliteConnPool) PrepareContext(ctx context.Context, query string) (*sql.Stmt, error) {
	return p.inner.PrepareContext(ctx, p.rewrite(query))
}

func (p sqliteConnPool) QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	return p.inner.QueryContext(ctx, p.rewrite(query), args...)
}

func (p sqliteConnPool) QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row {
	return p.inner.QueryRowContext(ctx, p.rewrite(query), args...)
}
