package networkmap_sqlite

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"

	"database/sql"

	networkmapdb "github.com/netbirdio/netbird/management/internals/network_map_db"
)

var ErrNoRows = errors.New("no rows in result set")

type SqliteStore struct {
	Db *sql.DB
}

type sqliteInterface interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

type SqliteStoreConn struct {
	Conn sqliteInterface
}

func NewSqliteStore(storeFile, dataDir string) (*SqliteStore, error) {
	dbfile := storeFile
	if envFile, ok := os.LookupEnv("NB_STORE_ENGINE_SQLITE_FILE"); ok && envFile != "" {
		dbfile = envFile
	}

	// Separate file path from any SQLite URI query parameters (e.g., "store.db?mode=rwc")
	filePath, query, hasQuery := strings.Cut(dbfile, "?")

	connStr := filePath
	if filePath != ":memory:" && !filepath.IsAbs(filePath) {
		connStr = filepath.Join(dataDir, filePath)
	}

	// Compose query parameters. User-provided ?_busy_timeout (or its mattn alias
	// ?_timeout) overrides our default; otherwise inject 30s so SQLite waits at
	// most that long on a lock instead of blocking the only Go-side connection.
	// mattn/go-sqlite3 applies PRAGMA from the DSN on every fresh connection, so
	// the value survives ConnMaxIdleTime/ConnMaxLifetime recycling. cache=shared
	// stays the default on non-Windows for the same reason as before.
	parsed, _ := url.ParseQuery(query)
	var defaults []string
	if parsed.Get("_busy_timeout") == "" && parsed.Get("_timeout") == "" {
		defaults = append(defaults, "_busy_timeout=30000")
	}
	if !hasQuery && runtime.GOOS != "windows" {
		// To avoid `The process cannot access the file because it is being used by another process` on Windows
		defaults = append(defaults, "cache=shared")
	}
	parts := defaults
	if hasQuery {
		parts = append(parts, query)
	}
	if len(parts) > 0 {
		connStr += "?" + strings.Join(parts, "&")
	}

	db, err := sql.Open("sqlite3", connStr)
	if err != nil {
		return nil, err
	}

	return &SqliteStore{Db: db}, nil
}

func (s *SqliteStore) BeginTx(ctx context.Context) (networkmapdb.NetworkMapDBStoreConn, error) {
	tx, err := s.Db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return nil, err
	}
	return &SqliteStoreConn{Conn: tx}, nil
}

func (s *SqliteStore) Exec(_ context.Context, query string, args ...any) error {
	_, err := s.Db.Exec(query, args...)
	return err
}

func (sc *SqliteStoreConn) RollbackTx(ctx context.Context) error {
	tx, ok := sc.Conn.(*sql.Tx)
	if !ok {
		return fmt.Errorf("expected an sql.Tx got %s", reflect.TypeOf(sc.Conn).Kind())
	}
	return tx.Rollback()
}

func (sc *SqliteStoreConn) CommitTx(ctx context.Context) error {
	tx, ok := sc.Conn.(*sql.Tx)
	if !ok {
		return fmt.Errorf("expected an sql.Tx got %s", reflect.TypeOf(sc.Conn).Kind())
	}
	return tx.Commit()
}

func (s *SqliteStore) UsingConn() *SqliteStoreConn {
	return &SqliteStoreConn{Conn: s.Db}
}

func CollectOneRowForSqlite[T any](rows *sql.Rows) (T, error) {
	defer rows.Close()
	var r T

	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return r, err
		}
		return r, ErrNoRows
	}
	err := rows.Scan(networkmapdb.StructFields(&r)...)
	if err != nil {
		return r, err
	}

	return r, nil
}

func CollectRowsForSqlite[T any](rows *sql.Rows) ([]T, error) {
	defer rows.Close()
	toret := make([]T, 0)

	for rows.Next() {
		var r T
		err := rows.Scan(networkmapdb.StructFields(&r)...)
		if err != nil {
			return nil, err
		}
		toret = append(toret, r)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return toret, nil
}
