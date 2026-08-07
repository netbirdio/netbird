package networkmap_sqlite

import (
	"context"
	"net/url"
	"path/filepath"
	"runtime"
	"strings"

	"database/sql"
)

type SqliteStore struct {
	Db *sql.DB
}

func NewSqliteStore(ctx context.Context, storeFile, dataDir, dsn string) (*SqliteStore, error) {
	// storeFile := storeSqliteFileName
	// if envFile, ok := os.LookupEnv("NB_STORE_ENGINE_SQLITE_FILE"); ok && envFile != "" {
	// 	storeFile = envFile
	// }

	// Separate file path from any SQLite URI query parameters (e.g., "store.db?mode=rwc")
	filePath, query, hasQuery := strings.Cut(storeFile, "?")

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

	db, err := sql.Open("sqlite3", "")
	if err != nil {
		return nil, err
	}
	return &SqliteStore{Db: db}, nil
}
