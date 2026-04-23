//go:build cgo
// +build cgo

package dex

import (
	"log/slog"

	"github.com/dexidp/dex/storage"
	"github.com/dexidp/dex/storage/sql"
)

// openSQLite opens the Dex sqlite3 storage. Only compiled when CGO is enabled,
// because github.com/dexidp/dex/storage/sql.SQLite3 is only populated under
// the cgo build tag upstream.
func openSQLite(file string, logger *slog.Logger) (storage.Storage, error) {
	return (&sql.SQLite3{File: file}).Open(logger)
}
