//go:build cgo

package dex

import (
	sql "github.com/dexidp/dex/storage/sql"
)

// newSQLite3 builds the dex SQLite3 config. CGO builds use the upstream
// struct that takes a File path. Non-CGO builds get an empty stub whose
// Open() returns the dex "SQLite not available" error — correct behaviour
// for binaries that can't link sqlite3 (e.g. cross-compiled ARM targets).
func newSQLite3(file string) *sql.SQLite3 {
	return &sql.SQLite3{File: file}
}
