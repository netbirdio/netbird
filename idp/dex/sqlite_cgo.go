//go:build cgo

package dex

import (
	sql "github.com/dexidp/dex/storage/sql"
)

// newSQLite3 builds the dex SQLite3 config. CGO builds use the upstream
// struct that takes a File path. Non-CGO builds (see sqlite_nocgo.go) build
// the empty stub — `Open()` then returns the dex "SQLite not available"
// error, which is correct behaviour for binaries that can't link sqlite3.
//
// Wrapping the construction this way keeps the call sites in config.go /
// provider.go compilable under both build modes — the upstream stub for
// !cgo has no File field, so a bare `sql.SQLite3{File: file}` literal fails
// the cross-compile for targets like linux/arm/v6 in the release pipeline.
func newSQLite3(file string) *sql.SQLite3 {
	return &sql.SQLite3{File: file}
}
