//go:build !cgo

package dex

import (
	sql "github.com/dexidp/dex/storage/sql"
)

// newSQLite3 for non-CGO builds. The dex SQLite3 stub has no fields and its
// Open() returns an error documenting the missing CGO support, which is the
// right behaviour for the cross-compiled artefacts (linux/arm, wasm, etc.)
// — those targets never actually run the embedded IdP.
//
// The `file` argument is ignored intentionally; keeping the signature
// matched with sqlite_cgo.go lets the call sites stay identical.
func newSQLite3(_ string) *sql.SQLite3 {
	return &sql.SQLite3{}
}
