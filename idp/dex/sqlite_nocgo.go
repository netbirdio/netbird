//go:build !cgo

package dex

import (
	sql "github.com/dexidp/dex/storage/sql"
)

// newSQLite3 for non-CGO builds. The dex SQLite3 stub has no fields and its
// Open() returns an error documenting the missing CGO support — correct
// behaviour for cross-compiled artefacts that never actually run the
// embedded IdP. The `file` argument is ignored.
func newSQLite3(_ string) *sql.SQLite3 {
	return &sql.SQLite3{}
}
