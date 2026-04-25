//go:build !cgo
// +build !cgo

package dex

import (
	"fmt"
	"log/slog"

	"github.com/dexidp/dex/storage"
)

// openSQLite is a no-CGO stub. Dex's sqlite3 backend requires CGO; when this
// binary is built with CGO_ENABLED=0 we reject sqlite storage with a clear
// message pointing operators at an alternative (Postgres) or a CGO build.
func openSQLite(_ string, _ *slog.Logger) (storage.Storage, error) {
	return nil, fmt.Errorf(
		"sqlite3 storage is not available: this binary was built with CGO_ENABLED=0; " +
			"rebuild with CGO_ENABLED=1 or switch to a postgres storage backend")
}
