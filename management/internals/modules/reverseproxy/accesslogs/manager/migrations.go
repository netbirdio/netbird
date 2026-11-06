package manager

import (
	"context"
	"embed"

	"gorm.io/gorm"

	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy/accesslogs"
	"github.com/netbirdio/netbird/management/internals/shared/db"
	"github.com/netbirdio/netbird/management/internals/shared/db/migrate"
)

//go:embed migrations
var migrationFiles embed.FS

const (
	// MigrationTable records the applied versions of the access log store.
	MigrationTable = "access_log_schema_migrations"
	// baselineVersion creates the schema the legacy path produced when versioning started.
	baselineVersion int64 = 20260930120000
)

// MigrationSet returns the versioned migrations of the access log store.
func MigrationSet() migrate.Set {
	return migrate.Set{
		Name:         "accesslogs",
		Table:        MigrationTable,
		Files:        migrate.Dir(migrationFiles, "migrations"),
		Baseline:     baselineVersion,
		LegacyTables: []string{"access_log_entries"},
		Legacy: func(_ context.Context, gormDB *gorm.DB) error {
			return gormDB.AutoMigrate(&accesslogs.AccessLogEntry{})
		},
	}
}

// NewMigrationRunner opens the configured access log database and returns the
// runner of the access log set together with the function that closes the connection.
func NewMigrationRunner(ctx context.Context, dataDir string, mainEngine db.Engine) (*migrate.Runner, func() error, error) {
	conn, err := openConn(ctx, dataDir, engineFor(mainEngine))
	if err != nil {
		return nil, nil, err
	}
	runner, err := migrate.New(conn.DB(nil), conn.Engine(), MigrationSet())
	if err != nil {
		_ = conn.Close()
		return nil, nil, err
	}
	return runner, conn.Close, nil
}
