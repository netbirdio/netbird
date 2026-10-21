package migrate

import (
	"context"
	"fmt"
	"io/fs"

	"github.com/pressly/goose/v3"
	"gorm.io/gorm"
)

const (
	// PostgresDir is the directory inside Set.Files holding the Postgres SQL migrations.
	PostgresDir = "postgres"
	// SqliteDir is the directory inside Set.Files holding the SQLite SQL migrations.
	SqliteDir = "sqlite"
)

// Set is the versioned migration set of one database: its SQL files per
// engine, its Go migrations and the bootstrap for databases created before
// versioning existed.
type Set struct {
	// Name identifies the set in logs and CLI output.
	Name string
	// Table is the version table the applied versions are recorded in.
	Table string
	// Files holds the PostgresDir and SqliteDir directories with goose SQL migrations.
	Files fs.FS
	// Go lists the Go migrations, applied in version order together with the SQL files.
	Go []*goose.Migration
	// Baseline is the version stamped as applied once Legacy has brought a
	// pre-versioned database to the baseline schema.
	Baseline int64
	// LegacyTables mark a pre-versioned database: when any of them exists
	// without the version table, Legacy runs before the versioned migrations.
	LegacyTables []string
	// Legacy brings a pre-versioned database to the Baseline schema. Nil
	// disables the bootstrap, and such a database then fails the baseline migration.
	Legacy func(ctx context.Context, gormDB *gorm.DB) error
}

// Dir returns the directory dir of an embedded file system, panicking when it
// is missing: a set's migrations are compiled in, so their absence is a build defect.
func Dir(files fs.FS, dir string) fs.FS {
	sub, err := fs.Sub(files, dir)
	if err != nil {
		panic(fmt.Sprintf("migrations directory %s: %v", dir, err))
	}
	return sub
}
