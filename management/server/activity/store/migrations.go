package store

import (
	"context"
	"embed"
	"fmt"

	"gorm.io/gorm"

	"github.com/netbirdio/netbird/management/internals/shared/db/migrate"
	"github.com/netbirdio/netbird/management/server/activity"
	"github.com/netbirdio/netbird/util/crypt"
)

//go:embed migrations
var migrationFiles embed.FS

const (
	// MigrationTable records the applied versions of the activity store.
	MigrationTable = "activity_schema_migrations"
	// baselineVersion creates the schema the legacy path produced when versioning started.
	baselineVersion int64 = 20260930120000
)

// MigrationSet returns the versioned migrations of the activity store. The
// legacy bootstrap re-encrypts stored names with fieldEncrypt.
func MigrationSet(fieldEncrypt *crypt.FieldEncrypt) migrate.Set {
	files := migrate.Dir(migrationFiles, "migrations")
	return migrate.Set{
		Name:         "activity",
		Table:        MigrationTable,
		Files:        files,
		Baseline:     baselineVersion,
		LegacyTables: []string{"events", "deleted_users"},
		Legacy: func(ctx context.Context, gormDB *gorm.DB) error {
			return legacyMigrate(ctx, fieldEncrypt, gormDB)
		},
	}
}

// NewMigrationRunner opens the configured events database and returns the
// runner of the activity set together with the function that closes the connection.
func NewMigrationRunner(ctx context.Context, dataDir, encryptionKey string) (*migrate.Runner, func() error, error) {
	fieldEncrypt, err := crypt.NewFieldEncrypt(encryptionKey)
	if err != nil {
		return nil, nil, fmt.Errorf("field encryptor: %w", err)
	}
	gormDB, engine, err := initDatabase(ctx, dataDir)
	if err != nil {
		return nil, nil, fmt.Errorf("initialize database: %w", err)
	}
	sqlDB, err := gormDB.DB()
	if err != nil {
		return nil, nil, fmt.Errorf("database handle: %w", err)
	}
	runner, err := migrate.New(gormDB, engine, MigrationSet(fieldEncrypt))
	if err != nil {
		_ = sqlDB.Close()
		return nil, nil, err
	}
	return runner, sqlDB.Close, nil
}

// legacyMigrate is the schema path databases followed before versioned
// migrations: the hand-written migrations followed by gorm's AutoMigrate.
func legacyMigrate(ctx context.Context, fieldEncrypt *crypt.FieldEncrypt, gormDB *gorm.DB) error {
	if err := runLegacyMigrations(ctx, fieldEncrypt, gormDB); err != nil {
		return fmt.Errorf("events database migration: %w", err)
	}
	if err := gormDB.AutoMigrate(&activity.Event{}, &activity.DeletedUser{}); err != nil {
		return fmt.Errorf("events auto migrate: %w", err)
	}
	return nil
}
