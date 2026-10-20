package migrate

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/pressly/goose/v3"
	"github.com/pressly/goose/v3/database"
	log "github.com/sirupsen/logrus"
	"gorm.io/gorm"

	"github.com/netbirdio/netbird/management/internals/shared/db"
)

const (
	// lockNotAvailable is the SQLSTATE Postgres raises when lock_timeout expires.
	lockNotAvailable = "55P03"
	lockRetries      = 5
	lockRetryDelay   = 2 * time.Second
	lockPollInterval = time.Second
	lockWaitLogEvery = 10
	unlockTimeout    = 10 * time.Second
	backupInfix      = ".bak."
)

// Runner applies one Set to one database.
type Runner struct {
	gormDB   *gorm.DB
	sqlDB    *sql.DB
	engine   db.Engine
	set      Set
	dialect  goose.Dialect
	files    fs.FS
	provider *goose.Provider
}

// PendingMigration is a migration of the set the database has not applied yet.
type PendingMigration struct {
	Version int64
	Path    string
	Type    goose.MigrationType
	// SQL is the file content of a SQL migration and empty for a Go migration.
	SQL string
}

// New prepares set for the database behind gormDB. Only Postgres and SQLite are supported.
func New(gormDB *gorm.DB, engine db.Engine, set Set) (*Runner, error) {
	var dialect goose.Dialect
	var dir string
	switch engine {
	case db.PostgresStoreEngine:
		dialect, dir = goose.DialectPostgres, PostgresDir
	case db.SqliteStoreEngine:
		dialect, dir = goose.DialectSQLite3, SqliteDir
	default:
		return nil, fmt.Errorf("%s migrations: engine %s is not supported", set.Name, engine)
	}

	files, err := fs.Sub(set.Files, dir)
	if err != nil {
		return nil, fmt.Errorf("%s migrations for %s: %w", set.Name, engine, err)
	}
	sqlDB, err := gormDB.DB()
	if err != nil {
		return nil, fmt.Errorf("%s migrations: database handle: %w", set.Name, err)
	}
	provider, err := goose.NewProvider(dialect, sqlDB, files,
		goose.WithTableName(set.Table),
		goose.WithAllowOutofOrder(true),
		goose.WithDisableGlobalRegistry(true),
		goose.WithGoMigrations(set.Go...),
	)
	if err != nil {
		return nil, fmt.Errorf("%s migrations for %s: %w", set.Name, engine, err)
	}

	return &Runner{
		gormDB:   gormDB,
		sqlDB:    sqlDB,
		engine:   engine,
		set:      set,
		dialect:  dialect,
		files:    files,
		provider: provider,
	}, nil
}

// Run brings the database to the state mode asks for.
func (r *Runner) Run(ctx context.Context, mode Mode) error {
	switch mode {
	case ModeSkip:
		log.WithContext(ctx).Infof("%s migrations: skipped", r.set.Name)
		return nil
	case ModeCheck:
		return r.check(ctx)
	case ModeAuto:
		return r.apply(ctx)
	default:
		return fmt.Errorf("%s migrations: unknown mode %q", r.set.Name, mode)
	}
}

// Status lists every migration of the set with its applied state. On a
// database that predates versioning everything is pending, and the version
// table is left for the bootstrap to create.
func (r *Runner) Status(ctx context.Context) ([]*goose.MigrationStatus, error) {
	if r.isLegacy() {
		sources := r.provider.ListSources()
		statuses := make([]*goose.MigrationStatus, 0, len(sources))
		for _, source := range sources {
			statuses = append(statuses, &goose.MigrationStatus{Source: source, State: goose.StatePending})
		}
		return statuses, nil
	}
	statuses, err := r.provider.Status(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s migrations: status: %w", r.set.Name, err)
	}
	return statuses, nil
}

// Pending lists the migrations the database has not applied, in version order.
func (r *Runner) Pending(ctx context.Context) ([]PendingMigration, error) {
	statuses, err := r.Status(ctx)
	if err != nil {
		return nil, err
	}

	var pending []PendingMigration
	for _, status := range statuses {
		if status.State != goose.StatePending {
			continue
		}
		migration := PendingMigration{
			Version: status.Source.Version,
			Path:    status.Source.Path,
			Type:    status.Source.Type,
		}
		if status.Source.Type == goose.TypeSQL {
			content, err := fs.ReadFile(r.files, status.Source.Path)
			if err != nil {
				return nil, fmt.Errorf("%s migrations: read %s: %w", r.set.Name, status.Source.Path, err)
			}
			migration.SQL = string(content)
		}
		pending = append(pending, migration)
	}
	return pending, nil
}

// Stamp records the baseline and every earlier version as applied without
// running them, creating the version table when it is missing.
func (r *Runner) Stamp(ctx context.Context) error {
	versionStore, err := r.versionStore()
	if err != nil {
		return err
	}
	// The table check needs the pool's only connection on SQLite, so it runs before the transaction takes it.
	createTable := !r.versionTableExists()

	conn, err := r.sqlDB.Conn(ctx)
	if err != nil {
		return fmt.Errorf("%s migrations: connection: %w", r.set.Name, err)
	}
	defer conn.Close()

	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("%s migrations: begin stamp: %w", r.set.Name, err)
	}
	defer tx.Rollback() //nolint:errcheck

	if createTable {
		if err := versionStore.CreateVersionTable(ctx, tx); err != nil {
			return fmt.Errorf("%s migrations: create version table: %w", r.set.Name, err)
		}
		if err := versionStore.Insert(ctx, tx, database.InsertRequest{Version: 0}); err != nil {
			return fmt.Errorf("%s migrations: record zero version: %w", r.set.Name, err)
		}
	}

	for _, source := range r.provider.ListSources() {
		if source.Version > r.set.Baseline {
			continue
		}
		recorded, err := versionStore.GetMigration(ctx, tx, source.Version)
		if err != nil && !errors.Is(err, database.ErrVersionNotFound) {
			return fmt.Errorf("%s migrations: read version %d: %w", r.set.Name, source.Version, err)
		}
		if recorded != nil {
			continue
		}
		if err := versionStore.Insert(ctx, tx, database.InsertRequest{Version: source.Version}); err != nil {
			return fmt.Errorf("%s migrations: stamp version %d: %w", r.set.Name, source.Version, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("%s migrations: stamp baseline: %w", r.set.Name, err)
	}
	log.WithContext(ctx).Infof("%s migrations: stamped baseline %d", r.set.Name, r.set.Baseline)
	return nil
}

func (r *Runner) check(ctx context.Context) error {
	if !r.versionTableExists() {
		return fmt.Errorf("%s migrations: database has no version table, run `migrate up` first", r.set.Name)
	}

	pending, err := r.Pending(ctx)
	if err != nil {
		return err
	}
	if len(pending) > 0 {
		return fmt.Errorf("%s migrations: %d pending, first is %d, run `migrate up` first", r.set.Name, len(pending), pending[0].Version)
	}
	log.WithContext(ctx).Infof("%s migrations: schema is current", r.set.Name)
	return nil
}

func (r *Runner) apply(ctx context.Context) error {
	unlock, err := r.lock(ctx)
	if err != nil {
		return err
	}
	defer unlock()

	fresh := !r.versionTableExists() && !r.hasLegacyTables()
	backedUp := r.engine != db.SqliteStoreEngine || fresh
	backup := func() error {
		if backedUp {
			return nil
		}
		backedUp = true
		return r.backupSqlite(ctx)
	}

	if err := r.bootstrapLegacy(ctx, backup); err != nil {
		return err
	}

	pending, err := r.Pending(ctx)
	if err != nil {
		return err
	}
	if len(pending) == 0 {
		log.WithContext(ctx).Infof("%s migrations: schema is current", r.set.Name)
		return nil
	}
	if err := backup(); err != nil {
		return err
	}

	log.WithContext(ctx).Infof("%s migrations: applying %d pending", r.set.Name, len(pending))
	results, err := r.up(ctx)
	for _, result := range results {
		log.WithContext(ctx).Infof("%s migrations: applied %s in %s", r.set.Name, describe(result.Source), result.Duration.Round(time.Millisecond))
	}
	return err
}

// bootstrapLegacy runs the set's Legacy path on a database that has tables
// but no version table, then stamps the baseline.
func (r *Runner) bootstrapLegacy(ctx context.Context, backup func() error) error {
	if r.set.Legacy == nil || !r.isLegacy() {
		return nil
	}

	if err := backup(); err != nil {
		return err
	}
	log.WithContext(ctx).Infof("%s migrations: database predates versioned migrations, running the legacy bootstrap", r.set.Name)
	if err := r.set.Legacy(ctx, r.gormDB); err != nil {
		return fmt.Errorf("%s migrations: legacy bootstrap: %w", r.set.Name, err)
	}
	return r.Stamp(ctx)
}

func (r *Runner) hasLegacyTables() bool {
	for _, table := range r.set.LegacyTables {
		if r.gormDB.Migrator().HasTable(table) {
			return true
		}
	}
	return false
}

func (r *Runner) up(ctx context.Context) ([]*goose.MigrationResult, error) {
	var applied []*goose.MigrationResult
	for attempt := 1; ; attempt++ {
		results, err := r.provider.Up(ctx)
		var partial *goose.PartialError
		if errors.As(err, &partial) {
			results = partial.Applied
		}
		applied = append(applied, results...)
		if err == nil {
			return applied, nil
		}
		if !isLockTimeout(err) || attempt == lockRetries {
			return applied, fmt.Errorf("%s migrations: %w", r.set.Name, err)
		}

		log.WithContext(ctx).Warnf("%s migrations: lock timeout, retry %d of %d in %s", r.set.Name, attempt, lockRetries, lockRetryDelay)
		select {
		case <-ctx.Done():
			return applied, ctx.Err()
		case <-time.After(lockRetryDelay):
		}
	}
}

// lock serialises concurrent runners of the same set on Postgres with a
// session advisory lock. goose holds one pooled connection for the whole run,
// so the lock takes a second one. SQLite has a single writer and needs no lock.
func (r *Runner) lock(ctx context.Context) (func(), error) {
	if r.engine != db.PostgresStoreEngine {
		return func() {}, nil
	}

	restore := func() {}
	if r.sqlDB.Stats().MaxOpenConnections == 1 {
		r.sqlDB.SetMaxOpenConns(2)
		restore = func() { r.sqlDB.SetMaxOpenConns(1) }
	}
	conn, err := r.sqlDB.Conn(ctx)
	if err != nil {
		restore()
		return nil, err
	}

	if err := r.acquireLock(ctx, conn); err != nil {
		_ = conn.Close()
		restore()
		return nil, err
	}

	return func() {
		unlockCtx, cancel := context.WithTimeout(context.Background(), unlockTimeout)
		defer cancel()
		if _, err := conn.ExecContext(unlockCtx, "SELECT pg_advisory_unlock(hashtext($1))", r.set.Table); err != nil {
			log.WithContext(ctx).Warnf("%s migrations: release lock: %v, discarding the connection", r.set.Name, err)
			// A session lock survives on a pooled connection, so the connection must not go back to the pool.
			_ = conn.Raw(func(any) error { return driver.ErrBadConn })
		}
		_ = conn.Close()
		restore()
	}, nil
}

// acquireLock polls for the advisory lock so a long wait behind another
// instance stays visible in the log instead of blocking silently.
func (r *Runner) acquireLock(ctx context.Context, conn *sql.Conn) error {
	log.WithContext(ctx).Infof("%s migrations: acquiring lock", r.set.Name)
	for attempt := 1; ; attempt++ {
		var locked bool
		if err := conn.QueryRowContext(ctx, "SELECT pg_try_advisory_lock(hashtext($1))", r.set.Table).Scan(&locked); err != nil {
			return fmt.Errorf("%s migrations: acquire lock: %w", r.set.Name, err)
		}
		if locked {
			return nil
		}
		if attempt%lockWaitLogEvery == 0 {
			log.WithContext(ctx).Infof("%s migrations: still waiting for another instance to finish migrating", r.set.Name)
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("%s migrations: acquire lock: %w", r.set.Name, ctx.Err())
		case <-time.After(lockPollInterval):
		}
	}
}

// backupSqlite copies the database file next to itself before the schema
// changes, keeping only the newest copy.
func (r *Runner) backupSqlite(ctx context.Context) error {
	var file string
	if err := r.gormDB.Raw("SELECT file FROM pragma_database_list WHERE name = 'main'").Scan(&file).Error; err != nil {
		return fmt.Errorf("%s migrations: locate database file: %w", r.set.Name, err)
	}
	if file == "" {
		return nil
	}

	version, err := r.recordedVersion()
	if err != nil {
		return err
	}
	target := fmt.Sprintf("%s%s%d", file, backupInfix, version)
	if err := os.Remove(target); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("%s migrations: replace backup %s: %w", r.set.Name, target, err)
	}
	if err := r.gormDB.Exec("VACUUM INTO " + quoteLiteral(target)).Error; err != nil {
		return fmt.Errorf("%s migrations: back up %s: %w", r.set.Name, file, err)
	}
	log.WithContext(ctx).Infof("%s migrations: wrote backup %s", r.set.Name, target)

	previous, err := filepath.Glob(filepath.Join(filepath.Dir(file), filepath.Base(file)+backupInfix+"*"))
	if err != nil {
		return fmt.Errorf("%s migrations: list backups: %w", r.set.Name, err)
	}
	for _, path := range previous {
		if path == target {
			continue
		}
		if err := os.Remove(path); err != nil {
			return fmt.Errorf("%s migrations: remove old backup %s: %w", r.set.Name, path, err)
		}
	}
	return nil
}

// recordedVersion is the highest applied version, read without goose so that
// a database without a version table is left untouched.
func (r *Runner) recordedVersion() (int64, error) {
	if !r.versionTableExists() {
		return 0, nil
	}
	var version int64
	if err := r.gormDB.Raw(fmt.Sprintf("SELECT COALESCE(MAX(version_id), 0) FROM %s", r.set.Table)).Scan(&version).Error; err != nil {
		return 0, fmt.Errorf("%s migrations: read version: %w", r.set.Name, err)
	}
	return version, nil
}

// isLegacy reports a database created before versioned migrations: tables of
// the set exist, but no version table does.
func (r *Runner) isLegacy() bool {
	return !r.versionTableExists() && r.hasLegacyTables()
}

func (r *Runner) versionTableExists() bool {
	return r.gormDB.Migrator().HasTable(r.set.Table)
}

func (r *Runner) versionStore() (database.Store, error) {
	versionStore, err := database.NewStore(r.dialect, r.set.Table)
	if err != nil {
		return nil, fmt.Errorf("%s migrations: version store: %w", r.set.Name, err)
	}
	return versionStore, nil
}

func describe(source *goose.Source) string {
	if source.Path == "" {
		return fmt.Sprintf("%d (go)", source.Version)
	}
	return fmt.Sprintf("%d %s", source.Version, filepath.Base(source.Path))
}

func isLockTimeout(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == lockNotAvailable
}

func quoteLiteral(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "''") + "'"
}
