package main

import (
	"context"
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	log "github.com/sirupsen/logrus"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/netbirdio/netbird/idp/dex"
	"github.com/netbirdio/netbird/management/internals/shared/db"
	"github.com/netbirdio/netbird/management/server/activity"
	"github.com/netbirdio/netbird/management/server/store"
)

type config struct {
	mysqlDSN          string
	postgresDSN       string
	eventsPostgresDSN string
	authPostgresDSN   string
	eventsDB          string
	authDB            string
}

type storeMigration struct {
	name       string
	source     *sql.DB
	dialect    dialect
	targetDSN  string
	schema     func(ctx context.Context, dsn string) error
	skipTables map[string]bool
}

func main() {
	cfg, err := parseFlags(os.Args[1:])
	if errors.Is(err, flag.ErrHelp) {
		return
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	// Silence the store constructors' migration logs.
	log.SetLevel(log.WarnLevel)

	if err := run(context.Background(), cfg); err != nil {
		fmt.Fprintf(os.Stderr, "migration failed: %v\n", err)
		os.Exit(1)
	}
}

func parseFlags(args []string) (*config, error) {
	cfg := &config{}
	fs := flag.NewFlagSet("netbird-mysql-migrate", flag.ContinueOnError)
	fs.StringVar(&cfg.mysqlDSN, "mysql-dsn", "", "MySQL DSN of the management store (required)")
	fs.StringVar(&cfg.postgresDSN, "postgres-dsn", "", "Postgres DSN to migrate all stores to (required)")
	fs.StringVar(&cfg.eventsPostgresDSN, "events-postgres-dsn", "", "Postgres DSN for activity events (default --postgres-dsn)")
	fs.StringVar(&cfg.authPostgresDSN, "auth-postgres-dsn", "", "Postgres DSN for the embedded IdP (default --postgres-dsn)")
	fs.StringVar(&cfg.eventsDB, "events-db", "/var/lib/netbird/events.db", "SQLite file of the activity events, skipped when missing")
	fs.StringVar(&cfg.authDB, "auth-db", "/var/lib/netbird/idp.db", "SQLite file of the embedded IdP, skipped when missing")
	if err := fs.Parse(args); err != nil {
		return nil, err
	}

	if cfg.mysqlDSN == "" || cfg.postgresDSN == "" {
		return nil, errors.New("--mysql-dsn and --postgres-dsn are required")
	}
	if cfg.eventsPostgresDSN == "" {
		cfg.eventsPostgresDSN = cfg.postgresDSN
	}
	if cfg.authPostgresDSN == "" {
		cfg.authPostgresDSN = cfg.postgresDSN
	}
	return cfg, nil
}

func run(ctx context.Context, cfg *config) error {
	migrations, closeSources, err := openSources(cfg)
	if err != nil {
		return err
	}
	defer closeSources()

	for _, m := range migrations {
		if err := m.schema(ctx, m.targetDSN); err != nil {
			return fmt.Errorf("create %s schema: %w", m.name, err)
		}
	}

	var (
		pools []*pgxpool.Pool
		txs   []pgx.Tx
	)
	// Roll back first: pool Close waits for the connections open transactions hold.
	defer func() {
		for _, tx := range txs {
			_ = tx.Rollback(ctx)
		}
		for _, pool := range pools {
			pool.Close()
		}
	}()

	results := make([]string, 0, len(migrations))
	for _, m := range migrations {
		pool, err := pgxpool.New(ctx, m.targetDSN)
		if err != nil {
			return fmt.Errorf("connect %s target: %w", m.name, err)
		}
		pools = append(pools, pool)

		tx, err := pool.Begin(ctx)
		if err != nil {
			return fmt.Errorf("begin %s transaction: %w", m.name, err)
		}
		txs = append(txs, tx)

		tables, rows, err := copyStore(ctx, m.source, m.dialect, tx, m.skipTables)
		if err != nil {
			return fmt.Errorf("%s: %w", m.name, err)
		}
		results = append(results, fmt.Sprintf("%s: %d rows from %d tables", m.name, rows, tables))
	}

	// Commit last so a failure in any store leaves every target empty.
	for i, tx := range txs {
		if err := tx.Commit(ctx); err != nil {
			return fmt.Errorf("commit %s: %w", migrations[i].name, err)
		}
	}

	for _, r := range results {
		fmt.Fprintln(os.Stdout, r)
	}
	fmt.Fprintln(os.Stdout, "Done. Point the store, activity and auth store settings at Postgres before starting the server.")
	return nil
}

func openSources(cfg *config) ([]storeMigration, func(), error) {
	var opened []*gorm.DB
	closeAll := func() {
		for _, g := range opened {
			if sqlDB, err := g.DB(); err == nil {
				_ = sqlDB.Close()
			}
		}
	}

	open := func(dialector gorm.Dialector) (*sql.DB, error) {
		g, err := gorm.Open(dialector, &gorm.Config{Logger: logger.Discard})
		if err != nil {
			return nil, err
		}
		opened = append(opened, g)
		return g.DB()
	}

	mysqlDB, err := open(mysql.Open(db.MysqlDSN(cfg.mysqlDSN)))
	if err != nil {
		closeAll()
		return nil, nil, fmt.Errorf("open MySQL: %w", err)
	}
	migrations := []storeMigration{{
		name: "management", source: mysqlDB, dialect: mysqlDialect,
		targetDSN: cfg.postgresDSN, schema: createManagementSchema,
	}}

	sqliteStores := []storeMigration{
		{name: "activity", targetDSN: cfg.eventsPostgresDSN, schema: createActivitySchema},
		{name: "auth", targetDSN: cfg.authPostgresDSN, schema: createAuthSchema, skipTables: map[string]bool{"migrations": true}},
	}
	for i, file := range []string{cfg.eventsDB, cfg.authDB} {
		m := sqliteStores[i]
		if _, err := os.Stat(file); errors.Is(err, os.ErrNotExist) {
			fmt.Fprintf(os.Stdout, "%s: %s not found, skipping\n", m.name, file)
			continue
		}
		m.source, err = open(sqlite.Open("file:" + file + "?mode=ro"))
		if err != nil {
			closeAll()
			return nil, nil, fmt.Errorf("open %s: %w", file, err)
		}
		m.dialect = sqliteDialect
		migrations = append(migrations, m)
	}

	return migrations, closeAll, nil
}

func createManagementSchema(ctx context.Context, dsn string) error {
	s, err := store.NewPostgresqlStore(ctx, dsn, nil, false)
	if err != nil {
		return err
	}
	return s.Close(ctx)
}

func createActivitySchema(_ context.Context, dsn string) error {
	g, err := gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		return err
	}
	defer func() {
		if sqlDB, err := g.DB(); err == nil {
			_ = sqlDB.Close()
		}
	}()
	return g.AutoMigrate(&activity.Event{}, &activity.DeletedUser{})
}

func createAuthSchema(_ context.Context, dsn string) error {
	cfg := dex.Storage{Type: "postgres", Config: map[string]any{"dsn": dsn}}
	s, err := cfg.OpenStorage(slog.New(slog.DiscardHandler))
	if err != nil {
		return err
	}
	return s.Close()
}
