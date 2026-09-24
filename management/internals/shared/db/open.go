package db

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

const (
	SqliteFileName = "store.db"
	sqliteInMemory = ":memory:"
)

// PoolConfig sizes the pgx pool a Postgres deployment uses for the read paths
// that bypass gorm.
type PoolConfig struct {
	MaxConns          int32
	MinConns          int32
	MaxConnLifetime   time.Duration
	HealthCheckPeriod time.Duration
}

var DefaultPoolConfig = PoolConfig{
	MaxConns:          30,
	MinConns:          1,
	MaxConnLifetime:   60 * time.Minute,
	HealthCheckPeriod: time.Minute,
}

// GormConfig is the configuration every engine is opened with.
func GormConfig() *gorm.Config {
	return &gorm.Config{
		Logger:          logger.Default.LogMode(logger.Silent),
		CreateBatchSize: 400,
	}
}

// OpenSqlite opens the SQLite database in dataDir, or the file named by
// NB_STORE_ENGINE_SQLITE_FILE.
func OpenSqlite(ctx context.Context, dataDir string) (*Conn, error) {
	storeFile := SqliteFileName
	if envFile, ok := os.LookupEnv("NB_STORE_ENGINE_SQLITE_FILE"); ok && envFile != "" {
		storeFile = envFile
	}

	// Separate file path from any SQLite URI query parameters (e.g., "store.db?mode=rwc")
	filePath, query, hasQuery := strings.Cut(storeFile, "?")

	connStr := filePath
	if filePath != sqliteInMemory && !filepath.IsAbs(filePath) {
		connStr = filepath.Join(dataDir, filePath)
	}

	// Compose query parameters. User-provided ?_busy_timeout (or its mattn alias
	// ?_timeout) overrides our default; otherwise inject 30s so SQLite waits at
	// most that long on a lock instead of blocking the only Go-side connection.
	// mattn/go-sqlite3 applies PRAGMA from the DSN on every fresh connection, so
	// the value survives ConnMaxIdleTime/ConnMaxLifetime recycling. cache=shared
	// stays the default on non-Windows for the same reason as before.
	parsed, _ := url.ParseQuery(query)
	var defaults []string
	if parsed.Get("_busy_timeout") == "" && parsed.Get("_timeout") == "" {
		defaults = append(defaults, "_busy_timeout=30000")
	}
	if !hasQuery && runtime.GOOS != "windows" {
		// To avoid `The process cannot access the file because it is being used by another process` on Windows
		defaults = append(defaults, "cache=shared")
	}
	parts := defaults
	if hasQuery {
		parts = append(parts, query)
	}
	if len(parts) > 0 {
		connStr += "?" + strings.Join(parts, "&")
	}

	gormDB, err := gorm.Open(sqlite.Open(connStr), GormConfig())
	if err != nil {
		return nil, err
	}
	return NewConn(ctx, gormDB, SqliteStoreEngine, nil)
}

// OpenPostgres opens a Postgres database through gorm and a pgx pool sized by pool.
func OpenPostgres(ctx context.Context, dsn string, pool PoolConfig) (*Conn, error) {
	gormDB, err := gorm.Open(postgres.Open(dsn), GormConfig())
	if err != nil {
		return nil, err
	}
	pgxPool, err := newPgxPool(ctx, dsn, pool)
	if err != nil {
		closeGorm(gormDB)
		return nil, err
	}
	return NewConn(ctx, gormDB, PostgresStoreEngine, pgxPool)
}

// MysqlDSN adds the connection parameters every MySQL handle needs, keeping
// the options already present in dsn.
func MysqlDSN(dsn string) string {
	separator := "?"
	if strings.Contains(dsn, "?") {
		separator = "&"
	}
	return dsn + separator + "charset=utf8&parseTime=True&loc=Local"
}

// OpenMysql opens a MySQL database through gorm.
func OpenMysql(ctx context.Context, dsn string) (*Conn, error) {
	gormDB, err := gorm.Open(mysql.Open(MysqlDSN(dsn)), GormConfig())
	if err != nil {
		return nil, err
	}
	return NewConn(ctx, gormDB, MysqlStoreEngine, nil)
}

func newPgxPool(ctx context.Context, dsn string, cfg PoolConfig) (*pgxpool.Pool, error) {
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("unable to parse database config: %w", err)
	}

	config.MaxConns = cfg.MaxConns
	config.MinConns = cfg.MinConns
	config.MaxConnLifetime = cfg.MaxConnLifetime
	config.HealthCheckPeriod = cfg.HealthCheckPeriod

	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("unable to create connection pool: %w", err)
	}

	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("unable to ping database: %w", err)
	}

	return pool, nil
}

func closeGorm(gormDB *gorm.DB) {
	if sqlDB, err := gormDB.DB(); err == nil {
		_ = sqlDB.Close()
	}
}
