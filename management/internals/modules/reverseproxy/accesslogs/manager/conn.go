package manager

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy/accesslogs"
	"github.com/netbirdio/netbird/management/internals/shared/db"
	"github.com/netbirdio/netbird/management/server/store"
)

const (
	// StoreEngineEnv selects the access log store engine. Unset follows the main store engine.
	StoreEngineEnv = "NB_ACCESS_LOG_STORE_ENGINE"
	// PostgresDSNEnv is the access log Postgres DSN. Unset reuses the main store DSN.
	PostgresDSNEnv = "NB_ACCESS_LOG_POSTGRES_DSN"
	// SqliteFileEnv is the access log SQLite file, resolved against the data directory when relative.
	SqliteFileEnv = "NB_ACCESS_LOG_SQLITE_FILE"
	// MaxOpenConnsEnv sizes the access log connection pool. Unset applies NB_SQL_MAX_OPEN_CONNS.
	MaxOpenConnsEnv = "NB_ACCESS_LOG_SQL_MAX_OPEN_CONNS"

	sqliteFileName = "access_logs.db"
)

// OpenConn opens and migrates the access log database. Unless configured
// otherwise, it follows mainEngine: SQLite uses its own file in dataDir and
// Postgres reuses the main DSN.
func OpenConn(ctx context.Context, dataDir string, mainEngine db.Engine) (*db.Conn, error) {
	engine := mainEngine
	if v := os.Getenv(StoreEngineEnv); v != "" {
		engine = db.Engine(strings.ToLower(v))
	}

	conn, err := openConn(ctx, dataDir, engine)
	if err != nil {
		return nil, err
	}
	if err := conn.AutoMigrate(&accesslogs.AccessLogEntry{}); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("migrate access log store: %w", err)
	}
	return conn, nil
}

func openConn(ctx context.Context, dataDir string, engine db.Engine) (*db.Conn, error) {
	switch engine {
	case db.SqliteStoreEngine:
		log.WithContext(ctx).Info("using SQLite access log store engine")
		file := sqliteFileName
		if v := os.Getenv(SqliteFileEnv); v != "" {
			file = v
		}
		return db.OpenSqliteFile(ctx, dataDir, file)
	case db.PostgresStoreEngine:
		log.WithContext(ctx).Info("using Postgres access log store engine")
		dsn, err := postgresDSN()
		if err != nil {
			return nil, err
		}
		return db.OpenPostgresWithoutPool(ctx, dsn, connOptions(ctx)...)
	default:
		return nil, fmt.Errorf("unsupported access log store engine: %s", engine)
	}
}

func postgresDSN() (string, error) {
	if dsn := os.Getenv(PostgresDSNEnv); dsn != "" {
		return dsn, nil
	}
	if dsn, ok := store.LookupPostgresDSN(); ok && dsn != "" {
		return dsn, nil
	}
	return "", fmt.Errorf("neither %s nor %s is set", PostgresDSNEnv, store.PostgresDsnEnv)
}

func connOptions(ctx context.Context) []db.Option {
	val := os.Getenv(MaxOpenConnsEnv)
	if val == "" {
		return nil
	}
	conns, err := strconv.Atoi(val)
	if err != nil || conns <= 0 {
		log.WithContext(ctx).Warnf("ignoring invalid %s value %q", MaxOpenConnsEnv, val)
		return nil
	}
	return []db.Option{db.WithMaxOpenConns(conns)}
}
