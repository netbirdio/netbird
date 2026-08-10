package networkmap_sqlite

import (
	"context"
	"errors"
	"net/url"
	"path/filepath"
	"runtime"
	"strings"

	"database/sql"

	networkmapdb "github.com/netbirdio/netbird/management/internals/network_map_db"
	"github.com/netbirdio/netbird/shared/management/networkmap/nmdata"
)

var ErrNoRows = errors.New("no rows in result set")

type SqliteStore struct {
	Db *sql.DB
}

type sqliteInterface interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

type SqliteStoreConn struct {
	Conn sqliteInterface
}

func NewSqliteStore(ctx context.Context, storeFile, dataDir string) (*SqliteStore, error) {
	// storeFile := storeSqliteFileName
	// if envFile, ok := os.LookupEnv("NB_STORE_ENGINE_SQLITE_FILE"); ok && envFile != "" {
	// 	storeFile = envFile
	// }

	// Separate file path from any SQLite URI query parameters (e.g., "store.db?mode=rwc")
	filePath, query, hasQuery := strings.Cut(storeFile, "?")

	connStr := filePath
	if filePath != ":memory:" && !filepath.IsAbs(filePath) {
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

	db, err := sql.Open("sqlite3", connStr)
	if err != nil {
		return nil, err
	}

	return &SqliteStore{Db: db}, nil
}

func (s *SqliteStore) WithTx(tx *sql.Tx) *SqliteStoreConn {
	return &SqliteStoreConn{Conn: tx}
}

func (s *SqliteStore) UsingConn() *SqliteStoreConn {
	return &SqliteStoreConn{Conn: s.Db}
}

func (s *SqliteStoreConn) GetPeers(ctx context.Context, accountId string) ([]nmdata.Peer, map[string][]*nmdata.Peer, error) {
	return nil, nil, nil
}
func (s *SqliteStoreConn) GetPolicies(ctx context.Context, accountId string) ([]nmdata.Policy, map[string]map[string]any, map[string]map[string]any, error) {
	return nil, nil, nil, nil
}
func (s *SqliteStoreConn) GetRoutes(ctx context.Context, accountId string) ([]nmdata.Route, error) {
	return nil, nil
}
func (s *SqliteStoreConn) GetNetwork(ctx context.Context, accountId string) (nmdata.Network, error) {
	return nmdata.Network{}, nil
}
func (s *SqliteStoreConn) GetPostureChecks(ctx context.Context, accountId string) ([]nmdata.PostureChecks, map[string]string, error) {
	return nil, nil, nil
}
func (s *SqliteStoreConn) GetAllowedUsers(ctx context.Context, accountId string) (map[string]struct{}, map[string][]string, error) {
	return nil, nil, nil
}
func (s *SqliteStoreConn) GetNetworkXIDToPublicIdMap(ctx context.Context, accountId string) (map[string]string, error) {
	return nil, nil
}
func (s *SqliteStoreConn) GetPrivateServices(ctx context.Context, accountId string) ([]networkmapdb.Service, error) {
	return nil, nil
}
func (s *SqliteStoreConn) GetProxyTargetedDomainResourceIDs(ctx context.Context, accountId string) (map[string]struct{}, error) {
	return nil, nil
}
