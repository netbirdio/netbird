package store

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	log "github.com/sirupsen/logrus"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	nbdns "github.com/netbirdio/netbird/dns"
	agentNetworkTypes "github.com/netbirdio/netbird/management/internals/modules/agentnetwork/types"
	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy/accesslogs"
	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy/domain"
	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy/proxy"
	rpservice "github.com/netbirdio/netbird/management/internals/modules/reverseproxy/service"
	"github.com/netbirdio/netbird/management/internals/modules/zones"
	"github.com/netbirdio/netbird/management/internals/modules/zones/records"
	resourceTypes "github.com/netbirdio/netbird/management/server/networks/resources/types"
	routerTypes "github.com/netbirdio/netbird/management/server/networks/routers/types"
	networkTypes "github.com/netbirdio/netbird/management/server/networks/types"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/posture"
	"github.com/netbirdio/netbird/management/server/telemetry"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/route"
	"github.com/netbirdio/netbird/util/crypt"
)

const (
	storeSqliteFileName            = "store.db"
	idQueryCondition               = "id = ?"
	keyQueryCondition              = "key = ?"
	mysqlKeyQueryCondition         = "`key` = ?"
	accountAndIDQueryCondition     = "account_id = ? and id = ?"
	accountAndAnyIDQueryCondition  = "account_id = ? and (id = ? or public_id = ?)"
	accountAndPeerIDQueryCondition = "account_id = ? and peer_id = ?"
	accountAndIDsQueryCondition    = "account_id = ? AND id IN ?"
	accountIDCondition             = "account_id = ?"
	peerNotFoundFMT                = "peer %s not found"

	pgMaxConnections    = 30
	pgMinConnections    = 1
	pgMaxConnLifetime   = 60 * time.Minute
	pgHealthCheckPeriod = 1 * time.Minute
)

// SqlStore represents an account storage backed by a Sql DB persisted to disk
type SqlStore struct {
	db                 *gorm.DB
	globalAccountLock  sync.Mutex
	metrics            telemetry.AppMetrics
	installationPK     int
	storeEngine        types.Engine
	pool               *pgxpool.Pool
	fieldEncrypt       *crypt.FieldEncrypt
	transactionTimeout time.Duration
}

type migrationFunc func(*gorm.DB) error

// NewSqlStore creates a new SqlStore instance.
func NewSqlStore(ctx context.Context, db *gorm.DB, storeEngine types.Engine, metrics telemetry.AppMetrics, skipMigration bool) (*SqlStore, error) {
	sql, err := db.DB()
	if err != nil {
		return nil, err
	}

	conns, err := strconv.Atoi(os.Getenv("NB_SQL_MAX_OPEN_CONNS"))
	if err != nil {
		conns = runtime.NumCPU()
	}

	transactionTimeout := 5 * time.Minute
	if v := os.Getenv("NB_STORE_TRANSACTION_TIMEOUT"); v != "" {
		if parsed, err := time.ParseDuration(v); err == nil {
			transactionTimeout = parsed
		}
	}
	log.WithContext(ctx).Infof("Setting transaction timeout to %v", transactionTimeout)

	if storeEngine == types.SqliteStoreEngine {
		if err == nil {
			log.WithContext(ctx).Warnf("setting NB_SQL_MAX_OPEN_CONNS is not supported for sqlite, using default value 1")
		}
		conns = 1
	}

	sql.SetMaxOpenConns(conns)
	sql.SetMaxIdleConns(conns)
	sql.SetConnMaxLifetime(time.Hour)
	sql.SetConnMaxIdleTime(3 * time.Minute)

	log.WithContext(ctx).Infof("Set max open db connections to %d, max idle to %d, max lifetime to %v, max idle time to %v",
		conns, conns, time.Hour, 3*time.Minute)

	if skipMigration {
		log.WithContext(ctx).Infof("skipping migration")
		return &SqlStore{db: db, storeEngine: storeEngine, metrics: metrics, installationPK: 1, transactionTimeout: transactionTimeout}, nil
	}

	if err := migratePreAuto(ctx, db); err != nil {
		return nil, fmt.Errorf("migratePreAuto: %w", err)
	}
	err = db.AutoMigrate(
		&types.SetupKey{}, &nbpeer.Peer{}, &types.User{}, &types.PersonalAccessToken{}, &types.ProxyAccessToken{},
		&types.Group{}, &types.GroupPeer{},
		&types.Account{}, &types.Policy{}, &types.PolicyRule{}, &route.Route{}, &nbdns.NameServerGroup{},
		&installation{}, &types.ExtraSettings{}, &posture.Checks{}, &nbpeer.NetworkAddress{},
		&networkTypes.Network{}, &routerTypes.NetworkRouter{}, &resourceTypes.NetworkResource{}, &types.AccountOnboarding{},
		&types.Job{}, &zones.Zone{}, &records.Record{}, &types.UserInviteRecord{}, &rpservice.Service{}, &rpservice.Target{}, &domain.Domain{},
		&accesslogs.AccessLogEntry{}, &proxy.Proxy{},
		&agentNetworkTypes.Provider{}, &agentNetworkTypes.Policy{}, &agentNetworkTypes.Guardrail{}, &agentNetworkTypes.Settings{},
		&agentNetworkTypes.Consumption{}, &agentNetworkTypes.AccountBudgetRule{},
		&agentNetworkTypes.AgentNetworkAccessLog{}, &agentNetworkTypes.AgentNetworkAccessLogGroup{},
		&agentNetworkTypes.AgentNetworkUsage{}, &agentNetworkTypes.AgentNetworkUsageGroup{},
	)
	if err != nil {
		return nil, fmt.Errorf("auto migratePreAuto: %w", err)
	}
	if err := migratePostAuto(ctx, db); err != nil {
		return nil, fmt.Errorf("migratePostAuto: %w", err)
	}

	return &SqlStore{db: db, storeEngine: storeEngine, metrics: metrics, installationPK: 1, transactionTimeout: transactionTimeout}, nil
}

func GetKeyQueryCondition(s *SqlStore) string {
	if s.storeEngine == types.MysqlStoreEngine {
		return mysqlKeyQueryCondition
	}
	return keyQueryCondition
}

// AcquireGlobalLock acquires global lock across all the accounts and returns a function that releases the lock
func (s *SqlStore) AcquireGlobalLock(ctx context.Context) (unlock func()) {
	log.WithContext(ctx).Tracef("acquiring global lock")
	start := time.Now()
	s.globalAccountLock.Lock()

	unlock = func() {
		s.globalAccountLock.Unlock()
		log.WithContext(ctx).Tracef("released global lock in %v", time.Since(start))
	}

	took := time.Since(start)
	log.WithContext(ctx).Tracef("took %v to acquire global lock", took)
	if s.metrics != nil {
		s.metrics.StoreMetrics().CountGlobalLockAcquisitionDuration(took)
	}

	return unlock
}

// Close closes the underlying DB connection
func (s *SqlStore) Close(_ context.Context) error {
	sql, err := s.db.DB()
	if err != nil {
		return fmt.Errorf("get db: %w", err)
	}
	return sql.Close()
}

// GetStoreEngine returns underlying store engine
func (s *SqlStore) GetStoreEngine() types.Engine {
	return s.storeEngine
}

// NewSqliteStore creates a new SQLite store.
func NewSqliteStore(ctx context.Context, dataDir string, metrics telemetry.AppMetrics, skipMigration bool) (*SqlStore, error) {
	storeFile := storeSqliteFileName
	if envFile, ok := os.LookupEnv("NB_STORE_ENGINE_SQLITE_FILE"); ok && envFile != "" {
		storeFile = envFile
	}

	// Separate file path from any SQLite URI query parameters (e.g., "store.db?mode=rwc")
	filePath, query, hasQuery := strings.Cut(storeFile, "?")

	connStr := filePath
	if !filepath.IsAbs(filePath) {
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

	db, err := gorm.Open(sqlite.Open(connStr), getGormConfig())
	if err != nil {
		return nil, err
	}

	return NewSqlStore(ctx, db, types.SqliteStoreEngine, metrics, skipMigration)
}

// NewPostgresqlStore creates a new Postgres store.
func NewPostgresqlStore(ctx context.Context, dsn string, metrics telemetry.AppMetrics, skipMigration bool) (*SqlStore, error) {
	db, err := gorm.Open(postgres.Open(dsn), getGormConfig())
	if err != nil {
		return nil, err
	}
	pool, err := connectToPgDb(context.Background(), dsn)
	if err != nil {
		return nil, err
	}
	store, err := NewSqlStore(ctx, db, types.PostgresStoreEngine, metrics, skipMigration)
	if err != nil {
		pool.Close()
		return nil, err
	}
	store.pool = pool
	return store, nil
}

func connectToPgDb(ctx context.Context, dsn string) (*pgxpool.Pool, error) {
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("unable to parse database config: %w", err)
	}

	config.MaxConns = pgMaxConnections
	config.MinConns = pgMinConnections
	config.MaxConnLifetime = pgMaxConnLifetime
	config.HealthCheckPeriod = pgHealthCheckPeriod

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

// NewMysqlStore creates a new MySQL store.
func NewMysqlStore(ctx context.Context, dsn string, metrics telemetry.AppMetrics, skipMigration bool) (*SqlStore, error) {
	db, err := gorm.Open(mysql.Open(dsn+"?charset=utf8&parseTime=True&loc=Local"), getGormConfig())
	if err != nil {
		return nil, err
	}

	store, err := NewSqlStore(ctx, db, types.MysqlStoreEngine, metrics, skipMigration)
	if err != nil {
		closeGormDB(db)
		return nil, err
	}
	return store, nil
}

func getGormConfig() *gorm.Config {
	return &gorm.Config{
		Logger:          logger.Default.LogMode(logger.Silent),
		CreateBatchSize: 400,
	}
}

// newPostgresStore initializes a new Postgres store.
func newPostgresStore(ctx context.Context, metrics telemetry.AppMetrics, skipMigration bool) (Store, error) {
	dsn, ok := lookupDSNEnv(PostgresDsnEnv, PostgresDsnEnvLegacy)
	if !ok {
		return nil, fmt.Errorf("%s is not set", PostgresDsnEnv)
	}
	return NewPostgresqlStore(ctx, dsn, metrics, skipMigration)
}

// newMysqlStore initializes a new MySQL store.
func newMysqlStore(ctx context.Context, metrics telemetry.AppMetrics, skipMigration bool) (Store, error) {
	dsn, ok := lookupDSNEnv(mysqlDsnEnv, mysqlDsnEnvLegacy)
	if !ok {
		return nil, fmt.Errorf("%s is not set", mysqlDsnEnv)
	}
	return NewMysqlStore(ctx, dsn, metrics, skipMigration)
}

// NewSqliteStoreFromFileStore restores a store from FileStore and stores SQLite DB in the file located in datadir.
func NewSqliteStoreFromFileStore(ctx context.Context, fileStore *FileStore, dataDir string, metrics telemetry.AppMetrics, skipMigration bool) (*SqlStore, error) {
	store, err := NewSqliteStore(ctx, dataDir, metrics, skipMigration)
	if err != nil {
		return nil, err
	}

	err = store.SaveInstallationID(ctx, fileStore.InstallationID)
	if err != nil {
		return nil, err
	}

	for _, account := range fileStore.GetAllAccounts(ctx) {
		_, err = account.GetGroupAll()
		if err != nil {
			if err := account.AddAllGroup(false); err != nil {
				return nil, err
			}
		}

		err := store.SaveAccount(ctx, account)
		if err != nil {
			return nil, err
		}
	}

	return store, nil
}

// NewPostgresqlStoreFromSqlStore restores a store from SqlStore and stores Postgres DB.
func NewPostgresqlStoreFromSqlStore(ctx context.Context, sqliteStore *SqlStore, dsn string, metrics telemetry.AppMetrics) (*SqlStore, error) {
	return newPostgresqlStoreFromSqlStore(ctx, sqliteStore, dsn, metrics, false)
}

func newPostgresqlStoreFromSqlStore(ctx context.Context, sqliteStore *SqlStore, dsn string, metrics telemetry.AppMetrics, skipMigration bool) (*SqlStore, error) {
	store, err := NewPostgresqlStoreForTests(ctx, dsn, metrics, skipMigration)
	if err != nil {
		return nil, err
	}

	if err := seedFromSqliteStore(ctx, store, sqliteStore); err != nil {
		closeStore(ctx, store)
		return nil, err
	}

	return store, nil
}

// used for tests only
func NewPostgresqlStoreForTests(ctx context.Context, dsn string, metrics telemetry.AppMetrics, skipMigration bool) (*SqlStore, error) {
	db, err := gorm.Open(postgres.Open(dsn), getGormConfig())
	if err != nil {
		return nil, err
	}
	pool, err := connectToPgDbForTests(context.Background(), dsn)
	if err != nil {
		closeGormDB(db)
		return nil, err
	}
	store, err := NewSqlStore(ctx, db, types.PostgresStoreEngine, metrics, skipMigration)
	if err != nil {
		// Release the sessions, or the caller cannot drop the database.
		pool.Close()
		closeGormDB(db)
		return nil, err
	}
	store.pool = pool
	return store, nil
}

// used for tests only
func connectToPgDbForTests(ctx context.Context, dsn string) (*pgxpool.Pool, error) {
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("unable to parse database config: %w", err)
	}

	config.MaxConns = 5
	config.MinConns = 1
	config.MaxConnLifetime = 30 * time.Second
	config.HealthCheckPeriod = 10 * time.Second

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

// NewMysqlStoreFromSqlStore restores a store from SqlStore and stores MySQL DB.
func NewMysqlStoreFromSqlStore(ctx context.Context, sqliteStore *SqlStore, dsn string, metrics telemetry.AppMetrics) (*SqlStore, error) {
	return newMysqlStoreFromSqlStore(ctx, sqliteStore, dsn, metrics, false)
}

// seedFromSqliteStore copies the installation ID and the accounts of the
// sqlite seed store into a freshly created engine store.
func seedFromSqliteStore(ctx context.Context, store, sqliteStore *SqlStore) error {
	if err := store.SaveInstallationID(ctx, sqliteStore.GetInstallationID()); err != nil {
		return err
	}
	for _, account := range sqliteStore.GetAllAccounts(ctx) {
		if err := store.SaveAccount(ctx, account); err != nil {
			return err
		}
	}
	return nil
}

// closeStore releases a store that is not handed to the caller, so a failed
// seed does not leak its connection and pool.
func closeStore(ctx context.Context, store *SqlStore) {
	store.Close(ctx)
	if store.pool != nil {
		store.pool.Close()
	}
}

func newMysqlStoreFromSqlStore(ctx context.Context, sqliteStore *SqlStore, dsn string, metrics telemetry.AppMetrics, skipMigration bool) (*SqlStore, error) {
	store, err := NewMysqlStore(ctx, dsn, metrics, skipMigration)
	if err != nil {
		return nil, err
	}

	if err := seedFromSqliteStore(ctx, store, sqliteStore); err != nil {
		closeStore(ctx, store)
		return nil, err
	}

	return store, nil
}

func (s *SqlStore) ExecuteInTransaction(ctx context.Context, operation func(store Store) error) error {
	timeoutCtx, cancel := context.WithTimeout(ctx, s.transactionTimeout)
	defer cancel()

	startTime := time.Now()
	tx := s.db.WithContext(timeoutCtx).Begin()
	if tx.Error != nil {
		return tx.Error
	}
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
			panic(r)
		}
	}()

	if s.storeEngine == types.PostgresStoreEngine {
		if err := tx.Exec("SET LOCAL statement_timeout = '1min'").Error; err != nil {
			tx.Rollback()
			return fmt.Errorf("failed to set statement timeout: %w", err)
		}
		if err := tx.Exec("SET LOCAL lock_timeout = '1min'").Error; err != nil {
			tx.Rollback()
			return fmt.Errorf("failed to set lock timeout: %w", err)
		}
	}

	// For MySQL, disable FK checks within this transaction to avoid deadlocks
	// This is session-scoped and doesn't require SUPER privileges
	if s.storeEngine == types.MysqlStoreEngine {
		if err := tx.Exec("SET FOREIGN_KEY_CHECKS = 0").Error; err != nil {
			tx.Rollback()
			return fmt.Errorf("failed to disable FK checks: %w", err)
		}
	}

	repo := s.withTx(tx)
	err := operation(repo)
	if err != nil {
		tx.Rollback()
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(timeoutCtx.Err(), context.DeadlineExceeded) {
			log.WithContext(ctx).Warnf("transaction exceeded %s timeout after %v, stack: %s", s.transactionTimeout, time.Since(startTime), debug.Stack())
		}
		return err
	}

	// Re-enable FK checks before commit (optional, as transaction end resets it)
	if s.storeEngine == types.MysqlStoreEngine {
		if err := tx.Exec("SET FOREIGN_KEY_CHECKS = 1").Error; err != nil {
			tx.Rollback()
			return fmt.Errorf("failed to re-enable FK checks: %w", err)
		}
	}

	err = tx.Commit().Error
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(timeoutCtx.Err(), context.DeadlineExceeded) {
			log.WithContext(ctx).Warnf("transaction commit exceeded %s timeout after %v, stack: %s", s.transactionTimeout, time.Since(startTime), debug.Stack())
		}
		return err
	}

	log.WithContext(ctx).Tracef("transaction took %v", time.Since(startTime))
	if s.metrics != nil {
		s.metrics.StoreMetrics().CountTransactionDuration(time.Since(startTime))
	}

	return nil
}

func (s *SqlStore) withTx(tx *gorm.DB) Store {
	return &SqlStore{
		db:           tx,
		storeEngine:  s.storeEngine,
		fieldEncrypt: s.fieldEncrypt,
	}
}

// transaction wraps a GORM transaction with MySQL-specific FK checks handling
// Use this instead of db.Transaction() directly to avoid deadlocks on MySQL/Aurora
func (s *SqlStore) transaction(fn func(*gorm.DB) error) error {
	return s.db.Transaction(func(tx *gorm.DB) error {
		// For MySQL, disable FK checks within this transaction to avoid deadlocks
		// This is session-scoped and doesn't require SUPER privileges
		if s.storeEngine == types.MysqlStoreEngine {
			if err := tx.Exec("SET FOREIGN_KEY_CHECKS = 0").Error; err != nil {
				return fmt.Errorf("failed to disable FK checks: %w", err)
			}
		}

		err := fn(tx)

		// Re-enable FK checks before commit (optional, as transaction end resets it)
		if s.storeEngine == types.MysqlStoreEngine && err == nil {
			if fkErr := tx.Exec("SET FOREIGN_KEY_CHECKS = 1").Error; fkErr != nil {
				return fmt.Errorf("failed to re-enable FK checks: %w", fkErr)
			}
		}

		return err
	})
}

func (s *SqlStore) GetDB() *gorm.DB {
	return s.db
}

// SetFieldEncrypt sets the field encryptor for encrypting sensitive user data.
func (s *SqlStore) SetFieldEncrypt(enc *crypt.FieldEncrypt) {
	s.fieldEncrypt = enc
}
