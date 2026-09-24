package store

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	log "github.com/sirupsen/logrus"
	"gorm.io/gorm"

	nbdns "github.com/netbirdio/netbird/dns"
	agentNetworkTypes "github.com/netbirdio/netbird/management/internals/modules/agentnetwork/types"
	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy/accesslogs"
	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy/domain"
	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy/proxy"
	rpservice "github.com/netbirdio/netbird/management/internals/modules/reverseproxy/service"
	"github.com/netbirdio/netbird/management/internals/modules/zones"
	"github.com/netbirdio/netbird/management/internals/modules/zones/records"
	"github.com/netbirdio/netbird/management/internals/shared/db"
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
	idQueryCondition               = "id = ?"
	keyQueryCondition              = "key = ?"
	mysqlKeyQueryCondition         = "`key` = ?"
	accountAndIDQueryCondition     = "account_id = ? and id = ?"
	accountAndAnyIDQueryCondition  = "account_id = ? and (id = ? or public_id = ?)"
	accountAndPeerIDQueryCondition = "account_id = ? and peer_id = ?"
	accountAndIDsQueryCondition    = "account_id = ? AND id IN ?"
	accountIDCondition             = "account_id = ?"
	peerNotFoundFMT                = "peer %s not found"
)

var testPoolConfig = db.PoolConfig{
	MaxConns:          5,
	MinConns:          1,
	MaxConnLifetime:   30 * time.Second,
	HealthCheckPeriod: 10 * time.Second,
}

// SqlStore represents an account storage backed by a Sql DB persisted to disk
type SqlStore struct {
	conn              *db.Conn
	db                *gorm.DB
	tx                *db.Tx
	globalAccountLock sync.Mutex
	metrics           telemetry.AppMetrics
	installationPK    int
	fieldEncrypt      *crypt.FieldEncrypt
}

type migrationFunc func(*gorm.DB) error

// NewSqlStore creates a new SqlStore instance on top of an open connection.
func NewSqlStore(ctx context.Context, conn *db.Conn, metrics telemetry.AppMetrics, skipMigration bool) (*SqlStore, error) {
	if metrics != nil {
		conn.SetTxMetrics(metrics.StoreMetrics())
	}
	store := &SqlStore{conn: conn, db: conn.DB(nil), metrics: metrics, installationPK: 1}

	if skipMigration {
		log.WithContext(ctx).Infof("skipping migration")
		return store, nil
	}

	if err := migratePreAuto(ctx, store.db); err != nil {
		return nil, fmt.Errorf("migratePreAuto: %w", err)
	}
	err := conn.AutoMigrate(
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
	if err := migratePostAuto(ctx, store.db); err != nil {
		return nil, fmt.Errorf("migratePostAuto: %w", err)
	}

	return store, nil
}

// newStore runs the migrations on conn and releases it when they fail.
func newStore(ctx context.Context, conn *db.Conn, metrics telemetry.AppMetrics, skipMigration bool) (*SqlStore, error) {
	store, err := NewSqlStore(ctx, conn, metrics, skipMigration)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return store, nil
}

// Conn returns the shared connection so domain repositories can run alongside this store.
func (s *SqlStore) Conn() *db.Conn {
	return s.conn
}

func (s *SqlStore) pgxPool() *pgxpool.Pool {
	return s.conn.Pool(s.tx)
}

func GetKeyQueryCondition(s *SqlStore) string {
	if s.conn.Engine() == db.MysqlStoreEngine {
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
	return s.conn.Close()
}

// GetStoreEngine returns underlying store engine
func (s *SqlStore) GetStoreEngine() types.Engine {
	return s.conn.Engine()
}

// NewSqliteStore creates a new SQLite store.
func NewSqliteStore(ctx context.Context, dataDir string, metrics telemetry.AppMetrics, skipMigration bool) (*SqlStore, error) {
	conn, err := db.OpenSqlite(ctx, dataDir)
	if err != nil {
		return nil, err
	}
	return newStore(ctx, conn, metrics, skipMigration)
}

// NewPostgresqlStore creates a new Postgres store.
func NewPostgresqlStore(ctx context.Context, dsn string, metrics telemetry.AppMetrics, skipMigration bool) (*SqlStore, error) {
	conn, err := db.OpenPostgres(ctx, dsn, db.DefaultPoolConfig)
	if err != nil {
		return nil, err
	}
	return newStore(ctx, conn, metrics, skipMigration)
}

// NewMysqlStore creates a new MySQL store.
func NewMysqlStore(ctx context.Context, dsn string, metrics telemetry.AppMetrics, skipMigration bool) (*SqlStore, error) {
	conn, err := db.OpenMysql(ctx, dsn)
	if err != nil {
		return nil, err
	}
	return newStore(ctx, conn, metrics, skipMigration)
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
		_ = store.Close(ctx)
		return nil, err
	}

	return store, nil
}

// used for tests only
func NewPostgresqlStoreForTests(ctx context.Context, dsn string, metrics telemetry.AppMetrics, skipMigration bool) (*SqlStore, error) {
	conn, err := db.OpenPostgres(ctx, dsn, testPoolConfig)
	if err != nil {
		return nil, err
	}
	return newStore(ctx, conn, metrics, skipMigration)
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

func newMysqlStoreFromSqlStore(ctx context.Context, sqliteStore *SqlStore, dsn string, metrics telemetry.AppMetrics, skipMigration bool) (*SqlStore, error) {
	store, err := NewMysqlStore(ctx, dsn, metrics, skipMigration)
	if err != nil {
		return nil, err
	}

	if err := seedFromSqliteStore(ctx, store, sqliteStore); err != nil {
		_ = store.Close(ctx)
		return nil, err
	}

	return store, nil
}

// ExecuteInTransaction runs operation in a transaction. A store that is already
// bound to one joins it instead of opening a second, independent transaction.
func (s *SqlStore) ExecuteInTransaction(ctx context.Context, operation func(store Store) error) error {
	if s.tx != nil {
		return operation(s)
	}
	return s.conn.RunInTx(ctx, func(tx *db.Tx) error {
		return operation(s.withTx(tx))
	})
}

func (s *SqlStore) withTx(tx *db.Tx) Store {
	return &SqlStore{
		conn:         s.conn,
		db:           s.conn.DB(tx),
		tx:           tx,
		fieldEncrypt: s.fieldEncrypt,
	}
}

func (s *SqlStore) GetDB() *gorm.DB {
	return s.db
}

// SetFieldEncrypt sets the field encryptor for encrypting sensitive user data.
func (s *SqlStore) SetFieldEncrypt(enc *crypt.FieldEncrypt) {
	s.fieldEncrypt = enc
}
