package store

import (
	"context"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	log "github.com/sirupsen/logrus"
	"gorm.io/gorm"

	"github.com/netbirdio/netbird/management/internals/shared/db"
	"github.com/netbirdio/netbird/management/internals/shared/db/migrate"
	"github.com/netbirdio/netbird/management/server/telemetry"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/util/crypt"
)

const (
	idQueryCondition               = "id = ?"
	keyQueryCondition              = "key = ?"
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

// NewSqlStore creates a new SqlStore instance on top of an open connection,
// bringing the schema to the state mode asks for first.
func NewSqlStore(ctx context.Context, conn *db.Conn, metrics telemetry.AppMetrics, mode migrate.Mode) (*SqlStore, error) {
	if metrics != nil {
		conn.SetTxMetrics(metrics.StoreMetrics())
	}

	runner, err := migrate.New(conn.DB(nil), conn.Engine(), MigrationSet())
	if err != nil {
		return nil, err
	}
	if err := runner.Run(ctx, mode); err != nil {
		return nil, err
	}

	return &SqlStore{conn: conn, db: conn.DB(nil), metrics: metrics, installationPK: 1}, nil
}

// newStore runs the migrations on conn and releases it when they fail.
func newStore(ctx context.Context, conn *db.Conn, metrics telemetry.AppMetrics, mode migrate.Mode) (*SqlStore, error) {
	store, err := NewSqlStore(ctx, conn, metrics, mode)
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
func NewSqliteStore(ctx context.Context, dataDir string, metrics telemetry.AppMetrics, mode migrate.Mode) (*SqlStore, error) {
	conn, err := db.OpenSqlite(ctx, dataDir)
	if err != nil {
		return nil, err
	}
	return newStore(ctx, conn, metrics, mode)
}

// NewPostgresqlStore creates a new Postgres store.
func NewPostgresqlStore(ctx context.Context, dsn string, metrics telemetry.AppMetrics, mode migrate.Mode) (*SqlStore, error) {
	conn, err := db.OpenPostgres(ctx, dsn, db.DefaultPoolConfig)
	if err != nil {
		return nil, err
	}
	return newStore(ctx, conn, metrics, mode)
}

func NewSqliteStoreFromFileStore(ctx context.Context, fileStore *FileStore, dataDir string, metrics telemetry.AppMetrics, mode migrate.Mode) (*SqlStore, error) {
	store, err := NewSqliteStore(ctx, dataDir, metrics, mode)
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
	return newPostgresqlStoreFromSqlStore(ctx, sqliteStore, dsn, metrics, migrate.ModeAuto)
}

func newPostgresqlStoreFromSqlStore(ctx context.Context, sqliteStore *SqlStore, dsn string, metrics telemetry.AppMetrics, mode migrate.Mode) (*SqlStore, error) {
	store, err := NewPostgresqlStoreForTests(ctx, dsn, metrics, mode)
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
func NewPostgresqlStoreForTests(ctx context.Context, dsn string, metrics telemetry.AppMetrics, mode migrate.Mode) (*SqlStore, error) {
	conn, err := db.OpenPostgres(ctx, dsn, testPoolConfig)
	if err != nil {
		return nil, err
	}
	return newStore(ctx, conn, metrics, mode)
}

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

// transaction runs fn as a savepoint of the bound transaction, or in a new
// transaction when the store is not bound to one.
func (s *SqlStore) transaction(ctx context.Context, fn func(tx *gorm.DB) error) error {
	if s.tx != nil {
		return s.db.Transaction(fn)
	}
	return s.conn.RunInTx(ctx, func(tx *db.Tx) error {
		return fn(s.conn.DB(tx))
	})
}

func (s *SqlStore) GetDB() *gorm.DB {
	return s.db
}

// SetFieldEncrypt sets the field encryptor for encrypting sensitive user data.
func (s *SqlStore) SetFieldEncrypt(enc *crypt.FieldEncrypt) {
	s.fieldEncrypt = enc
}
