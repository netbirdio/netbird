package store

import (
	"path/filepath"
	"runtime"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"gorm.io/gorm/logger"

	"github.com/netbirdio/netbird/management/refactor/peers"
	"github.com/netbirdio/netbird/management/refactor/settings"
	"github.com/netbirdio/netbird/management/server/telemetry"
)

const (
	SqliteStoreEngine StoreEngine = "sqlite"
)

// SqliteStore represents an account storage backed by a Sqlite DB persisted to disk
type DefaultSqliteStore struct {
	db                *gorm.DB
	storeFile         string
	accountLocks      sync.Map
	globalAccountLock sync.Mutex
	metrics           telemetry.AppMetrics
	installationPK    int
}

func (s *DefaultSqliteStore) FindSettings(accountID string) (*settings.Settings, error) {
	// TODO implement me
	panic("implement me")
}

func (s *DefaultSqliteStore) FindPeerByPubKey(pubKey string) (*peers.Peer, error) {
	// TODO implement me
	panic("implement me")
}

func (s *DefaultSqliteStore) FindPeerByID(id string) (*peers.Peer, error) {
	// TODO implement me
	panic("implement me")
}

func (s *DefaultSqliteStore) FindAllPeersInAccount(id string) ([]*peers.Peer, error) {
	// TODO implement me
	panic("implement me")
}

func (s *DefaultSqliteStore) UpdatePeer(peer peers.Peer) error {
	// TODO implement me
	panic("implement me")
}

type installation struct {
	ID                  uint `gorm:"primaryKey"`
	InstallationIDValue string
}

// NewSqliteStore restores a store from the file located in the datadir
func NewDefaultSqliteStore(dataDir string, metrics telemetry.AppMetrics) (*DefaultSqliteStore, error) {
	storeStr := "store.db?cache=shared"
	if runtime.GOOS == "windows" {
		// Vo avoid `The process cannot access the file because it is being used by another process` on Windows
		storeStr = "store.db"
	}

	file := filepath.Join(dataDir, storeStr)
	db, err := gorm.Open(sqlite.Open(file), &gorm.Config{
		Logger:      logger.Default.LogMode(logger.Silent),
		PrepareStmt: true,
	})
	if err != nil {
		return nil, err
	}

	sql, err := db.DB()
	if err != nil {
		return nil, err
	}
	conns := runtime.NumCPU()
	sql.SetMaxOpenConns(conns) // TODO: make it configurable

	// err = db.AutoMigrate(
	// 	&SetupKey{}, &Peer{}, &User{}, &PersonalAccessToken{}, &Group{}, &Rule{},
	// 	&Account{}, &Policy{}, &PolicyRule{}, &route.Route{}, &nbdns.NameServerGroup{},
	// 	&installation{},
	// )
	// if err != nil {
	// 	return nil, err
	// }

	return &DefaultSqliteStore{db: db, storeFile: file, metrics: metrics, installationPK: 1}, nil
}

func (s *DefaultSqliteStore) GetLicense() string {
	// TODO implement me
	panic("implement me")
}

// AcquireGlobalLock acquires global lock across all the accounts and returns a function that releases the lock
func (s *DefaultSqliteStore) AcquireGlobalLock() (unlock func()) {
	log.Debugf("acquiring global lock")
	start := time.Now()
	s.globalAccountLock.Lock()

	unlock = func() {
		s.globalAccountLock.Unlock()
		log.Debugf("released global lock in %v", time.Since(start))
	}

	took := time.Since(start)
	log.Debugf("took %v to acquire global lock", took)
	if s.metrics != nil {
		s.metrics.StoreMetrics().CountGlobalLockAcquisitionDuration(took)
	}

	return unlock
}

func (s *DefaultSqliteStore) AcquireAccountLock(accountID string) (unlock func()) {
	log.Debugf("acquiring lock for account %s", accountID)

	start := time.Now()
	value, _ := s.accountLocks.LoadOrStore(accountID, &sync.Mutex{})
	mtx := value.(*sync.Mutex)
	mtx.Lock()

	unlock = func() {
		mtx.Unlock()
		log.Debugf("released lock for account %s in %v", accountID, time.Since(start))
	}

	return unlock
}

func (s *DefaultSqliteStore) SaveInstallationID(ID string) error {
	installation := installation{InstallationIDValue: ID}
	installation.ID = uint(s.installationPK)

	return s.db.Clauses(clause.OnConflict{UpdateAll: true}).Create(&installation).Error
}

func (s *DefaultSqliteStore) GetInstallationID() string {
	var installation installation

	if result := s.db.First(&installation, "id = ?", s.installationPK); result.Error != nil {
		return ""
	}

	return installation.InstallationIDValue
}

// Close is noop in Sqlite
func (s *DefaultSqliteStore) Close() error {
	return nil
}

// GetStoreEngine returns SqliteStoreEngine
func (s *DefaultSqliteStore) GetStoreEngine() StoreEngine {
	return SqliteStoreEngine
}
