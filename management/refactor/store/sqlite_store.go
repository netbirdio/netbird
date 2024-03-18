package store

import (
	"errors"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"gorm.io/gorm/logger"

	dnsTypes "github.com/netbirdio/netbird/management/refactor/resources/dns/types"
	groupTypes "github.com/netbirdio/netbird/management/refactor/resources/groups/types"
	"github.com/netbirdio/netbird/management/refactor/resources/peers"
	policyTypes "github.com/netbirdio/netbird/management/refactor/resources/policies/types"
	routeTypes "github.com/netbirdio/netbird/management/refactor/resources/routes/types"
	"github.com/netbirdio/netbird/management/refactor/resources/settings"
	setupKeyTypes "github.com/netbirdio/netbird/management/refactor/resources/setup_keys/types"
	userTypes "github.com/netbirdio/netbird/management/refactor/resources/users/types"

	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/status"
	"github.com/netbirdio/netbird/management/server/telemetry"
)

const (
	SqliteStoreEngine StoreEngine = "sqlite"
)

// SqliteStore represents an account storage backed by a Sqlite DB persisted to disk
type DefaultSqliteStore struct {
	DB                *gorm.DB
	storeFile         string
	accountLocks      sync.Map
	globalAccountLock sync.Mutex
	metrics           telemetry.AppMetrics
	installationPK    int
	accounts          map[string]*DefaultAccount
}

type installation struct {
	ID                  uint `gorm:"primaryKey"`
	InstallationIDValue string
}

// NewSqliteStore restores a store from the file located in the datadir
func NewDefaultSqliteStore(dataDir string, metrics telemetry.AppMetrics) (*DefaultSqliteStore, error) {
	storeStr := "store.DB?cache=shared"
	if runtime.GOOS == "windows" {
		// Vo avoid `The process cannot access the file because it is being used by another process` on Windows
		storeStr = "store.DB"
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

	// err = DB.AutoMigrate(
	// 	&SetupKey{}, &Peer{}, &User{}, &PersonalAccessToken{}, &Group{}, &Rule{},
	// 	&Account{}, &Policy{}, &PolicyRule{}, &route.Route{}, &nbdns.NameServerGroup{},
	// 	&installation{},
	// )
	// if err != nil {
	// 	return nil, err
	// }

	return &DefaultSqliteStore{DB: db, storeFile: file, metrics: metrics, installationPK: 1}, nil
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

func (s *DefaultSqliteStore) LoadAccount(accountID string) error {
	var account DefaultAccount
	result := s.DB.Model(&account).
		Preload("UsersG.PATsG"). // have to be specifies as this is nester reference
		Preload(clause.Associations).
		First(&account, "id = ?", accountID)
	if result.Error != nil {
		log.Errorf("error when getting account from the store: %s", result.Error)
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return status.Errorf(status.NotFound, "account not found")
		}
		return status.Errorf(status.Internal, "issue getting account from store")
	}

	// we have to manually preload policy rules as it seems that gorm preloading doesn't do it for us
	for i, policy := range account.Policies {
		var rules []*policyTypes.DefaultPolicyRule
		err := s.DB.Model(&policyTypes.DefaultPolicyRule{}).Find(&rules, "policy_id = ?", policy.ID).Error
		if err != nil {
			return status.Errorf(status.NotFound, "rule not found")
		}
		account.Policies[i].Rules = rules
	}

	account.SetupKeys = make(map[string]*setupKeyTypes.DefaultSetupKey, len(account.SetupKeysG))
	for _, key := range account.SetupKeysG {
		account.SetupKeys[key.Key] = key.Copy()
	}
	account.SetupKeysG = nil

	account.Peers = make(map[string]*nbpeer.Peer, len(account.PeersG))
	for _, peer := range account.PeersG {
		account.Peers[peer.ID] = peer.Copy()
	}
	account.PeersG = nil

	account.Users = make(map[string]*userTypes.DefaultUser, len(account.UsersG))
	for _, user := range account.UsersG {
		user.PATs = make(map[string]*PersonalAccessToken, len(user.PATs))
		for _, pat := range user.PATsG {
			user.PATs[pat.ID] = pat.Copy()
		}
		account.Users[user.Id] = user.Copy()
	}
	account.UsersG = nil

	account.Groups = make(map[string]*groupTypes.DefaultGroup, len(account.GroupsG))
	for _, group := range account.GroupsG {
		account.Groups[group.ID] = group.Copy()
	}
	account.GroupsG = nil

	account.Routes = make(map[string]*routeTypes.DefaultRoute, len(account.RoutesG))
	for _, route := range account.RoutesG {
		account.Routes[route.ID] = route.Copy()
	}
	account.RoutesG = nil

	account.NameServerGroups = make(map[string]*dnsTypes.DefaultNameServerGroup, len(account.NameServerGroupsG))
	for _, ns := range account.NameServerGroupsG {
		account.NameServerGroups[ns.ID] = ns.Copy()
	}
	account.NameServerGroupsG = nil

	s.accounts[account.Id] = &account

	return nil
}

func (s *DefaultSqliteStore) WriteAccount(accountID string) error {
	start := time.Now()

	account, ok := s.accounts[accountID]
	if !ok {
		return status.Errorf(status.NotFound, "account not found")
	}

	for _, key := range account.SetupKeys {
		account.SetupKeysG = append(account.SetupKeysG, *key)
	}

	for id, peer := range account.Peers {
		peer.ID = id
		account.PeersG = append(account.PeersG, *peer)
	}

	for id, user := range account.Users {
		user.Id = id
		for id, pat := range user.PATs {
			pat.ID = id
			user.PATsG = append(user.PATsG, *pat)
		}
		account.UsersG = append(account.UsersG, *user)
	}

	for id, group := range account.Groups {
		group.ID = id
		account.GroupsG = append(account.GroupsG, *group)
	}

	for id, route := range account.Routes {
		route.ID = id
		account.RoutesG = append(account.RoutesG, *route)
	}

	for id, ns := range account.NameServerGroups {
		ns.ID = id
		account.NameServerGroupsG = append(account.NameServerGroupsG, *ns)
	}

	err := s.DB.Transaction(func(tx *gorm.DB) error {
		result := tx.Select(clause.Associations).Delete(account.Policies, "account_id = ?", account.Id)
		if result.Error != nil {
			return result.Error
		}

		result = tx.Select(clause.Associations).Delete(account.UsersG, "account_id = ?", account.Id)
		if result.Error != nil {
			return result.Error
		}

		result = tx.Select(clause.Associations).Delete(account)
		if result.Error != nil {
			return result.Error
		}

		result = tx.
			Session(&gorm.Session{FullSaveAssociations: true}).
			Clauses(clause.OnConflict{UpdateAll: true}).Create(account)
		if result.Error != nil {
			return result.Error
		}
		return nil
	})

	took := time.Since(start)
	if s.metrics != nil {
		s.metrics.StoreMetrics().CountPersistenceDuration(took)
	}
	log.Debugf("took %d ms to persist an account to the SQLite", took.Milliseconds())

	return err
}

func (s *DefaultSqliteStore) SaveInstallationID(ID string) error {
	installation := installation{InstallationIDValue: ID}
	installation.ID = uint(s.installationPK)

	return s.DB.Clauses(clause.OnConflict{UpdateAll: true}).Create(&installation).Error
}

func (s *DefaultSqliteStore) GetInstallationID() string {
	var installation installation

	if result := s.DB.First(&installation, "id = ?", s.installationPK); result.Error != nil {
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

func (s *DefaultSqliteStore) GetLicense() string {
	// TODO implement me
	panic("implement me")
}

func (s *DefaultSqliteStore) FindSettings(accountID string) (settings.Settings, error) {
	account, ok := s.accounts[accountID]
	if !ok {
		return nil, status.Errorf(status.NotFound, "account not found")
	}
	return account.Settings, nil
}

func (s *DefaultSqliteStore) FindPeerByPubKey(accountID string, pubKey string) (peers.Peer, error) {
	a, ok := s.accounts[accountID]
	if !ok {
		return nil, status.Errorf(status.NotFound, "account not found")
	}
	for _, peer := range a.Peers {
		if peer.Key == pubKey {
			return peer.Copy(), nil
		}
	}

	return nil, status.Errorf(status.NotFound, "peer with the public key %s not found", pubKey)
}

func (s *DefaultSqliteStore) FindPeerByID(accountID string, id string) (peers.Peer, error) {
	a, ok := s.accounts[accountID]
	if !ok {
		return nil, status.Errorf(status.NotFound, "account not found")
	}
	for _, peer := range a.Peers {
		if peer.ID == id {
			return peer.Copy(), nil
		}
	}

	return nil, status.Errorf(status.NotFound, "peer with the ID %s not found", id)
}

func (s *DefaultSqliteStore) FindAllPeersInAccount(accountId string) ([]peers.Peer, error) {
	a, ok := s.accounts[accountID]
	if !ok {
		return nil, status.Errorf(status.NotFound, "account not found")
	}
	return a.Peers, nil
}

func (s *DefaultSqliteStore) UpdatePeer(peer peers.Peer) error {
	// TODO implement me
	panic("implement me")
}
