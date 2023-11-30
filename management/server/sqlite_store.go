package server

import (
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"gorm.io/gorm/logger"

	nbdns "github.com/netbirdio/netbird/dns"
	"github.com/netbirdio/netbird/management/server/account"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/status"
	"github.com/netbirdio/netbird/management/server/telemetry"
	"github.com/netbirdio/netbird/route"
)

// SqliteStore represents an account storage backed by a Sqlite DB persisted to disk
type SqliteStore struct {
	db                *gorm.DB
	storeFile         string
	accountLocks      sync.Map
	globalAccountLock sync.Mutex
	metrics           telemetry.AppMetrics
	installationPK    int
}

type installation struct {
	ID                  uint `gorm:"primaryKey"`
	InstallationIDValue string
}

// NewSqliteStore restores a store from the file located in the datadir
func NewSqliteStore(dataDir string, metrics telemetry.AppMetrics) (*SqliteStore, error) {
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

	err = db.AutoMigrate(
		&SetupKey{}, &nbpeer.Peer{}, &User{}, &PersonalAccessToken{}, &Group{}, &Rule{},
		&Account{}, &Policy{}, &PolicyRule{}, &route.Route{}, &nbdns.NameServerGroup{},
		&installation{}, &account.ExtraSettings{},
	)
	if err != nil {
		return nil, err
	}

	return &SqliteStore{db: db, storeFile: file, metrics: metrics, installationPK: 1}, nil
}

// NewSqliteStoreFromFileStore restores a store from FileStore and stores SQLite DB in the file located in datadir
func NewSqliteStoreFromFileStore(filestore *FileStore, dataDir string, metrics telemetry.AppMetrics) (*SqliteStore, error) {
	store, err := NewSqliteStore(dataDir, metrics)
	if err != nil {
		return nil, err
	}

	err = store.SaveInstallationID(filestore.InstallationID)
	if err != nil {
		return nil, err
	}

	for _, account := range filestore.GetAllAccounts() {
		err := store.SaveAccount(account)
		if err != nil {
			return nil, err
		}
	}

	return store, nil
}

// AcquireGlobalLock acquires global lock across all the accounts and returns a function that releases the lock
func (s *SqliteStore) AcquireGlobalLock() (unlock func()) {
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

func (s *SqliteStore) AcquireAccountLock(accountID string) (unlock func()) {
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

func (s *SqliteStore) SaveAccount(account *Account) error {
	start := time.Now()

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

	for id, rule := range account.Rules {
		rule.ID = id
		account.RulesG = append(account.RulesG, *rule)
	}

	for id, route := range account.Routes {
		route.ID = id
		account.RoutesG = append(account.RoutesG, *route)
	}

	for id, ns := range account.NameServerGroups {
		ns.ID = id
		account.NameServerGroupsG = append(account.NameServerGroupsG, *ns)
	}

	err := s.db.Transaction(func(tx *gorm.DB) error {
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

func (s *SqliteStore) DeleteAccount(account *Account) error {
	start := time.Now()

	err := s.db.Transaction(func(tx *gorm.DB) error {
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

		return nil
	})

	took := time.Since(start)
	if s.metrics != nil {
		s.metrics.StoreMetrics().CountPersistenceDuration(took)
	}
	log.Debugf("took %d ms to delete an account to the SQLite", took.Milliseconds())

	return err
}

func (s *SqliteStore) SaveInstallationID(ID string) error {
	installation := installation{InstallationIDValue: ID}
	installation.ID = uint(s.installationPK)

	return s.db.Clauses(clause.OnConflict{UpdateAll: true}).Create(&installation).Error
}

func (s *SqliteStore) GetInstallationID() string {
	var installation installation

	if result := s.db.First(&installation, "id = ?", s.installationPK); result.Error != nil {
		return ""
	}

	return installation.InstallationIDValue
}

func (s *SqliteStore) SavePeerStatus(accountID, peerID string, peerStatus nbpeer.PeerStatus) error {
	var peer nbpeer.Peer

	result := s.db.First(&peer, "account_id = ? and id = ?", accountID, peerID)
	if result.Error != nil {
		return status.Errorf(status.NotFound, "peer %s not found", peerID)
	}

	peer.Status = &peerStatus

	return s.db.Save(peer).Error
}

// DeleteHashedPAT2TokenIDIndex is noop in Sqlite
func (s *SqliteStore) DeleteHashedPAT2TokenIDIndex(hashedToken string) error {
	return nil
}

// DeleteTokenID2UserIDIndex is noop in Sqlite
func (s *SqliteStore) DeleteTokenID2UserIDIndex(tokenID string) error {
	return nil
}

func (s *SqliteStore) GetAccountByPrivateDomain(domain string) (*Account, error) {
	var account Account

	result := s.db.First(&account, "domain = ? and is_domain_primary_account = ? and domain_category = ?",
		strings.ToLower(domain), true, PrivateCategory)
	if result.Error != nil {
		return nil, status.Errorf(status.NotFound, "account not found: provided domain is not registered or is not private")
	}

	// TODO:  rework to not call GetAccount
	return s.GetAccount(account.Id)
}

func (s *SqliteStore) GetAccountBySetupKey(setupKey string) (*Account, error) {
	var key SetupKey
	result := s.db.Select("account_id").First(&key, "key = ?", strings.ToUpper(setupKey))
	if result.Error != nil {
		return nil, status.Errorf(status.NotFound, "account not found: index lookup failed")
	}

	if key.AccountID == "" {
		return nil, status.Errorf(status.NotFound, "account not found: index lookup failed")
	}

	return s.GetAccount(key.AccountID)
}

func (s *SqliteStore) GetTokenIDByHashedToken(hashedToken string) (string, error) {
	var token PersonalAccessToken
	result := s.db.First(&token, "hashed_token = ?", hashedToken)
	if result.Error != nil {
		return "", status.Errorf(status.NotFound, "account not found: index lookup failed")
	}

	return token.ID, nil
}

func (s *SqliteStore) GetUserByTokenID(tokenID string) (*User, error) {
	var token PersonalAccessToken
	result := s.db.First(&token, "id = ?", tokenID)
	if result.Error != nil {
		return nil, status.Errorf(status.NotFound, "account not found: index lookup failed")
	}

	if token.UserID == "" {
		return nil, status.Errorf(status.NotFound, "account not found: index lookup failed")
	}

	var user User
	result = s.db.Preload("PATsG").First(&user, "id = ?", token.UserID)
	if result.Error != nil {
		return nil, status.Errorf(status.NotFound, "account not found: index lookup failed")
	}

	user.PATs = make(map[string]*PersonalAccessToken, len(user.PATsG))
	for _, pat := range user.PATsG {
		user.PATs[pat.ID] = pat.Copy()
	}

	return &user, nil
}

func (s *SqliteStore) GetAllAccounts() (all []*Account) {
	var accounts []Account
	result := s.db.Find(&accounts)
	if result.Error != nil {
		return all
	}

	for _, account := range accounts {
		if acc, err := s.GetAccount(account.Id); err == nil {
			all = append(all, acc)
		}
	}

	return all
}

func (s *SqliteStore) GetAccount(accountID string) (*Account, error) {
	var account Account

	result := s.db.Model(&account).
		Preload("UsersG.PATsG"). // have to be specifies as this is nester reference
		Preload(clause.Associations).
		First(&account, "id = ?", accountID)
	if result.Error != nil {
		return nil, status.Errorf(status.NotFound, "account not found")
	}

	// we have to manually preload policy rules as it seems that gorm preloading doesn't do it for us
	for i, policy := range account.Policies {
		var rules []*PolicyRule
		err := s.db.Model(&PolicyRule{}).Find(&rules, "policy_id = ?", policy.ID).Error
		if err != nil {
			return nil, status.Errorf(status.NotFound, "rule not found")
		}
		account.Policies[i].Rules = rules
	}

	account.SetupKeys = make(map[string]*SetupKey, len(account.SetupKeysG))
	for _, key := range account.SetupKeysG {
		account.SetupKeys[key.Key] = key.Copy()
	}
	account.SetupKeysG = nil

	account.Peers = make(map[string]*nbpeer.Peer, len(account.PeersG))
	for _, peer := range account.PeersG {
		account.Peers[peer.ID] = peer.Copy()
	}
	account.PeersG = nil

	account.Users = make(map[string]*User, len(account.UsersG))
	for _, user := range account.UsersG {
		user.PATs = make(map[string]*PersonalAccessToken, len(user.PATs))
		for _, pat := range user.PATsG {
			user.PATs[pat.ID] = pat.Copy()
		}
		account.Users[user.Id] = user.Copy()
	}
	account.UsersG = nil

	account.Groups = make(map[string]*Group, len(account.GroupsG))
	for _, group := range account.GroupsG {
		account.Groups[group.ID] = group.Copy()
	}
	account.GroupsG = nil

	account.Rules = make(map[string]*Rule, len(account.RulesG))
	for _, rule := range account.RulesG {
		account.Rules[rule.ID] = rule.Copy()
	}
	account.RulesG = nil

	account.Routes = make(map[string]*route.Route, len(account.RoutesG))
	for _, route := range account.RoutesG {
		account.Routes[route.ID] = route.Copy()
	}
	account.RoutesG = nil

	account.NameServerGroups = make(map[string]*nbdns.NameServerGroup, len(account.NameServerGroupsG))
	for _, ns := range account.NameServerGroupsG {
		account.NameServerGroups[ns.ID] = ns.Copy()
	}
	account.NameServerGroupsG = nil

	return &account, nil
}

func (s *SqliteStore) GetAccountByUser(userID string) (*Account, error) {
	var user User
	result := s.db.Select("account_id").First(&user, "id = ?", userID)
	if result.Error != nil {
		return nil, status.Errorf(status.NotFound, "account not found: index lookup failed")
	}

	if user.AccountID == "" {
		return nil, status.Errorf(status.NotFound, "account not found: index lookup failed")
	}

	return s.GetAccount(user.AccountID)
}

func (s *SqliteStore) GetAccountByPeerID(peerID string) (*Account, error) {
	var peer nbpeer.Peer
	result := s.db.Select("account_id").First(&peer, "id = ?", peerID)
	if result.Error != nil {
		return nil, status.Errorf(status.NotFound, "account not found: index lookup failed")
	}

	if peer.AccountID == "" {
		return nil, status.Errorf(status.NotFound, "account not found: index lookup failed")
	}

	return s.GetAccount(peer.AccountID)
}

func (s *SqliteStore) GetAccountByPeerPubKey(peerKey string) (*Account, error) {
	var peer nbpeer.Peer

	result := s.db.Select("account_id").First(&peer, "key = ?", peerKey)
	if result.Error != nil {
		return nil, status.Errorf(status.NotFound, "account not found: index lookup failed")
	}

	if peer.AccountID == "" {
		return nil, status.Errorf(status.NotFound, "account not found: index lookup failed")
	}

	return s.GetAccount(peer.AccountID)
}

// SaveUserLastLogin stores the last login time for a user in DB.
func (s *SqliteStore) SaveUserLastLogin(accountID, userID string, lastLogin time.Time) error {
	var user User

	result := s.db.First(&user, "account_id = ? and id = ?", accountID, userID)
	if result.Error != nil {
		return status.Errorf(status.NotFound, "user %s not found", userID)
	}

	user.LastLogin = lastLogin

	return s.db.Save(user).Error
}

// Close is noop in Sqlite
func (s *SqliteStore) Close() error {
	return nil
}

// GetStoreEngine returns SqliteStoreEngine
func (s *SqliteStore) GetStoreEngine() StoreEngine {
	return SqliteStoreEngine
}
