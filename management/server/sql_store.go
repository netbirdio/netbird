package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"gorm.io/gorm/logger"

	nbdns "github.com/netbirdio/netbird/dns"
	"github.com/netbirdio/netbird/management/server/account"
	nbgroup "github.com/netbirdio/netbird/management/server/group"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/posture"
	"github.com/netbirdio/netbird/management/server/status"
	"github.com/netbirdio/netbird/management/server/telemetry"
	"github.com/netbirdio/netbird/route"
)

// SqlStore represents an account storage backed by a Sql DB persisted to disk
type SqlStore struct {
	db                *gorm.DB
	accountLocks      sync.Map
	globalAccountLock sync.Mutex
	metrics           telemetry.AppMetrics
	installationPK    int
	storeEngine       StoreEngine
}

type installation struct {
	ID                  uint `gorm:"primaryKey"`
	InstallationIDValue string
}

type migrationFunc func(*gorm.DB) error

// NewSqlStore creates a new SqlStore instance.
func NewSqlStore(db *gorm.DB, storeEngine StoreEngine, metrics telemetry.AppMetrics) (*SqlStore, error) {
	sql, err := db.DB()
	if err != nil {
		return nil, err
	}
	conns := runtime.NumCPU()
	sql.SetMaxOpenConns(conns) // TODO: make it configurable

	if err := migrate(db); err != nil {
		return nil, fmt.Errorf("migrate: %w", err)
	}
	err = db.AutoMigrate(
		&SetupKey{}, &nbpeer.Peer{}, &User{}, &PersonalAccessToken{}, &nbgroup.Group{},
		&Account{}, &Policy{}, &PolicyRule{}, &route.Route{}, &nbdns.NameServerGroup{},
		&installation{}, &account.ExtraSettings{}, &posture.Checks{}, &nbpeer.NetworkAddress{},
	)
	if err != nil {
		return nil, fmt.Errorf("auto migrate: %w", err)
	}

	return &SqlStore{db: db, storeEngine: storeEngine, metrics: metrics, installationPK: 1}, nil
}

// AcquireGlobalLock acquires global lock across all the accounts and returns a function that releases the lock
func (s *SqlStore) AcquireGlobalLock() (unlock func()) {
	log.Tracef("acquiring global lock")
	start := time.Now()
	s.globalAccountLock.Lock()

	unlock = func() {
		s.globalAccountLock.Unlock()
		log.Tracef("released global lock in %v", time.Since(start))
	}

	took := time.Since(start)
	log.Tracef("took %v to acquire global lock", took)
	if s.metrics != nil {
		s.metrics.StoreMetrics().CountGlobalLockAcquisitionDuration(took)
	}

	return unlock
}

func (s *SqlStore) AcquireAccountWriteLock(accountID string) (unlock func()) {
	log.Tracef("acquiring write lock for account %s", accountID)

	start := time.Now()
	value, _ := s.accountLocks.LoadOrStore(accountID, &sync.RWMutex{})
	mtx := value.(*sync.RWMutex)
	mtx.Lock()

	unlock = func() {
		mtx.Unlock()
		log.Tracef("released write lock for account %s in %v", accountID, time.Since(start))
	}

	return unlock
}

func (s *SqlStore) AcquireAccountReadLock(accountID string) (unlock func()) {
	log.Tracef("acquiring read lock for account %s", accountID)

	start := time.Now()
	value, _ := s.accountLocks.LoadOrStore(accountID, &sync.RWMutex{})
	mtx := value.(*sync.RWMutex)
	mtx.RLock()

	unlock = func() {
		mtx.RUnlock()
		log.Tracef("released read lock for account %s in %v", accountID, time.Since(start))
	}

	return unlock
}

func (s *SqlStore) SaveAccount(account *Account) error {
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
			Clauses(clause.OnConflict{UpdateAll: true}).
			Create(account)
		if result.Error != nil {
			return result.Error
		}
		return nil
	})

	took := time.Since(start)
	if s.metrics != nil {
		s.metrics.StoreMetrics().CountPersistenceDuration(took)
	}
	log.Debugf("took %d ms to persist an account to the store", took.Milliseconds())

	return err
}

func (s *SqlStore) DeleteAccount(account *Account) error {
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
	log.Debugf("took %d ms to delete an account to the store", took.Milliseconds())

	return err
}

func (s *SqlStore) SaveInstallationID(ID string) error {
	installation := installation{InstallationIDValue: ID}
	installation.ID = uint(s.installationPK)

	return s.db.Clauses(clause.OnConflict{UpdateAll: true}).Create(&installation).Error
}

func (s *SqlStore) GetInstallationID() string {
	var installation installation

	if result := s.db.First(&installation, "id = ?", s.installationPK); result.Error != nil {
		return ""
	}

	return installation.InstallationIDValue
}

func (s *SqlStore) SavePeerStatus(accountID, peerID string, peerStatus nbpeer.PeerStatus) error {
	var peerCopy nbpeer.Peer
	peerCopy.Status = &peerStatus
	result := s.db.Model(&nbpeer.Peer{}).
		Where("account_id = ? AND id = ?", accountID, peerID).
		Updates(peerCopy)

	if result.Error != nil {
		return result.Error
	}

	if result.RowsAffected == 0 {
		return status.Errorf(status.NotFound, "peer %s not found", peerID)
	}

	return nil
}

func (s *SqlStore) SavePeerLocation(accountID string, peerWithLocation *nbpeer.Peer) error {
	// To maintain data integrity, we create a copy of the peer's location to prevent unintended updates to other fields.
	var peerCopy nbpeer.Peer
	// Since the location field has been migrated to JSON serialization,
	// updating the struct ensures the correct data format is inserted into the database.
	peerCopy.Location = peerWithLocation.Location

	result := s.db.Model(&nbpeer.Peer{}).
		Where("account_id = ? and id = ?", accountID, peerWithLocation.ID).
		Updates(peerCopy)

	if result.Error != nil {
		return result.Error
	}

	if result.RowsAffected == 0 {
		return status.Errorf(status.NotFound, "peer %s not found", peerWithLocation.ID)
	}

	return nil
}

// DeleteHashedPAT2TokenIDIndex is noop in SqlStore
func (s *SqlStore) DeleteHashedPAT2TokenIDIndex(hashedToken string) error {
	return nil
}

// DeleteTokenID2UserIDIndex is noop in SqlStore
func (s *SqlStore) DeleteTokenID2UserIDIndex(tokenID string) error {
	return nil
}

func (s *SqlStore) GetAccountByPrivateDomain(domain string) (*Account, error) {
	var account Account

	result := s.db.First(&account, "domain = ? and is_domain_primary_account = ? and domain_category = ?",
		strings.ToLower(domain), true, PrivateCategory)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, status.Errorf(status.NotFound, "account not found: provided domain is not registered or is not private")
		}
		log.Errorf("error when getting account from the store: %s", result.Error)
		return nil, status.Errorf(status.Internal, "issue getting account from store")
	}

	// TODO:  rework to not call GetAccount
	return s.GetAccount(account.Id)
}

func (s *SqlStore) GetAccountBySetupKey(setupKey string) (*Account, error) {
	var key SetupKey
	result := s.db.Select("account_id").First(&key, "key = ?", strings.ToUpper(setupKey))
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, status.Errorf(status.NotFound, "account not found: index lookup failed")
		}
		log.Errorf("error when getting setup key from the store: %s", result.Error)
		return nil, status.Errorf(status.Internal, "issue getting setup key from store")
	}

	if key.AccountID == "" {
		return nil, status.Errorf(status.NotFound, "account not found: index lookup failed")
	}

	return s.GetAccount(key.AccountID)
}

func (s *SqlStore) GetTokenIDByHashedToken(hashedToken string) (string, error) {
	var token PersonalAccessToken
	result := s.db.First(&token, "hashed_token = ?", hashedToken)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return "", status.Errorf(status.NotFound, "account not found: index lookup failed")
		}
		log.Errorf("error when getting token from the store: %s", result.Error)
		return "", status.Errorf(status.Internal, "issue getting account from store")
	}

	return token.ID, nil
}

func (s *SqlStore) GetUserByTokenID(tokenID string) (*User, error) {
	var token PersonalAccessToken
	result := s.db.First(&token, "id = ?", tokenID)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, status.Errorf(status.NotFound, "account not found: index lookup failed")
		}
		log.Errorf("error when getting token from the store: %s", result.Error)
		return nil, status.Errorf(status.Internal, "issue getting account from store")
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

func (s *SqlStore) GetAllAccounts() (all []*Account) {
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

func (s *SqlStore) GetAccount(accountID string) (*Account, error) {

	var account Account
	result := s.db.Model(&account).
		Preload("UsersG.PATsG"). // have to be specifies as this is nester reference
		Preload(clause.Associations).
		First(&account, "id = ?", accountID)
	if result.Error != nil {
		log.Errorf("error when getting account %s from the store: %s", accountID, result.Error)
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, status.Errorf(status.NotFound, "account not found")
		}
		return nil, status.Errorf(status.Internal, "issue getting account from store")
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

	account.Groups = make(map[string]*nbgroup.Group, len(account.GroupsG))
	for _, group := range account.GroupsG {
		account.Groups[group.ID] = group.Copy()
	}
	account.GroupsG = nil

	account.Routes = make(map[route.ID]*route.Route, len(account.RoutesG))
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

func (s *SqlStore) GetAccountByUser(userID string) (*Account, error) {
	var user User
	result := s.db.Select("account_id").First(&user, "id = ?", userID)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, status.Errorf(status.NotFound, "account not found: index lookup failed")
		}
		return nil, status.Errorf(status.Internal, "issue getting account from store")
	}

	if user.AccountID == "" {
		return nil, status.Errorf(status.NotFound, "account not found: index lookup failed")
	}

	return s.GetAccount(user.AccountID)
}

func (s *SqlStore) GetAccountByPeerID(peerID string) (*Account, error) {
	var peer nbpeer.Peer
	result := s.db.Select("account_id").First(&peer, "id = ?", peerID)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, status.Errorf(status.NotFound, "account not found: index lookup failed")
		}
		log.Errorf("error when getting peer from the store: %s", result.Error)
		return nil, status.Errorf(status.Internal, "issue getting account from store")
	}

	if peer.AccountID == "" {
		return nil, status.Errorf(status.NotFound, "account not found: index lookup failed")
	}

	return s.GetAccount(peer.AccountID)
}

func (s *SqlStore) GetAccountByPeerPubKey(peerKey string) (*Account, error) {
	var peer nbpeer.Peer

	result := s.db.Select("account_id").First(&peer, "key = ?", peerKey)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, status.Errorf(status.NotFound, "account not found: index lookup failed")
		}
		log.Errorf("error when getting peer from the store: %s", result.Error)
		return nil, status.Errorf(status.Internal, "issue getting account from store")
	}

	if peer.AccountID == "" {
		return nil, status.Errorf(status.NotFound, "account not found: index lookup failed")
	}

	return s.GetAccount(peer.AccountID)
}

func (s *SqlStore) GetAccountIDByPeerPubKey(peerKey string) (string, error) {
	var peer nbpeer.Peer
	var accountID string
	result := s.db.Model(&peer).Select("account_id").Where("key = ?", peerKey).First(&accountID)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return "", status.Errorf(status.NotFound, "account not found: index lookup failed")
		}
		log.Errorf("error when getting peer from the store: %s", result.Error)
		return "", status.Errorf(status.Internal, "issue getting account from store")
	}

	return accountID, nil
}

func (s *SqlStore) GetAccountIDByUserID(userID string) (string, error) {
	var user User
	var accountID string
	result := s.db.Model(&user).Select("account_id").Where("id = ?", userID).First(&accountID)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return "", status.Errorf(status.NotFound, "account not found: index lookup failed")
		}
		return "", status.Errorf(status.Internal, "issue getting account from store")
	}

	return accountID, nil
}

func (s *SqlStore) GetAccountIDBySetupKey(setupKey string) (string, error) {
	var key SetupKey
	var accountID string
	result := s.db.Model(&key).Select("account_id").Where("key = ?", strings.ToUpper(setupKey)).First(&accountID)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return "", status.Errorf(status.NotFound, "account not found: index lookup failed")
		}
		log.Errorf("error when getting setup key from the store: %s", result.Error)
		return "", status.Errorf(status.Internal, "issue getting setup key from store")
	}

	return accountID, nil
}

func (s *SqlStore) GetPeerByPeerPubKey(peerKey string) (*nbpeer.Peer, error) {
	var peer nbpeer.Peer
	result := s.db.First(&peer, "key = ?", peerKey)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, status.Errorf(status.NotFound, "peer not found")
		}
		log.Errorf("error when getting peer from the store: %s", result.Error)
		return nil, status.Errorf(status.Internal, "issue getting peer from store")
	}

	return &peer, nil
}

func (s *SqlStore) GetAccountSettings(accountID string) (*Settings, error) {
	var accountSettings AccountSettings
	if err := s.db.Model(&Account{}).Where("id = ?", accountID).First(&accountSettings).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, status.Errorf(status.NotFound, "settings not found")
		}
		log.Errorf("error when getting settings from the store: %s", err)
		return nil, status.Errorf(status.Internal, "issue getting settings from store")
	}
	return accountSettings.Settings, nil
}

// SaveUserLastLogin stores the last login time for a user in DB.
func (s *SqlStore) SaveUserLastLogin(accountID, userID string, lastLogin time.Time) error {
	var user User

	result := s.db.First(&user, "account_id = ? and id = ?", accountID, userID)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return status.Errorf(status.NotFound, "user %s not found", userID)
		}
		return status.Errorf(status.Internal, "issue getting user from store")
	}

	user.LastLogin = lastLogin

	return s.db.Save(user).Error
}

func (s *SqlStore) GetPostureCheckByChecksDefinition(accountID string, checks *posture.ChecksDefinition) (*posture.Checks, error) {
	definitionJSON, err := json.Marshal(checks)
	if err != nil {
		return nil, err
	}

	var postureCheck posture.Checks
	err = s.db.Where("account_id = ? AND checks = ?", accountID, string(definitionJSON)).First(&postureCheck).Error
	if err != nil {
		return nil, err
	}

	return &postureCheck, nil
}

// Close closes the underlying DB connection
func (s *SqlStore) Close() error {
	sql, err := s.db.DB()
	if err != nil {
		return fmt.Errorf("get db: %w", err)
	}
	return sql.Close()
}

// GetStoreEngine returns underlying store engine
func (s *SqlStore) GetStoreEngine() StoreEngine {
	return s.storeEngine
}

// NewSqliteStore creates a new SQLite store.
func NewSqliteStore(dataDir string, metrics telemetry.AppMetrics) (*SqlStore, error) {
	storeStr := "store.db?cache=shared"
	if runtime.GOOS == "windows" {
		// Vo avoid `The process cannot access the file because it is being used by another process` on Windows
		storeStr = "store.db"
	}

	file := filepath.Join(dataDir, storeStr)
	db, err := gorm.Open(sqlite.Open(file), &gorm.Config{
		Logger:          logger.Default.LogMode(logger.Silent),
		CreateBatchSize: 400,
		PrepareStmt:     true,
	})
	if err != nil {
		return nil, err
	}

	return NewSqlStore(db, SqliteStoreEngine, metrics)
}

// NewPostgresqlStore creates a new Postgres store.
func NewPostgresqlStore(dsn string, metrics telemetry.AppMetrics) (*SqlStore, error) {
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger:      logger.Default.LogMode(logger.Silent),
		PrepareStmt: true,
	})
	if err != nil {
		return nil, err
	}

	return NewSqlStore(db, PostgresStoreEngine, metrics)
}

// NewSqliteStoreFromFileStore restores a store from FileStore and stores SQLite DB in the file located in datadir.
func NewSqliteStoreFromFileStore(fileStore *FileStore, dataDir string, metrics telemetry.AppMetrics) (*SqlStore, error) {
	store, err := NewSqliteStore(dataDir, metrics)
	if err != nil {
		return nil, err
	}

	err = store.SaveInstallationID(fileStore.InstallationID)
	if err != nil {
		return nil, err
	}

	for _, account := range fileStore.GetAllAccounts() {
		err := store.SaveAccount(account)
		if err != nil {
			return nil, err
		}
	}

	return store, nil
}

// NewPostgresqlStoreFromFileStore restores a store from FileStore and stores Postgres DB.
func NewPostgresqlStoreFromFileStore(fileStore *FileStore, dsn string, metrics telemetry.AppMetrics) (*SqlStore, error) {
	store, err := NewPostgresqlStore(dsn, metrics)
	if err != nil {
		return nil, err
	}

	err = store.SaveInstallationID(fileStore.InstallationID)
	if err != nil {
		return nil, err
	}

	for _, account := range fileStore.GetAllAccounts() {
		err := store.SaveAccount(account)
		if err != nil {
			return nil, err
		}
	}

	return store, nil
}
