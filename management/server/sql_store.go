package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
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

const (
	storeSqliteFileName        = "store.db"
	idQueryCondition           = "id = ?"
	accountAndIDQueryCondition = "account_id = ? and id = ?"
	peerNotFoundFMT            = "peer %s not found"
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
func NewSqlStore(ctx context.Context, db *gorm.DB, storeEngine StoreEngine, metrics telemetry.AppMetrics) (*SqlStore, error) {
	sql, err := db.DB()
	if err != nil {
		return nil, err
	}
	conns := runtime.NumCPU()
	sql.SetMaxOpenConns(conns) // TODO: make it configurable

	if err := migrate(ctx, db); err != nil {
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

// AcquireWriteLockByUID acquires an ID lock for writing to a resource and returns a function that releases the lock
func (s *SqlStore) AcquireWriteLockByUID(ctx context.Context, uniqueID string) (unlock func()) {
	log.WithContext(ctx).Tracef("acquiring write lock for ID %s", uniqueID)

	start := time.Now()
	value, _ := s.accountLocks.LoadOrStore(uniqueID, &sync.RWMutex{})
	mtx := value.(*sync.RWMutex)
	mtx.Lock()

	unlock = func() {
		mtx.Unlock()
		log.WithContext(ctx).Tracef("released write lock for ID %s in %v", uniqueID, time.Since(start))
	}

	return unlock
}

// AcquireReadLockByUID acquires an ID lock for writing to a resource and returns a function that releases the lock
func (s *SqlStore) AcquireReadLockByUID(ctx context.Context, uniqueID string) (unlock func()) {
	log.WithContext(ctx).Tracef("acquiring read lock for ID %s", uniqueID)

	start := time.Now()
	value, _ := s.accountLocks.LoadOrStore(uniqueID, &sync.RWMutex{})
	mtx := value.(*sync.RWMutex)
	mtx.RLock()

	unlock = func() {
		mtx.RUnlock()
		log.WithContext(ctx).Tracef("released read lock for ID %s in %v", uniqueID, time.Since(start))
	}

	return unlock
}

func (s *SqlStore) SaveAccount(ctx context.Context, account *Account) error {
	start := time.Now()

	// todo: remove this check after the issue is resolved
	s.checkAccountDomainBeforeSave(ctx, account.Id, account.Domain)

	generateAccountSQLTypes(account)

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
	log.WithContext(ctx).Debugf("took %d ms to persist an account to the store", took.Milliseconds())

	return err
}

// generateAccountSQLTypes generates the GORM compatible types for the account
func generateAccountSQLTypes(account *Account) {
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
}

// checkAccountDomainBeforeSave temporary method to troubleshoot an issue with domains getting blank
func (s *SqlStore) checkAccountDomainBeforeSave(ctx context.Context, accountID, newDomain string) {
	var acc Account
	var domain string
	result := s.db.Model(&acc).Select("domain").Where(idQueryCondition, accountID).First(&domain)
	if result.Error != nil {
		if !errors.Is(result.Error, gorm.ErrRecordNotFound) {
			log.WithContext(ctx).Errorf("error when getting account %s from the store to check domain: %s", accountID, result.Error)
		}
		return
	}
	if domain != "" && newDomain == "" {
		log.WithContext(ctx).Warnf("saving an account with empty domain when there was a domain set. Previous domain %s, Account ID: %s, Trace: %s", domain, accountID, debug.Stack())
	}
}

func (s *SqlStore) DeleteAccount(ctx context.Context, account *Account) error {
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
	log.WithContext(ctx).Debugf("took %d ms to delete an account to the store", took.Milliseconds())

	return err
}

func (s *SqlStore) SaveInstallationID(_ context.Context, ID string) error {
	installation := installation{InstallationIDValue: ID}
	installation.ID = uint(s.installationPK)

	return s.db.Clauses(clause.OnConflict{UpdateAll: true}).Create(&installation).Error
}

func (s *SqlStore) GetInstallationID() string {
	var installation installation

	if result := s.db.First(&installation, idQueryCondition, s.installationPK); result.Error != nil {
		return ""
	}

	return installation.InstallationIDValue
}

func (s *SqlStore) SavePeer(ctx context.Context, accountID string, peer *nbpeer.Peer) error {
	// To maintain data integrity, we create a copy of the peer's to prevent unintended updates to other fields.
	peerCopy := peer.Copy()
	peerCopy.AccountID = accountID

	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		// check if peer exists before saving
		var peerID string
		result := tx.Model(&nbpeer.Peer{}).Select("id").Find(&peerID, accountAndIDQueryCondition, accountID, peer.ID)
		if result.Error != nil {
			return result.Error
		}

		if peerID == "" {
			return status.Errorf(status.NotFound, peerNotFoundFMT, peer.ID)
		}

		result = tx.Model(&nbpeer.Peer{}).Where(accountAndIDQueryCondition, accountID, peer.ID).Save(peerCopy)
		if result.Error != nil {
			return result.Error
		}

		return nil
	})

	if err != nil {
		return err
	}

	return nil
}

func (s *SqlStore) SavePeerStatus(accountID, peerID string, peerStatus nbpeer.PeerStatus) error {
	var peerCopy nbpeer.Peer
	peerCopy.Status = &peerStatus

	fieldsToUpdate := []string{
		"peer_status_last_seen", "peer_status_connected",
		"peer_status_login_expired", "peer_status_required_approval",
	}
	result := s.db.Model(&nbpeer.Peer{}).
		Select(fieldsToUpdate).
		Where(accountAndIDQueryCondition, accountID, peerID).
		Updates(&peerCopy)
	if result.Error != nil {
		return result.Error
	}

	if result.RowsAffected == 0 {
		return status.Errorf(status.NotFound, peerNotFoundFMT, peerID)
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
		Where(accountAndIDQueryCondition, accountID, peerWithLocation.ID).
		Updates(peerCopy)

	if result.Error != nil {
		return result.Error
	}

	if result.RowsAffected == 0 {
		return status.Errorf(status.NotFound, peerNotFoundFMT, peerWithLocation.ID)
	}

	return nil
}

// SaveUsers saves the given list of users to the database.
// It updates existing users if a conflict occurs.
func (s *SqlStore) SaveUsers(accountID string, users map[string]*User) error {
	usersToSave := make([]User, 0, len(users))
	for _, user := range users {
		user.AccountID = accountID
		for id, pat := range user.PATs {
			pat.ID = id
			user.PATsG = append(user.PATsG, *pat)
		}
		usersToSave = append(usersToSave, *user)
	}
	return s.db.Session(&gorm.Session{FullSaveAssociations: true}).
		Clauses(clause.OnConflict{UpdateAll: true}).
		Create(&usersToSave).Error
}

// SaveGroups saves the given list of groups to the database.
// It updates existing groups if a conflict occurs.
func (s *SqlStore) SaveGroups(accountID string, groups map[string]*nbgroup.Group) error {
	groupsToSave := make([]nbgroup.Group, 0, len(groups))
	for _, group := range groups {
		group.AccountID = accountID
		groupsToSave = append(groupsToSave, *group)
	}
	return s.db.Clauses(clause.OnConflict{UpdateAll: true}).Create(&groupsToSave).Error
}

// DeleteHashedPAT2TokenIDIndex is noop in SqlStore
func (s *SqlStore) DeleteHashedPAT2TokenIDIndex(hashedToken string) error {
	return nil
}

// DeleteTokenID2UserIDIndex is noop in SqlStore
func (s *SqlStore) DeleteTokenID2UserIDIndex(tokenID string) error {
	return nil
}

func (s *SqlStore) GetAccountByPrivateDomain(ctx context.Context, domain string) (*Account, error) {
	var account Account

	result := s.db.First(&account, "domain = ? and is_domain_primary_account = ? and domain_category = ?",
		strings.ToLower(domain), true, PrivateCategory)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, status.Errorf(status.NotFound, "account not found: provided domain is not registered or is not private")
		}
		log.WithContext(ctx).Errorf("error when getting account from the store: %s", result.Error)
		return nil, status.Errorf(status.Internal, "issue getting account from store")
	}

	// TODO:  rework to not call GetAccount
	return s.GetAccount(ctx, account.Id)
}

func (s *SqlStore) GetAccountBySetupKey(ctx context.Context, setupKey string) (*Account, error) {
	var key SetupKey
	result := s.db.Select("account_id").First(&key, "key = ?", strings.ToUpper(setupKey))
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, status.Errorf(status.NotFound, "account not found: index lookup failed")
		}
		log.WithContext(ctx).Errorf("error when getting setup key from the store: %s", result.Error)
		return nil, status.Errorf(status.Internal, "issue getting setup key from store")
	}

	if key.AccountID == "" {
		return nil, status.Errorf(status.NotFound, "account not found: index lookup failed")
	}

	return s.GetAccount(ctx, key.AccountID)
}

func (s *SqlStore) GetTokenIDByHashedToken(ctx context.Context, hashedToken string) (string, error) {
	var token PersonalAccessToken
	result := s.db.First(&token, "hashed_token = ?", hashedToken)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return "", status.Errorf(status.NotFound, "account not found: index lookup failed")
		}
		log.WithContext(ctx).Errorf("error when getting token from the store: %s", result.Error)
		return "", status.Errorf(status.Internal, "issue getting account from store")
	}

	return token.ID, nil
}

func (s *SqlStore) GetUserByTokenID(ctx context.Context, tokenID string) (*User, error) {
	var token PersonalAccessToken
	result := s.db.First(&token, idQueryCondition, tokenID)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, status.Errorf(status.NotFound, "account not found: index lookup failed")
		}
		log.WithContext(ctx).Errorf("error when getting token from the store: %s", result.Error)
		return nil, status.Errorf(status.Internal, "issue getting account from store")
	}

	if token.UserID == "" {
		return nil, status.Errorf(status.NotFound, "account not found: index lookup failed")
	}

	var user User
	result = s.db.Preload("PATsG").First(&user, idQueryCondition, token.UserID)
	if result.Error != nil {
		return nil, status.Errorf(status.NotFound, "account not found: index lookup failed")
	}

	user.PATs = make(map[string]*PersonalAccessToken, len(user.PATsG))
	for _, pat := range user.PATsG {
		user.PATs[pat.ID] = pat.Copy()
	}

	return &user, nil
}

func (s *SqlStore) GetAllAccounts(ctx context.Context) (all []*Account) {
	var accounts []Account
	result := s.db.Find(&accounts)
	if result.Error != nil {
		return all
	}

	for _, account := range accounts {
		if acc, err := s.GetAccount(ctx, account.Id); err == nil {
			all = append(all, acc)
		}
	}

	return all
}

func (s *SqlStore) GetAccount(ctx context.Context, accountID string) (*Account, error) {

	var account Account
	result := s.db.Model(&account).
		Preload("UsersG.PATsG"). // have to be specifies as this is nester reference
		Preload(clause.Associations).
		First(&account, idQueryCondition, accountID)
	if result.Error != nil {
		log.WithContext(ctx).Errorf("error when getting account %s from the store: %s", accountID, result.Error)
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

func (s *SqlStore) GetAccountByUser(ctx context.Context, userID string) (*Account, error) {
	var user User
	result := s.db.Select("account_id").First(&user, idQueryCondition, userID)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, status.Errorf(status.NotFound, "account not found: index lookup failed")
		}
		return nil, status.Errorf(status.Internal, "issue getting account from store")
	}

	if user.AccountID == "" {
		return nil, status.Errorf(status.NotFound, "account not found: index lookup failed")
	}

	return s.GetAccount(ctx, user.AccountID)
}

func (s *SqlStore) GetAccountByPeerID(ctx context.Context, peerID string) (*Account, error) {
	var peer nbpeer.Peer
	result := s.db.Select("account_id").First(&peer, idQueryCondition, peerID)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, status.Errorf(status.NotFound, "account not found: index lookup failed")
		}
		log.WithContext(ctx).Errorf("error when getting peer from the store: %s", result.Error)
		return nil, status.Errorf(status.Internal, "issue getting account from store")
	}

	if peer.AccountID == "" {
		return nil, status.Errorf(status.NotFound, "account not found: index lookup failed")
	}

	return s.GetAccount(ctx, peer.AccountID)
}

func (s *SqlStore) GetAccountByPeerPubKey(ctx context.Context, peerKey string) (*Account, error) {
	var peer nbpeer.Peer

	result := s.db.Select("account_id").First(&peer, "key = ?", peerKey)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, status.Errorf(status.NotFound, "account not found: index lookup failed")
		}
		log.WithContext(ctx).Errorf("error when getting peer from the store: %s", result.Error)
		return nil, status.Errorf(status.Internal, "issue getting account from store")
	}

	if peer.AccountID == "" {
		return nil, status.Errorf(status.NotFound, "account not found: index lookup failed")
	}

	return s.GetAccount(ctx, peer.AccountID)
}

func (s *SqlStore) GetAccountIDByPeerPubKey(ctx context.Context, peerKey string) (string, error) {
	var peer nbpeer.Peer
	var accountID string
	result := s.db.Model(&peer).Select("account_id").Where("key = ?", peerKey).First(&accountID)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return "", status.Errorf(status.NotFound, "account not found: index lookup failed")
		}
		log.WithContext(ctx).Errorf("error when getting peer from the store: %s", result.Error)
		return "", status.Errorf(status.Internal, "issue getting account from store")
	}

	return accountID, nil
}

func (s *SqlStore) GetAccountIDByUserID(userID string) (string, error) {
	var user User
	var accountID string
	result := s.db.Model(&user).Select("account_id").Where(idQueryCondition, userID).First(&accountID)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return "", status.Errorf(status.NotFound, "account not found: index lookup failed")
		}
		return "", status.Errorf(status.Internal, "issue getting account from store")
	}

	return accountID, nil
}

func (s *SqlStore) GetAccountIDBySetupKey(ctx context.Context, setupKey string) (string, error) {
	var key SetupKey
	var accountID string
	result := s.db.Model(&key).Select("account_id").Where("key = ?", strings.ToUpper(setupKey)).First(&accountID)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return "", status.Errorf(status.NotFound, "account not found: index lookup failed")
		}
		log.WithContext(ctx).Errorf("error when getting setup key from the store: %s", result.Error)
		return "", status.Errorf(status.Internal, "issue getting setup key from store")
	}

	return accountID, nil
}

func (s *SqlStore) GetPeerByPeerPubKey(ctx context.Context, peerKey string) (*nbpeer.Peer, error) {
	var peer nbpeer.Peer
	result := s.db.First(&peer, "key = ?", peerKey)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, status.Errorf(status.NotFound, "peer not found")
		}
		log.WithContext(ctx).Errorf("error when getting peer from the store: %s", result.Error)
		return nil, status.Errorf(status.Internal, "issue getting peer from store")
	}

	return &peer, nil
}

func (s *SqlStore) GetAccountSettings(ctx context.Context, accountID string) (*Settings, error) {
	var accountSettings AccountSettings
	if err := s.db.Model(&Account{}).Where(idQueryCondition, accountID).First(&accountSettings).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, status.Errorf(status.NotFound, "settings not found")
		}
		log.WithContext(ctx).Errorf("error when getting settings from the store: %s", err)
		return nil, status.Errorf(status.Internal, "issue getting settings from store")
	}
	return accountSettings.Settings, nil
}

// SaveUserLastLogin stores the last login time for a user in DB.
func (s *SqlStore) SaveUserLastLogin(accountID, userID string, lastLogin time.Time) error {
	var user User

	result := s.db.First(&user, accountAndIDQueryCondition, accountID, userID)
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
func (s *SqlStore) Close(_ context.Context) error {
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
func NewSqliteStore(ctx context.Context, dataDir string, metrics telemetry.AppMetrics) (*SqlStore, error) {
	storeStr := fmt.Sprintf("%s?cache=shared", storeSqliteFileName)
	if runtime.GOOS == "windows" {
		// Vo avoid `The process cannot access the file because it is being used by another process` on Windows
		storeStr = storeSqliteFileName
	}

	file := filepath.Join(dataDir, storeStr)
	db, err := gorm.Open(sqlite.Open(file), getGormConfig())
	if err != nil {
		return nil, err
	}

	return NewSqlStore(ctx, db, SqliteStoreEngine, metrics)
}

// NewPostgresqlStore creates a new Postgres store.
func NewPostgresqlStore(ctx context.Context, dsn string, metrics telemetry.AppMetrics) (*SqlStore, error) {
	db, err := gorm.Open(postgres.Open(dsn), getGormConfig())
	if err != nil {
		return nil, err
	}

	return NewSqlStore(ctx, db, PostgresStoreEngine, metrics)
}

func getGormConfig() *gorm.Config {
	return &gorm.Config{
		Logger:          logger.Default.LogMode(logger.Silent),
		CreateBatchSize: 400,
		PrepareStmt:     true,
	}
}

// newPostgresStore initializes a new Postgres store.
func newPostgresStore(ctx context.Context, metrics telemetry.AppMetrics) (Store, error) {
	dsn, ok := os.LookupEnv(postgresDsnEnv)
	if !ok {
		return nil, fmt.Errorf("%s is not set", postgresDsnEnv)
	}
	return NewPostgresqlStore(ctx, dsn, metrics)
}

// NewSqliteStoreFromFileStore restores a store from FileStore and stores SQLite DB in the file located in datadir.
func NewSqliteStoreFromFileStore(ctx context.Context, fileStore *FileStore, dataDir string, metrics telemetry.AppMetrics) (*SqlStore, error) {
	store, err := NewSqliteStore(ctx, dataDir, metrics)
	if err != nil {
		return nil, err
	}

	err = store.SaveInstallationID(ctx, fileStore.InstallationID)
	if err != nil {
		return nil, err
	}

	for _, account := range fileStore.GetAllAccounts(ctx) {
		err := store.SaveAccount(ctx, account)
		if err != nil {
			return nil, err
		}
	}

	return store, nil
}

// NewPostgresqlStoreFromFileStore restores a store from FileStore and stores Postgres DB.
func NewPostgresqlStoreFromFileStore(ctx context.Context, fileStore *FileStore, dsn string, metrics telemetry.AppMetrics) (*SqlStore, error) {
	store, err := NewPostgresqlStore(ctx, dsn, metrics)
	if err != nil {
		return nil, err
	}

	err = store.SaveInstallationID(ctx, fileStore.InstallationID)
	if err != nil {
		return nil, err
	}

	for _, account := range fileStore.GetAllAccounts(ctx) {
		err := store.SaveAccount(ctx, account)
		if err != nil {
			return nil, err
		}
	}

	return store, nil
}
