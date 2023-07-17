package server

import (
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/netbirdio/netbird/management/server/status"
	"github.com/netbirdio/netbird/management/server/telemetry"
	log "github.com/sirupsen/logrus"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"gorm.io/gorm/logger"
)

// SqliteStore represents an account storage backed by a Sqlite DB persisted to disk
type SqliteStore struct {
	db             *gorm.DB
	storeFile      string
	accountLocks   sync.Map
	InstallationPK int
}

type installation struct {
	ID                  uint `gorm:"primaryKey"`
	InstallationIDValue string
}

type accountIndex struct {
	ID          string `gorm:"primaryKey"`
	Type        string `gorm:"primaryKey"`
	SecondaryID string
	AccountID   string  `gorm:"index"`
	Account     Account `gorm:"foreignKey:account_id;references:id"`
}

// NewSqliteStore restores a store from the file located in the datadir
func NewSqliteStore(dataDir string, metrics telemetry.AppMetrics) (*SqliteStore, error) {
	file := filepath.Join(dataDir, "store.db?cache=shared")
	db, err := gorm.Open(sqlite.Open(file), &gorm.Config{
		Logger:                 logger.Default.LogMode(logger.Silent),
		SkipDefaultTransaction: true,
		PrepareStmt:            true,
	})
	if err != nil {
		return nil, err
	}

	sql, err := db.DB()
	if err != nil {
		return nil, err
	}
	sql.SetMaxOpenConns(runtime.NumCPU()) // TODO: make it configurable

	err = db.AutoMigrate(&Account{})
	if err != nil {
		return nil, err
	}

	err = db.AutoMigrate(&accountIndex{})
	if err != nil {
		return nil, err
	}

	err = db.AutoMigrate(&installation{})
	if err != nil {
		return nil, err
	}

	for _, name := range []string{"account_indices_add", "account_indices_update", "account_indices_delete"} {
		db.Exec("DROP TRIGGER IF EXISTS " + name)
	}

	indicesStatements := `
	DELETE FROM account_indices where account_id = new.id;

	INSERT INTO account_indices(account_id, type, id) SELECT new.id, 'user-id', j.key from json_each(new.users) as j
		WHERE true ON CONFLICT(id, type) DO UPDATE SET account_id=excluded.account_id, type=excluded.type, id=excluded.id, secondary_id=excluded.secondary_id;
	INSERT INTO account_indices(account_id, type, id) SELECT new.id, 'peer-id', j.key from json_each(new.peers) as j
		WHERE true ON CONFLICT(id, type) DO UPDATE SET account_id=excluded.account_id, type=excluded.type, id=excluded.id, secondary_id=excluded.secondary_id;
	INSERT INTO account_indices(account_id, type, id) SELECT new.id, 'setup-key', upper(j.key) from json_each(new.setup_keys) as j
		WHERE true ON CONFLICT(id, type) DO UPDATE SET account_id=excluded.account_id, type=excluded.type, id=excluded.id, secondary_id=excluded.secondary_id;
	INSERT INTO account_indices(account_id, type, id) SELECT new.id, 'peer-key', json_extract(j.value, '$.Key') from json_each(new.peers) as j
		WHERE true ON CONFLICT(id, type) DO UPDATE SET account_id=excluded.account_id, type=excluded.type, id=excluded.id, secondary_id=excluded.secondary_id;

	INSERT INTO account_indices(account_id, type, id, secondary_id) SELECT new.id, 'token-id', json_extract(j.value, '$.ID'), k
		FROM (SELECT json_extract(u.value, '$.PATs') pats, t.id, u.key k 
				FROM accounts t, json_each(t.users) u) t, json_each(t.pats) j
		WHERE true ON CONFLICT(id, type) DO UPDATE SET account_id=excluded.account_id, type=excluded.type, id=excluded.id, secondary_id=excluded.secondary_id;

	INSERT INTO account_indices(account_id, type, id, secondary_id) 
		SELECT new.id, 'hashed-token', json_extract(j.value, '$.HashedToken'), json_extract(j.value, '$.ID')
		FROM (SELECT json_extract(u.value, '$.PATs') pats, t.id 
				FROM accounts t, json_each(t.users) u) t, json_each(t.pats) j
		WHERE true ON CONFLICT(id, type) DO UPDATE SET account_id=excluded.account_id, type=excluded.type, id=excluded.id, secondary_id=excluded.secondary_id;
	`
	db.Exec(fmt.Sprintf("CREATE TRIGGER account_indices_add AFTER INSERT ON accounts BEGIN %s END", indicesStatements))
	db.Exec(fmt.Sprintf("CREATE TRIGGER account_indices_update AFTER UPDATE ON accounts BEGIN %s END", indicesStatements))
	db.Exec(`CREATE TRIGGER account_indices_delete AFTER DELETE ON accounts BEGIN
		DELETE FROM account_indices where account_id = old.id;
  	END;`)

	return &SqliteStore{db: db, storeFile: file, InstallationPK: 1}, nil
}

// NewSqliteStoreFromFileStor restores a store from FileStore and stored SQLite DB in the file located in datadir
func NewSqliteStoreFromFileStore(filestore *FileStore, dataDir string, metrics telemetry.AppMetrics) (*SqliteStore, error) {
	store, err := NewSqliteStore(dataDir, metrics)
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

// lookupIndex fetched account though lookup table using provided index
func (s *SqliteStore) lookupIndex(t, id string) (*Account, error) {
	var account accountIndex
	result := s.db.Preload(clause.Associations).First(&account, "type = ? and id = ?", t, id)
	if result.Error != nil {
		return nil, status.Errorf(status.NotFound, "account not found: index lookup failed")
	}

	if account.Account.Id == "" {
		return nil, status.Errorf(status.NotFound, "account not found: index lookup failed")
	}

	return &account.Account, nil
}

// AcquireGlobalLock is noop in SqliteStore
func (s *SqliteStore) AcquireGlobalLock() (unlock func()) {
	return func() {}
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
	result := s.db.Clauses(clause.OnConflict{UpdateAll: true}).Create(account)

	return result.Error
}

func (s *SqliteStore) SaveInstallationID(ID string) error {
	installation := installation{InstallationIDValue: ID}
	installation.ID = uint(s.InstallationPK)

	result := s.db.Clauses(clause.OnConflict{UpdateAll: true}).Create(&installation)

	return result.Error
}

func (s *SqliteStore) GetInstallationID() string {
	var installation installation

	result := s.db.First(&installation, "id = ?", s.InstallationPK)
	if result.Error != nil {
		return ""
	}

	return installation.InstallationIDValue
}

func (s *SqliteStore) SavePeerStatus(accountID, peerID string, peerStatus PeerStatus) error {
	account, err := s.GetAccount(accountID)
	if err != nil {
		return err
	}

	peer := account.Peers[peerID]
	if peer == nil {
		return status.Errorf(status.NotFound, "peer %s not found", peerID)
	}

	peer.Status = &peerStatus

	return s.SaveAccount(account)
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

	result := s.db.First(&account, "domain = ?", strings.ToLower(domain))
	if result.Error != nil {
		return nil, status.Errorf(status.NotFound, "account not found: provided domain is not registered or is not private")
	}

	return &account, nil
}

func (s *SqliteStore) GetAccountBySetupKey(setupKey string) (*Account, error) {
	return s.lookupIndex("setup-key", strings.ToUpper(setupKey))
}

func (s *SqliteStore) GetTokenIDByHashedToken(token string) (string, error) {
	var account accountIndex
	result := s.db.First(&account, "type = ? and id = ?", "hashed-token", token)
	if result.Error != nil {
		return "", status.Errorf(status.NotFound, "tokenID not found: provided token doesn't exists")
	}

	return account.SecondaryID, nil
}

func (s *SqliteStore) GetUserByTokenID(tokenID string) (*User, error) {
	var account accountIndex
	result := s.db.Preload(clause.Associations).First(&account, "id = ?", tokenID)
	if result.Error != nil {
		return nil, status.Errorf(status.NotFound, "user not found: provided token id is not found")
	}

	for _, user := range account.Account.Users {
		if user.Id == account.SecondaryID {
			return user, nil
		}
	}

	return nil, status.Errorf(status.NotFound, "user not found: provided token id is not found")
}

func (s *SqliteStore) GetAllAccounts() (all []*Account) {
	var accounts []Account
	result := s.db.Find(&accounts)
	if result.Error != nil {
		return all
	}

	for _, account := range accounts {
		all = append(all, account.Copy())
	}

	return all
}

func (s *SqliteStore) GetAccount(accountID string) (*Account, error) {
	var account Account

	result := s.db.First(&account, "id = ?", accountID)
	if result.Error != nil {
		return nil, status.Errorf(status.NotFound, "account not found")
	}

	return &account, nil
}

func (s *SqliteStore) GetAccountByUser(userID string) (*Account, error) {
	return s.lookupIndex("user-id", userID)
}

func (s *SqliteStore) GetAccountByPeerID(peerID string) (*Account, error) {
	return s.lookupIndex("peer-id", peerID)
}

func (s *SqliteStore) GetAccountByPeerPubKey(peerKey string) (*Account, error) {
	return s.lookupIndex("peer-key", peerKey)
}

// Close is noop in Sqlite
func (s *SqliteStore) Close() error {
	return nil
}
