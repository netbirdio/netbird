package server

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/netbirdio/netbird/management/server/telemetry"
	"github.com/netbirdio/netbird/util"
	log "github.com/sirupsen/logrus"
	"gorm.io/gorm"

	"github.com/netbirdio/netbird/management/server/migration"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/posture"
	"github.com/netbirdio/netbird/management/server/testutil"
	"github.com/netbirdio/netbird/route"
)

type Store interface {
	GetAllAccounts() []*Account
	GetAccount(accountID string) (*Account, error)
	DeleteAccount(account *Account) error
	GetAccountByUser(userID string) (*Account, error)
	GetAccountByPeerPubKey(peerKey string) (*Account, error)
	GetAccountIDByPeerPubKey(peerKey string) (string, error)
	GetAccountIDByUserID(peerKey string) (string, error)
	GetAccountIDBySetupKey(peerKey string) (string, error)
	GetAccountByPeerID(peerID string) (*Account, error)
	GetAccountBySetupKey(setupKey string) (*Account, error) // todo use key hash later
	GetAccountByPrivateDomain(domain string) (*Account, error)
	GetTokenIDByHashedToken(secret string) (string, error)
	GetUserByTokenID(tokenID string) (*User, error)
	GetPostureCheckByChecksDefinition(accountID string, checks *posture.ChecksDefinition) (*posture.Checks, error)
	SaveAccount(account *Account) error
	DeleteHashedPAT2TokenIDIndex(hashedToken string) error
	DeleteTokenID2UserIDIndex(tokenID string) error
	GetInstallationID() string
	SaveInstallationID(ID string) error
	// AcquireAccountWriteLock should attempt to acquire account lock for write purposes and return a function that releases the lock
	AcquireAccountWriteLock(accountID string) func()
	// AcquireAccountReadLock should attempt to acquire account lock for read purposes and return a function that releases the lock
	AcquireAccountReadLock(accountID string) func()
	// AcquireGlobalLock should attempt to acquire a global lock and return a function that releases the lock
	AcquireGlobalLock() func()
	SavePeerStatus(accountID, peerID string, status nbpeer.PeerStatus) error
	SavePeerLocation(accountID string, peer *nbpeer.Peer) error
	SaveUserLastLogin(accountID, userID string, lastLogin time.Time) error
	// Close should close the store persisting all unsaved data.
	Close() error
	// GetStoreEngine should return StoreEngine of the current store implementation.
	// This is also a method of metrics.DataSource interface.
	GetStoreEngine() StoreEngine
	GetPeerByPeerPubKey(peerKey string) (*nbpeer.Peer, error)
	GetAccountSettings(accountID string) (*Settings, error)
}

type StoreEngine string

const (
	FileStoreEngine     StoreEngine = "jsonfile"
	SqliteStoreEngine   StoreEngine = "sqlite"
	PostgresStoreEngine StoreEngine = "postgres"

	postgresDsnEnv = "NETBIRD_STORE_ENGINE_POSTGRES_DSN"
)

func getStoreEngineFromEnv() StoreEngine {
	// NETBIRD_STORE_ENGINE supposed to be used in tests. Otherwise, rely on the config file.
	kind, ok := os.LookupEnv("NETBIRD_STORE_ENGINE")
	if !ok {
		return ""
	}

	value := StoreEngine(strings.ToLower(kind))
	if value == SqliteStoreEngine || value == PostgresStoreEngine {
		return value
	}

	return SqliteStoreEngine
}

// getStoreEngine determines the store engine to use.
// If no engine is specified, it attempts to retrieve it from the environment.
// If still not specified, it defaults to using SQLite.
// Additionally, it handles the migration from a JSON store file to SQLite if applicable.
func getStoreEngine(dataDir string, kind StoreEngine) StoreEngine {
	if kind == "" {
		kind = getStoreEngineFromEnv()
		if kind == "" {
			kind = SqliteStoreEngine

			// Migrate if it is the first run with a JSON file existing and no SQLite file present
			jsonStoreFile := filepath.Join(dataDir, storeFileName)
			sqliteStoreFile := filepath.Join(dataDir, storeSqliteFileName)

			if util.FileExists(jsonStoreFile) && !util.FileExists(sqliteStoreFile) {
				log.Warnf("unsupported store engine specified, but found %s. Automatically migrating to SQLite.", jsonStoreFile)

				// Attempt to migrate from JSON store to SQLite
				if err := MigrateFileStoreToSqlite(dataDir); err != nil {
					log.Errorf("failed to migrate filestore to SQLite: %v", err)
					kind = FileStoreEngine
				}
			}
		}
	}

	return kind
}

// NewStore creates a new store based on the provided engine type, data directory, and telemetry metrics
func NewStore(kind StoreEngine, dataDir string, metrics telemetry.AppMetrics) (Store, error) {
	kind = getStoreEngine(dataDir, kind)

	if err := checkFileStoreEngine(kind, dataDir); err != nil {
		return nil, err
	}

	switch kind {
	case SqliteStoreEngine:
		log.Info("using SQLite store engine")
		return NewSqliteStore(dataDir, metrics)
	case PostgresStoreEngine:
		log.Info("using Postgres store engine")
		return newPostgresStore(metrics)
	default:
		return nil, fmt.Errorf("unsupported kind of store: %s", kind)
	}
}

func checkFileStoreEngine(kind StoreEngine, dataDir string) error {
	if kind == FileStoreEngine {
		storeFile := filepath.Join(dataDir, storeFileName)
		if util.FileExists(storeFile) {
			return fmt.Errorf("%s is not supported. Please refer to the documentation for migrating to SQLite: "+
				"https://docs.netbird.io/selfhosted/sqlite-store#migrating-from-json-store-to-sq-lite-store", FileStoreEngine)
		}
	}
	return nil
}

// migrate migrates the SQLite database to the latest schema
func migrate(db *gorm.DB) error {
	migrations := getMigrations()

	for _, m := range migrations {
		if err := m(db); err != nil {
			return err
		}
	}

	return nil
}

func getMigrations() []migrationFunc {
	return []migrationFunc{
		func(db *gorm.DB) error {
			return migration.MigrateFieldFromGobToJSON[Account, net.IPNet](db, "network_net")
		},
		func(db *gorm.DB) error {
			return migration.MigrateFieldFromGobToJSON[route.Route, netip.Prefix](db, "network")
		},
		func(db *gorm.DB) error {
			return migration.MigrateFieldFromGobToJSON[route.Route, []string](db, "peer_groups")
		},
		func(db *gorm.DB) error {
			return migration.MigrateNetIPFieldFromBlobToJSON[nbpeer.Peer](db, "location_connection_ip", "")
		},
		func(db *gorm.DB) error {
			return migration.MigrateNetIPFieldFromBlobToJSON[nbpeer.Peer](db, "ip", "idx_peers_account_id_ip")
		},
	}
}

// NewTestStoreFromJson is only used in tests
func NewTestStoreFromJson(dataDir string) (Store, func(), error) {
	fstore, err := NewFileStore(dataDir, nil)
	if err != nil {
		return nil, nil, err
	}

	// if store engine is not set in the config we first try to evaluate NETBIRD_STORE_ENGINE
	kind := getStoreEngineFromEnv()
	if kind == "" {
		kind = SqliteStoreEngine
	}

	var (
		store   Store
		cleanUp func()
	)

	if kind == PostgresStoreEngine {
		cleanUp, err = testutil.CreatePGDB()
		if err != nil {
			return nil, nil, err
		}

		dsn, ok := os.LookupEnv(postgresDsnEnv)
		if !ok {
			return nil, nil, fmt.Errorf("%s is not set", postgresDsnEnv)
		}

		store, err = NewPostgresqlStoreFromFileStore(fstore, dsn, nil)
		if err != nil {
			return nil, nil, err
		}
	} else {
		store, err = NewSqliteStoreFromFileStore(fstore, dataDir, nil)
		if err != nil {
			return nil, nil, err
		}
		cleanUp = func() { store.Close() }
	}

	return store, cleanUp, nil
}

// MigrateFileStoreToSqlite migrates the file store to the SQLite store.
func MigrateFileStoreToSqlite(dataDir string) error {
	fileStorePath := path.Join(dataDir, storeFileName)
	if _, err := os.Stat(fileStorePath); errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("%s doesn't exist, couldn't continue the operation", fileStorePath)
	}

	sqlStorePath := path.Join(dataDir, storeSqliteFileName)
	if _, err := os.Stat(sqlStorePath); err == nil {
		return fmt.Errorf("%s already exists, couldn't continue the operation", sqlStorePath)
	}

	fstore, err := NewFileStore(dataDir, nil)
	if err != nil {
		return fmt.Errorf("failed creating file store: %s: %v", dataDir, err)
	}

	fsStoreAccounts := len(fstore.GetAllAccounts())
	log.Infof("%d account will be migrated from file store %s to sqlite store %s",
		fsStoreAccounts, fileStorePath, sqlStorePath)

	store, err := NewSqliteStoreFromFileStore(fstore, dataDir, nil)
	if err != nil {
		return fmt.Errorf("failed creating file store: %s: %v", dataDir, err)
	}

	sqliteStoreAccounts := len(store.GetAllAccounts())
	if fsStoreAccounts != sqliteStoreAccounts {
		return fmt.Errorf("failed to migrate accounts from file to sqlite. Expected accounts: %d, got: %d",
			fsStoreAccounts, sqliteStoreAccounts)
	}

	return nil
}
