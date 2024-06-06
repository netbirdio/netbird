package server

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"gorm.io/gorm"

	"github.com/netbirdio/netbird/management/server/migration"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/posture"
	"github.com/netbirdio/netbird/management/server/telemetry"
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
	if value == FileStoreEngine || value == SqliteStoreEngine || value == PostgresStoreEngine {
		return value
	}

	return SqliteStoreEngine
}

func getStoreEngineFromDatadir(dataDir string) StoreEngine {
	storeFile := filepath.Join(dataDir, storeFileName)
	if _, err := os.Stat(storeFile); err != nil {
		// json file not found then use sqlite as default
		return SqliteStoreEngine
	}
	return FileStoreEngine
}

func NewStore(kind StoreEngine, dataDir string, metrics telemetry.AppMetrics) (Store, error) {
	if kind == "" {
		// if store engine is not set in the config we first try to evaluate NETBIRD_STORE_ENGINE
		kind = getStoreEngineFromEnv()
		if kind == "" {
			// NETBIRD_STORE_ENGINE is not set we evaluate default based on dataDir
			kind = getStoreEngineFromDatadir(dataDir)
		}
	}
	switch kind {
	case FileStoreEngine:
		log.Info("using JSON file store engine")
		return NewFileStore(dataDir, metrics)
	case SqliteStoreEngine:
		log.Info("using SQLite store engine")
		return NewSqliteStore(dataDir, metrics)
	case PostgresStoreEngine:
		log.Info("using Postgres store engine")
		dsn, ok := os.LookupEnv(postgresDsnEnv)
		if !ok {
			return nil, fmt.Errorf("%s is not set", postgresDsnEnv)
		}
		return NewPostgresqlStore(dsn, metrics)
	default:
		return nil, fmt.Errorf("unsupported kind of store %s", kind)
	}
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

	cleanUp := func() {}

	// if store engine is not set in the config we first try to evaluate NETBIRD_STORE_ENGINE
	kind := getStoreEngineFromEnv()
	if kind == "" {
		// NETBIRD_STORE_ENGINE is not set we evaluate default based on dataDir
		kind = getStoreEngineFromDatadir(dataDir)
	}

	switch kind {
	case FileStoreEngine:
		return fstore, cleanUp, nil
	case SqliteStoreEngine:
		store, err := NewSqliteStoreFromFileStore(fstore, dataDir, nil)
		if err != nil {
			return nil, nil, err
		}
		return store, cleanUp, nil
	case PostgresStoreEngine:
		cleanUp, err = testutil.CreatePGDB()
		if err != nil {
			return nil, nil, err
		}

		dsn, ok := os.LookupEnv(postgresDsnEnv)
		if !ok {
			return nil, nil, fmt.Errorf("%s is not set", postgresDsnEnv)
		}

		store, err := NewPostgresqlStoreFromFileStore(fstore, dsn, nil)
		if err != nil {
			return nil, nil, err
		}
		return store, cleanUp, nil
	default:
		store, err := NewSqliteStoreFromFileStore(fstore, dataDir, nil)
		if err != nil {
			return nil, nil, err
		}
		return store, cleanUp, nil
	}
}
