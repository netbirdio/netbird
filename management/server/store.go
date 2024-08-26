package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"gorm.io/gorm"

	nbgroup "github.com/netbirdio/netbird/management/server/group"

	"github.com/netbirdio/netbird/management/server/telemetry"
	"github.com/netbirdio/netbird/util"

	"github.com/netbirdio/netbird/management/server/migration"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/posture"
	"github.com/netbirdio/netbird/management/server/testutil"
	"github.com/netbirdio/netbird/route"
)

type LockingStrength string

const (
	LockingStrengthUpdate      LockingStrength = "UPDATE"        // Strongest lock, preventing any changes by other transactions until your transaction completes.
	LockingStrengthShare       LockingStrength = "SHARE"         // Allows reading but prevents changes by other transactions.
	LockingStrengthNoKeyUpdate LockingStrength = "NO KEY UPDATE" // Similar to UPDATE but allows changes to related rows.
	LockingStrengthKeyShare    LockingStrength = "KEY SHARE"     // Protects against changes to primary/unique keys but allows other updates.
)

type Store interface {
	GetAllAccounts(ctx context.Context) []*Account
	GetAccount(ctx context.Context, accountID string) (*Account, error)
	DeleteAccount(ctx context.Context, account *Account) error
	GetAccountByUser(ctx context.Context, userID string) (*Account, error)
	GetAccountByPeerPubKey(ctx context.Context, peerKey string) (*Account, error)
	GetAccountIDByPeerPubKey(ctx context.Context, peerKey string) (string, error)
	GetAccountIDByUserID(peerKey string) (string, error)
	GetAccountIDBySetupKey(ctx context.Context, peerKey string) (string, error)
	GetAccountByPeerID(ctx context.Context, peerID string) (*Account, error)
	GetAccountBySetupKey(ctx context.Context, setupKey string) (*Account, error) // todo use key hash later
	GetAccountByPrivateDomain(ctx context.Context, domain string) (*Account, error)
	GetTokenIDByHashedToken(ctx context.Context, secret string) (string, error)
	GetUserByTokenID(ctx context.Context, tokenID string) (*User, error)
	GetUserByUserID(ctx context.Context, lockStrength LockingStrength, userID string) (*User, error)
	GetAccountGroups(ctx context.Context, accountID string) ([]*nbgroup.Group, error)
	GetPostureCheckByChecksDefinition(accountID string, checks *posture.ChecksDefinition) (*posture.Checks, error)
	SaveAccount(ctx context.Context, account *Account) error
	SaveUsers(accountID string, users map[string]*User) error
	SaveGroups(accountID string, groups map[string]*nbgroup.Group) error
	DeleteHashedPAT2TokenIDIndex(hashedToken string) error
	DeleteTokenID2UserIDIndex(tokenID string) error
	GetInstallationID() string
	SaveInstallationID(ctx context.Context, ID string) error
	// AcquireWriteLockByUID should attempt to acquire a lock for write purposes and return a function that releases the lock
	AcquireWriteLockByUID(ctx context.Context, uniqueID string) func()
	// AcquireReadLockByUID should attempt to acquire lock for read purposes and return a function that releases the lock
	AcquireReadLockByUID(ctx context.Context, uniqueID string) func()
	// AcquireGlobalLock should attempt to acquire a global lock and return a function that releases the lock
	AcquireGlobalLock(ctx context.Context) func()
	SavePeer(ctx context.Context, accountID string, peer *nbpeer.Peer) error
	SavePeerStatus(accountID, peerID string, status nbpeer.PeerStatus) error
	SavePeerLocation(accountID string, peer *nbpeer.Peer) error
	SaveUserLastLogin(ctx context.Context, accountID, userID string, lastLogin time.Time) error
	// Close should close the store persisting all unsaved data.
	Close(ctx context.Context) error
	// GetStoreEngine should return StoreEngine of the current store implementation.
	// This is also a method of metrics.DataSource interface.
	GetStoreEngine() StoreEngine
	GetPeerByPeerPubKey(ctx context.Context, lockStrength LockingStrength, peerKey string) (*nbpeer.Peer, error)
	GetAccountSettings(ctx context.Context, lockStrength LockingStrength, accountID string) (*Settings, error)
	GetSetupKeyBySecret(ctx context.Context, lockStrength LockingStrength, key string) (*SetupKey, error)
	GetTakenIPs(ctx context.Context, lockStrength LockingStrength, accountId string) ([]net.IP, error)
	IncrementSetupKeyUsage(ctx context.Context, setupKeyID string) error
	AddPeerToAllGroup(ctx context.Context, accountID string, peerID string) error
	GetPeerLabelsInAccount(ctx context.Context, lockStrength LockingStrength, accountId string) ([]string, error)
	AddPeerToGroup(ctx context.Context, accountId string, peerId string, groupID string) error
	AddPeerToAccount(ctx context.Context, peer *nbpeer.Peer) error
	IncrementNetworkSerial(ctx context.Context, accountId string) error
	GetAccountNetwork(ctx context.Context, lockStrength LockingStrength, accountId string) (*Network, error)
	ExecuteInTransaction(ctx context.Context, f func(store Store) error) error
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
func getStoreEngine(ctx context.Context, dataDir string, kind StoreEngine) StoreEngine {
	if kind == "" {
		kind = getStoreEngineFromEnv()
		if kind == "" {
			kind = SqliteStoreEngine

			// Migrate if it is the first run with a JSON file existing and no SQLite file present
			jsonStoreFile := filepath.Join(dataDir, storeFileName)
			sqliteStoreFile := filepath.Join(dataDir, storeSqliteFileName)

			if util.FileExists(jsonStoreFile) && !util.FileExists(sqliteStoreFile) {
				log.WithContext(ctx).Warnf("unsupported store engine specified, but found %s. Automatically migrating to SQLite.", jsonStoreFile)

				// Attempt to migrate from JSON store to SQLite
				if err := MigrateFileStoreToSqlite(ctx, dataDir); err != nil {
					log.WithContext(ctx).Errorf("failed to migrate filestore to SQLite: %v", err)
					kind = FileStoreEngine
				}
			}
		}
	}

	return kind
}

// NewStore creates a new store based on the provided engine type, data directory, and telemetry metrics
func NewStore(ctx context.Context, kind StoreEngine, dataDir string, metrics telemetry.AppMetrics) (Store, error) {
	kind = getStoreEngine(ctx, dataDir, kind)

	if err := checkFileStoreEngine(kind, dataDir); err != nil {
		return nil, err
	}

	switch kind {
	case SqliteStoreEngine:
		log.WithContext(ctx).Info("using SQLite store engine")
		return NewSqliteStore(ctx, dataDir, metrics)
	case PostgresStoreEngine:
		log.WithContext(ctx).Info("using Postgres store engine")
		return newPostgresStore(ctx, metrics)
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
func migrate(ctx context.Context, db *gorm.DB) error {
	migrations := getMigrations(ctx)

	for _, m := range migrations {
		if err := m(db); err != nil {
			return err
		}
	}

	return nil
}

func getMigrations(ctx context.Context) []migrationFunc {
	return []migrationFunc{
		func(db *gorm.DB) error {
			return migration.MigrateFieldFromGobToJSON[Account, net.IPNet](ctx, db, "network_net")
		},
		func(db *gorm.DB) error {
			return migration.MigrateFieldFromGobToJSON[route.Route, netip.Prefix](ctx, db, "network")
		},
		func(db *gorm.DB) error {
			return migration.MigrateFieldFromGobToJSON[route.Route, []string](ctx, db, "peer_groups")
		},
		func(db *gorm.DB) error {
			return migration.MigrateNetIPFieldFromBlobToJSON[nbpeer.Peer](ctx, db, "location_connection_ip", "")
		},
		func(db *gorm.DB) error {
			return migration.MigrateNetIPFieldFromBlobToJSON[nbpeer.Peer](ctx, db, "ip", "idx_peers_account_id_ip")
		},
	}
}

// NewTestStoreFromJson is only used in tests
func NewTestStoreFromJson(ctx context.Context, dataDir string) (Store, func(), error) {
	fstore, err := NewFileStore(ctx, dataDir, nil)
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

		store, err = NewPostgresqlStoreFromFileStore(ctx, fstore, dsn, nil)
		if err != nil {
			return nil, nil, err
		}
	} else {
		store, err = NewSqliteStoreFromFileStore(ctx, fstore, dataDir, nil)
		if err != nil {
			return nil, nil, err
		}
		cleanUp = func() { store.Close(ctx) }
	}

	return store, cleanUp, nil
}

// MigrateFileStoreToSqlite migrates the file store to the SQLite store.
func MigrateFileStoreToSqlite(ctx context.Context, dataDir string) error {
	fileStorePath := path.Join(dataDir, storeFileName)
	if _, err := os.Stat(fileStorePath); errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("%s doesn't exist, couldn't continue the operation", fileStorePath)
	}

	sqlStorePath := path.Join(dataDir, storeSqliteFileName)
	if _, err := os.Stat(sqlStorePath); err == nil {
		return fmt.Errorf("%s already exists, couldn't continue the operation", sqlStorePath)
	}

	fstore, err := NewFileStore(ctx, dataDir, nil)
	if err != nil {
		return fmt.Errorf("failed creating file store: %s: %v", dataDir, err)
	}

	fsStoreAccounts := len(fstore.GetAllAccounts(ctx))
	log.WithContext(ctx).Infof("%d account will be migrated from file store %s to sqlite store %s",
		fsStoreAccounts, fileStorePath, sqlStorePath)

	store, err := NewSqliteStoreFromFileStore(ctx, fstore, dataDir, nil)
	if err != nil {
		return fmt.Errorf("failed creating file store: %s: %v", dataDir, err)
	}

	sqliteStoreAccounts := len(store.GetAllAccounts(ctx))
	if fsStoreAccounts != sqliteStoreAccounts {
		return fmt.Errorf("failed to migrate accounts from file to sqlite. Expected accounts: %d, got: %d",
			fsStoreAccounts, sqliteStoreAccounts)
	}

	return nil
}
