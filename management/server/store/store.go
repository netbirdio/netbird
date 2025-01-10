package store

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"github.com/netbirdio/netbird/dns"
	"github.com/netbirdio/netbird/management/server/testutil"
	"github.com/netbirdio/netbird/management/server/types"

	"github.com/netbirdio/netbird/management/server/telemetry"
	"github.com/netbirdio/netbird/util"

	"github.com/netbirdio/netbird/management/server/migration"
	resourceTypes "github.com/netbirdio/netbird/management/server/networks/resources/types"
	routerTypes "github.com/netbirdio/netbird/management/server/networks/routers/types"
	networkTypes "github.com/netbirdio/netbird/management/server/networks/types"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/posture"
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
	GetAllAccounts(ctx context.Context) []*types.Account
	GetAccount(ctx context.Context, accountID string) (*types.Account, error)
	AccountExists(ctx context.Context, lockStrength LockingStrength, id string) (bool, error)
	GetAccountDomainAndCategory(ctx context.Context, lockStrength LockingStrength, accountID string) (string, string, error)
	GetAccountByUser(ctx context.Context, userID string) (*types.Account, error)
	GetAccountByPeerPubKey(ctx context.Context, peerKey string) (*types.Account, error)
	GetAccountIDByPeerPubKey(ctx context.Context, peerKey string) (string, error)
	GetAccountIDByUserID(userID string) (string, error)
	GetAccountIDBySetupKey(ctx context.Context, peerKey string) (string, error)
	GetAccountByPeerID(ctx context.Context, peerID string) (*types.Account, error)
	GetAccountBySetupKey(ctx context.Context, setupKey string) (*types.Account, error) // todo use key hash later
	GetAccountByPrivateDomain(ctx context.Context, domain string) (*types.Account, error)
	GetAccountIDByPrivateDomain(ctx context.Context, lockStrength LockingStrength, domain string) (string, error)
	GetAccountSettings(ctx context.Context, lockStrength LockingStrength, accountID string) (*types.Settings, error)
	GetAccountDNSSettings(ctx context.Context, lockStrength LockingStrength, accountID string) (*types.DNSSettings, error)
	SaveAccount(ctx context.Context, account *types.Account) error
	DeleteAccount(ctx context.Context, account *types.Account) error
	UpdateAccountDomainAttributes(ctx context.Context, accountID string, domain string, category string, isPrimaryDomain bool) error
	SaveDNSSettings(ctx context.Context, lockStrength LockingStrength, accountID string, settings *types.DNSSettings) error

	GetUserByTokenID(ctx context.Context, tokenID string) (*types.User, error)
	GetUserByUserID(ctx context.Context, lockStrength LockingStrength, userID string) (*types.User, error)
	GetAccountUsers(ctx context.Context, lockStrength LockingStrength, accountID string) ([]*types.User, error)
	SaveUsers(accountID string, users map[string]*types.User) error
	SaveUser(ctx context.Context, lockStrength LockingStrength, user *types.User) error
	SaveUserLastLogin(ctx context.Context, accountID, userID string, lastLogin time.Time) error
	GetTokenIDByHashedToken(ctx context.Context, secret string) (string, error)
	DeleteHashedPAT2TokenIDIndex(hashedToken string) error
	DeleteTokenID2UserIDIndex(tokenID string) error

	GetAccountGroups(ctx context.Context, lockStrength LockingStrength, accountID string) ([]*types.Group, error)
	GetResourceGroups(ctx context.Context, lockStrength LockingStrength, accountID, resourceID string) ([]*types.Group, error)
	GetGroupByID(ctx context.Context, lockStrength LockingStrength, accountID, groupID string) (*types.Group, error)
	GetGroupByName(ctx context.Context, lockStrength LockingStrength, groupName, accountID string) (*types.Group, error)
	GetGroupsByIDs(ctx context.Context, lockStrength LockingStrength, accountID string, groupIDs []string) (map[string]*types.Group, error)
	SaveGroups(ctx context.Context, lockStrength LockingStrength, groups []*types.Group) error
	SaveGroup(ctx context.Context, lockStrength LockingStrength, group *types.Group) error
	DeleteGroup(ctx context.Context, lockStrength LockingStrength, accountID, groupID string) error
	DeleteGroups(ctx context.Context, strength LockingStrength, accountID string, groupIDs []string) error

	GetAccountPolicies(ctx context.Context, lockStrength LockingStrength, accountID string) ([]*types.Policy, error)
	GetPolicyByID(ctx context.Context, lockStrength LockingStrength, accountID, policyID string) (*types.Policy, error)
	CreatePolicy(ctx context.Context, lockStrength LockingStrength, policy *types.Policy) error
	SavePolicy(ctx context.Context, lockStrength LockingStrength, policy *types.Policy) error
	DeletePolicy(ctx context.Context, lockStrength LockingStrength, accountID, policyID string) error

	GetPostureCheckByChecksDefinition(accountID string, checks *posture.ChecksDefinition) (*posture.Checks, error)
	GetAccountPostureChecks(ctx context.Context, lockStrength LockingStrength, accountID string) ([]*posture.Checks, error)
	GetPostureChecksByID(ctx context.Context, lockStrength LockingStrength, accountID, postureCheckID string) (*posture.Checks, error)
	GetPostureChecksByIDs(ctx context.Context, lockStrength LockingStrength, accountID string, postureChecksIDs []string) (map[string]*posture.Checks, error)
	SavePostureChecks(ctx context.Context, lockStrength LockingStrength, postureCheck *posture.Checks) error
	DeletePostureChecks(ctx context.Context, lockStrength LockingStrength, accountID, postureChecksID string) error

	GetPeerLabelsInAccount(ctx context.Context, lockStrength LockingStrength, accountId string) ([]string, error)
	AddPeerToAllGroup(ctx context.Context, accountID string, peerID string) error
	AddPeerToGroup(ctx context.Context, accountId string, peerId string, groupID string) error
	AddResourceToGroup(ctx context.Context, accountId string, groupID string, resource *types.Resource) error
	RemoveResourceFromGroup(ctx context.Context, accountId string, groupID string, resourceID string) error
	AddPeerToAccount(ctx context.Context, peer *nbpeer.Peer) error
	GetPeerByPeerPubKey(ctx context.Context, lockStrength LockingStrength, peerKey string) (*nbpeer.Peer, error)
	GetUserPeers(ctx context.Context, lockStrength LockingStrength, accountID, userID string) ([]*nbpeer.Peer, error)
	GetPeerByID(ctx context.Context, lockStrength LockingStrength, accountID string, peerID string) (*nbpeer.Peer, error)
	GetPeersByIDs(ctx context.Context, lockStrength LockingStrength, accountID string, peerIDs []string) (map[string]*nbpeer.Peer, error)
	SavePeer(ctx context.Context, accountID string, peer *nbpeer.Peer) error
	SavePeerStatus(accountID, peerID string, status nbpeer.PeerStatus) error
	SavePeerLocation(accountID string, peer *nbpeer.Peer) error

	GetSetupKeyBySecret(ctx context.Context, lockStrength LockingStrength, key string) (*types.SetupKey, error)
	IncrementSetupKeyUsage(ctx context.Context, setupKeyID string) error
	GetAccountSetupKeys(ctx context.Context, lockStrength LockingStrength, accountID string) ([]*types.SetupKey, error)
	GetSetupKeyByID(ctx context.Context, lockStrength LockingStrength, accountID, setupKeyID string) (*types.SetupKey, error)
	SaveSetupKey(ctx context.Context, lockStrength LockingStrength, setupKey *types.SetupKey) error
	DeleteSetupKey(ctx context.Context, lockStrength LockingStrength, accountID, keyID string) error

	GetAccountRoutes(ctx context.Context, lockStrength LockingStrength, accountID string) ([]*route.Route, error)
	GetRouteByID(ctx context.Context, lockStrength LockingStrength, routeID string, accountID string) (*route.Route, error)

	GetAccountNameServerGroups(ctx context.Context, lockStrength LockingStrength, accountID string) ([]*dns.NameServerGroup, error)
	GetNameServerGroupByID(ctx context.Context, lockStrength LockingStrength, nameServerGroupID string, accountID string) (*dns.NameServerGroup, error)
	SaveNameServerGroup(ctx context.Context, lockStrength LockingStrength, nameServerGroup *dns.NameServerGroup) error
	DeleteNameServerGroup(ctx context.Context, lockStrength LockingStrength, accountID, nameServerGroupID string) error

	GetTakenIPs(ctx context.Context, lockStrength LockingStrength, accountId string) ([]net.IP, error)
	IncrementNetworkSerial(ctx context.Context, lockStrength LockingStrength, accountId string) error
	GetAccountNetwork(ctx context.Context, lockStrength LockingStrength, accountId string) (*types.Network, error)

	GetInstallationID() string
	SaveInstallationID(ctx context.Context, ID string) error

	// AcquireWriteLockByUID should attempt to acquire a lock for write purposes and return a function that releases the lock
	AcquireWriteLockByUID(ctx context.Context, uniqueID string) func()
	// AcquireReadLockByUID should attempt to acquire lock for read purposes and return a function that releases the lock
	AcquireReadLockByUID(ctx context.Context, uniqueID string) func()
	// AcquireGlobalLock should attempt to acquire a global lock and return a function that releases the lock
	AcquireGlobalLock(ctx context.Context) func()

	// Close should close the store persisting all unsaved data.
	Close(ctx context.Context) error
	// GetStoreEngine should return Engine of the current store implementation.
	// This is also a method of metrics.DataSource interface.
	GetStoreEngine() Engine
	ExecuteInTransaction(ctx context.Context, f func(store Store) error) error

	GetAccountNetworks(ctx context.Context, lockStrength LockingStrength, accountID string) ([]*networkTypes.Network, error)
	GetNetworkByID(ctx context.Context, lockStrength LockingStrength, accountID, networkID string) (*networkTypes.Network, error)
	SaveNetwork(ctx context.Context, lockStrength LockingStrength, network *networkTypes.Network) error
	DeleteNetwork(ctx context.Context, lockStrength LockingStrength, accountID, networkID string) error

	GetNetworkRoutersByNetID(ctx context.Context, lockStrength LockingStrength, accountID, netID string) ([]*routerTypes.NetworkRouter, error)
	GetNetworkRoutersByAccountID(ctx context.Context, lockStrength LockingStrength, accountID string) ([]*routerTypes.NetworkRouter, error)
	GetNetworkRouterByID(ctx context.Context, lockStrength LockingStrength, accountID, routerID string) (*routerTypes.NetworkRouter, error)
	SaveNetworkRouter(ctx context.Context, lockStrength LockingStrength, router *routerTypes.NetworkRouter) error
	DeleteNetworkRouter(ctx context.Context, lockStrength LockingStrength, accountID, routerID string) error

	GetNetworkResourcesByNetID(ctx context.Context, lockStrength LockingStrength, accountID, netID string) ([]*resourceTypes.NetworkResource, error)
	GetNetworkResourcesByAccountID(ctx context.Context, lockStrength LockingStrength, accountID string) ([]*resourceTypes.NetworkResource, error)
	GetNetworkResourceByID(ctx context.Context, lockStrength LockingStrength, accountID, resourceID string) (*resourceTypes.NetworkResource, error)
	GetNetworkResourceByName(ctx context.Context, lockStrength LockingStrength, accountID, resourceName string) (*resourceTypes.NetworkResource, error)
	SaveNetworkResource(ctx context.Context, lockStrength LockingStrength, resource *resourceTypes.NetworkResource) error
	DeleteNetworkResource(ctx context.Context, lockStrength LockingStrength, accountID, resourceID string) error
}

type Engine string

const (
	FileStoreEngine     Engine = "jsonfile"
	SqliteStoreEngine   Engine = "sqlite"
	PostgresStoreEngine Engine = "postgres"
	MysqlStoreEngine    Engine = "mysql"

	postgresDsnEnv = "NETBIRD_STORE_ENGINE_POSTGRES_DSN"
	mysqlDsnEnv    = "NETBIRD_STORE_ENGINE_MYSQL_DSN"
)

func getStoreEngineFromEnv() Engine {
	// NETBIRD_STORE_ENGINE supposed to be used in tests. Otherwise, rely on the config file.
	kind, ok := os.LookupEnv("NETBIRD_STORE_ENGINE")
	if !ok {
		return ""
	}

	value := Engine(strings.ToLower(kind))
	if value == SqliteStoreEngine || value == PostgresStoreEngine || value == MysqlStoreEngine {
		return value
	}

	return SqliteStoreEngine
}

// getStoreEngine determines the store engine to use.
// If no engine is specified, it attempts to retrieve it from the environment.
// If still not specified, it defaults to using SQLite.
// Additionally, it handles the migration from a JSON store file to SQLite if applicable.
func getStoreEngine(ctx context.Context, dataDir string, kind Engine) Engine {
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
func NewStore(ctx context.Context, kind Engine, dataDir string, metrics telemetry.AppMetrics) (Store, error) {
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
	case MysqlStoreEngine:
		log.WithContext(ctx).Info("using MySQL store engine")
		return newMysqlStore(ctx, metrics)
	default:
		return nil, fmt.Errorf("unsupported kind of store: %s", kind)
	}
}

func checkFileStoreEngine(kind Engine, dataDir string) error {
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
			return migration.MigrateFieldFromGobToJSON[types.Account, net.IPNet](ctx, db, "network_net")
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
		func(db *gorm.DB) error {
			return migration.MigrateSetupKeyToHashedSetupKey[types.SetupKey](ctx, db)
		},
		func(db *gorm.DB) error {
			return migration.MigrateNewField[resourceTypes.NetworkResource](ctx, db, "enabled", true)
		},
		func(db *gorm.DB) error {
			return migration.MigrateNewField[routerTypes.NetworkRouter](ctx, db, "enabled", true)
		},
	}
}

// NewTestStoreFromSQL is only used in tests. It will create a test database base of the store engine set in env.
// Optionally it can load a SQL file to the database. If the filename is empty it will return an empty database
func NewTestStoreFromSQL(ctx context.Context, filename string, dataDir string) (Store, func(), error) {
	kind := getStoreEngineFromEnv()
	if kind == "" {
		kind = SqliteStoreEngine
	}

	storeStr := fmt.Sprintf("%s?cache=shared", storeSqliteFileName)
	if runtime.GOOS == "windows" {
		// Vo avoid `The process cannot access the file because it is being used by another process` on Windows
		storeStr = storeSqliteFileName
	}

	file := filepath.Join(dataDir, storeStr)
	db, err := gorm.Open(sqlite.Open(file), getGormConfig())
	if err != nil {
		return nil, nil, err
	}

	if filename != "" {
		err = loadSQL(db, filename)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to load SQL file: %v", err)
		}
	}

	store, err := NewSqlStore(ctx, db, SqliteStoreEngine, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create test store: %v", err)
	}

	return getSqlStoreEngine(ctx, store, kind)
}

func getSqlStoreEngine(ctx context.Context, store *SqlStore, kind Engine) (Store, func(), error) {
	if kind == PostgresStoreEngine {
		cleanUp, err := testutil.CreatePostgresTestContainer()
		if err != nil {
			return nil, nil, err
		}

		dsn, ok := os.LookupEnv(postgresDsnEnv)
		if !ok {
			return nil, nil, fmt.Errorf("%s is not set", postgresDsnEnv)
		}

		store, err = NewPostgresqlStoreFromSqlStore(ctx, store, dsn, nil)
		if err != nil {
			return nil, nil, err
		}

		return store, cleanUp, nil
	}

	if kind == MysqlStoreEngine {
		cleanUp, err := testutil.CreateMysqlTestContainer()
		if err != nil {
			return nil, nil, err
		}

		dsn, ok := os.LookupEnv(mysqlDsnEnv)
		if !ok {
			return nil, nil, fmt.Errorf("%s is not set", mysqlDsnEnv)
		}

		store, err = NewMysqlStoreFromSqlStore(ctx, store, dsn, nil)
		if err != nil {
			return nil, nil, err
		}

		return store, cleanUp, nil
	}

	closeConnection := func() {
		store.Close(ctx)
	}

	return store, closeConnection, nil
}

func loadSQL(db *gorm.DB, filepath string) error {
	sqlContent, err := os.ReadFile(filepath)
	if err != nil {
		return err
	}

	queries := strings.Split(string(sqlContent), ";")

	for _, query := range queries {
		query = strings.TrimSpace(query)
		if query != "" {
			err := db.Exec(query).Error
			if err != nil {
				return err
			}
		}
	}

	return nil
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
