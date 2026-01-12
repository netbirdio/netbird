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
	"regexp"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"github.com/netbirdio/netbird/dns"
	"github.com/netbirdio/netbird/management/server/telemetry"
	"github.com/netbirdio/netbird/management/server/testutil"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/util"
	"github.com/netbirdio/netbird/util/crypt"

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
	LockingStrengthNone        LockingStrength = "NONE"          // No locking, allowing all transactions to proceed without restrictions.
)

type Store interface {
	GetAccountsCounter(ctx context.Context) (int64, error)
	GetAllAccounts(ctx context.Context) []*types.Account
	GetAccount(ctx context.Context, accountID string) (*types.Account, error)
	GetAccountMeta(ctx context.Context, lockStrength LockingStrength, accountID string) (*types.AccountMeta, error)
	GetAccountOnboarding(ctx context.Context, accountID string) (*types.AccountOnboarding, error)
	AccountExists(ctx context.Context, lockStrength LockingStrength, id string) (bool, error)
	GetAccountDomainAndCategory(ctx context.Context, lockStrength LockingStrength, accountID string) (string, string, error)
	GetAccountByUser(ctx context.Context, userID string) (*types.Account, error)
	GetAccountByPeerPubKey(ctx context.Context, peerKey string) (*types.Account, error)
	GetAnyAccountID(ctx context.Context) (string, error)
	GetAccountIDByPeerPubKey(ctx context.Context, peerKey string) (string, error)
	GetAccountIDByUserID(ctx context.Context, lockStrength LockingStrength, userID string) (string, error)
	GetAccountIDBySetupKey(ctx context.Context, peerKey string) (string, error)
	GetAccountIDByPeerID(ctx context.Context, lockStrength LockingStrength, peerID string) (string, error)
	GetAccountByPeerID(ctx context.Context, peerID string) (*types.Account, error)
	GetAccountBySetupKey(ctx context.Context, setupKey string) (*types.Account, error) // todo use key hash later
	GetAccountByPrivateDomain(ctx context.Context, domain string) (*types.Account, error)
	GetAccountIDByPrivateDomain(ctx context.Context, lockStrength LockingStrength, domain string) (string, error)
	GetAccountSettings(ctx context.Context, lockStrength LockingStrength, accountID string) (*types.Settings, error)
	GetAccountDNSSettings(ctx context.Context, lockStrength LockingStrength, accountID string) (*types.DNSSettings, error)
	GetAccountCreatedBy(ctx context.Context, lockStrength LockingStrength, accountID string) (string, error)
	SaveAccount(ctx context.Context, account *types.Account) error
	DeleteAccount(ctx context.Context, account *types.Account) error
	UpdateAccountDomainAttributes(ctx context.Context, accountID string, domain string, category string, isPrimaryDomain bool) error
	SaveDNSSettings(ctx context.Context, accountID string, settings *types.DNSSettings) error
	SaveAccountSettings(ctx context.Context, accountID string, settings *types.Settings) error
	CountAccountsByPrivateDomain(ctx context.Context, domain string) (int64, error)
	SaveAccountOnboarding(ctx context.Context, onboarding *types.AccountOnboarding) error

	GetUserByPATID(ctx context.Context, lockStrength LockingStrength, patID string) (*types.User, error)
	GetUserByUserID(ctx context.Context, lockStrength LockingStrength, userID string) (*types.User, error)
	GetAccountUsers(ctx context.Context, lockStrength LockingStrength, accountID string) ([]*types.User, error)
	GetAccountOwner(ctx context.Context, lockStrength LockingStrength, accountID string) (*types.User, error)
	SaveUsers(ctx context.Context, users []*types.User) error
	SaveUser(ctx context.Context, user *types.User) error
	SaveUserLastLogin(ctx context.Context, accountID, userID string, lastLogin time.Time) error
	DeleteUser(ctx context.Context, accountID, userID string) error
	GetTokenIDByHashedToken(ctx context.Context, secret string) (string, error)
	DeleteHashedPAT2TokenIDIndex(hashedToken string) error
	DeleteTokenID2UserIDIndex(tokenID string) error

	GetPATByID(ctx context.Context, lockStrength LockingStrength, userID, patID string) (*types.PersonalAccessToken, error)
	GetUserPATs(ctx context.Context, lockStrength LockingStrength, userID string) ([]*types.PersonalAccessToken, error)
	GetPATByHashedToken(ctx context.Context, lockStrength LockingStrength, hashedToken string) (*types.PersonalAccessToken, error)
	MarkPATUsed(ctx context.Context, patID string) error
	SavePAT(ctx context.Context, pat *types.PersonalAccessToken) error
	DeletePAT(ctx context.Context, userID, patID string) error

	GetAccountGroups(ctx context.Context, lockStrength LockingStrength, accountID string) ([]*types.Group, error)
	GetResourceGroups(ctx context.Context, lockStrength LockingStrength, accountID, resourceID string) ([]*types.Group, error)
	GetGroupByID(ctx context.Context, lockStrength LockingStrength, accountID, groupID string) (*types.Group, error)
	GetGroupByName(ctx context.Context, lockStrength LockingStrength, groupName, accountID string) (*types.Group, error)
	GetGroupsByIDs(ctx context.Context, lockStrength LockingStrength, accountID string, groupIDs []string) (map[string]*types.Group, error)
	CreateGroups(ctx context.Context, accountID string, groups []*types.Group) error
	UpdateGroups(ctx context.Context, accountID string, groups []*types.Group) error
	CreateGroup(ctx context.Context, group *types.Group) error
	UpdateGroup(ctx context.Context, group *types.Group) error
	DeleteGroup(ctx context.Context, accountID, groupID string) error
	DeleteGroups(ctx context.Context, accountID string, groupIDs []string) error

	GetAccountPolicies(ctx context.Context, lockStrength LockingStrength, accountID string) ([]*types.Policy, error)
	GetPolicyByID(ctx context.Context, lockStrength LockingStrength, accountID, policyID string) (*types.Policy, error)
	CreatePolicy(ctx context.Context, policy *types.Policy) error
	SavePolicy(ctx context.Context, policy *types.Policy) error
	DeletePolicy(ctx context.Context, accountID, policyID string) error

	GetPostureCheckByChecksDefinition(accountID string, checks *posture.ChecksDefinition) (*posture.Checks, error)
	GetAccountPostureChecks(ctx context.Context, lockStrength LockingStrength, accountID string) ([]*posture.Checks, error)
	GetPostureChecksByID(ctx context.Context, lockStrength LockingStrength, accountID, postureCheckID string) (*posture.Checks, error)
	GetPostureChecksByIDs(ctx context.Context, lockStrength LockingStrength, accountID string, postureChecksIDs []string) (map[string]*posture.Checks, error)
	SavePostureChecks(ctx context.Context, postureCheck *posture.Checks) error
	DeletePostureChecks(ctx context.Context, accountID, postureChecksID string) error

	GetPeerLabelsInAccount(ctx context.Context, lockStrength LockingStrength, accountId string, hostname string) ([]string, error)
	AddPeerToAllGroup(ctx context.Context, accountID string, peerID string) error
	AddPeerToGroup(ctx context.Context, accountID, peerId string, groupID string) error
	RemovePeerFromGroup(ctx context.Context, peerID string, groupID string) error
	RemovePeerFromAllGroups(ctx context.Context, peerID string) error
	GetPeerGroups(ctx context.Context, lockStrength LockingStrength, accountId string, peerId string) ([]*types.Group, error)
	GetPeerGroupIDs(ctx context.Context, lockStrength LockingStrength, accountId string, peerId string) ([]string, error)
	AddResourceToGroup(ctx context.Context, accountId string, groupID string, resource *types.Resource) error
	RemoveResourceFromGroup(ctx context.Context, accountId string, groupID string, resourceID string) error
	AddPeerToAccount(ctx context.Context, peer *nbpeer.Peer) error
	GetPeerByPeerPubKey(ctx context.Context, lockStrength LockingStrength, peerKey string) (*nbpeer.Peer, error)
	GetAccountPeers(ctx context.Context, lockStrength LockingStrength, accountID, nameFilter, ipFilter string) ([]*nbpeer.Peer, error)
	GetUserPeers(ctx context.Context, lockStrength LockingStrength, accountID, userID string) ([]*nbpeer.Peer, error)
	GetPeerByID(ctx context.Context, lockStrength LockingStrength, accountID string, peerID string) (*nbpeer.Peer, error)
	GetPeersByIDs(ctx context.Context, lockStrength LockingStrength, accountID string, peerIDs []string) (map[string]*nbpeer.Peer, error)
	GetPeersByGroupIDs(ctx context.Context, accountID string, groupIDs []string) ([]*nbpeer.Peer, error)
	GetAccountPeersWithExpiration(ctx context.Context, lockStrength LockingStrength, accountID string) ([]*nbpeer.Peer, error)
	GetAccountPeersWithInactivity(ctx context.Context, lockStrength LockingStrength, accountID string) ([]*nbpeer.Peer, error)
	GetAllEphemeralPeers(ctx context.Context, lockStrength LockingStrength) ([]*nbpeer.Peer, error)
	SavePeer(ctx context.Context, accountID string, peer *nbpeer.Peer) error
	SavePeerStatus(ctx context.Context, accountID, peerID string, status nbpeer.PeerStatus) error
	SavePeerLocation(ctx context.Context, accountID string, peer *nbpeer.Peer) error
	ApproveAccountPeers(ctx context.Context, accountID string) (int, error)
	DeletePeer(ctx context.Context, accountID string, peerID string) error

	GetSetupKeyBySecret(ctx context.Context, lockStrength LockingStrength, key string) (*types.SetupKey, error)
	IncrementSetupKeyUsage(ctx context.Context, setupKeyID string) error
	GetAccountSetupKeys(ctx context.Context, lockStrength LockingStrength, accountID string) ([]*types.SetupKey, error)
	GetSetupKeyByID(ctx context.Context, lockStrength LockingStrength, accountID, setupKeyID string) (*types.SetupKey, error)
	SaveSetupKey(ctx context.Context, setupKey *types.SetupKey) error
	DeleteSetupKey(ctx context.Context, accountID, keyID string) error

	GetAccountRoutes(ctx context.Context, lockStrength LockingStrength, accountID string) ([]*route.Route, error)
	GetRouteByID(ctx context.Context, lockStrength LockingStrength, accountID, routeID string) (*route.Route, error)
	SaveRoute(ctx context.Context, route *route.Route) error
	DeleteRoute(ctx context.Context, accountID, routeID string) error

	GetAccountNameServerGroups(ctx context.Context, lockStrength LockingStrength, accountID string) ([]*dns.NameServerGroup, error)
	GetNameServerGroupByID(ctx context.Context, lockStrength LockingStrength, nameServerGroupID string, accountID string) (*dns.NameServerGroup, error)
	SaveNameServerGroup(ctx context.Context, nameServerGroup *dns.NameServerGroup) error
	DeleteNameServerGroup(ctx context.Context, accountID, nameServerGroupID string) error

	GetTakenIPs(ctx context.Context, lockStrength LockingStrength, accountId string) ([]net.IP, error)
	IncrementNetworkSerial(ctx context.Context, accountId string) error
	GetAccountNetwork(ctx context.Context, lockStrength LockingStrength, accountId string) (*types.Network, error)

	GetInstallationID() string
	SaveInstallationID(ctx context.Context, ID string) error

	// AcquireGlobalLock should attempt to acquire a global lock and return a function that releases the lock
	AcquireGlobalLock(ctx context.Context) func()

	// Close should close the store persisting all unsaved data.
	Close(ctx context.Context) error
	// GetStoreEngine should return Engine of the current store implementation.
	// This is also a method of metrics.DataSource interface.
	GetStoreEngine() types.Engine
	ExecuteInTransaction(ctx context.Context, f func(store Store) error) error

	GetAccountNetworks(ctx context.Context, lockStrength LockingStrength, accountID string) ([]*networkTypes.Network, error)
	GetNetworkByID(ctx context.Context, lockStrength LockingStrength, accountID, networkID string) (*networkTypes.Network, error)
	SaveNetwork(ctx context.Context, network *networkTypes.Network) error
	DeleteNetwork(ctx context.Context, accountID, networkID string) error

	GetNetworkRoutersByNetID(ctx context.Context, lockStrength LockingStrength, accountID, netID string) ([]*routerTypes.NetworkRouter, error)
	GetNetworkRoutersByAccountID(ctx context.Context, lockStrength LockingStrength, accountID string) ([]*routerTypes.NetworkRouter, error)
	GetNetworkRouterByID(ctx context.Context, lockStrength LockingStrength, accountID, routerID string) (*routerTypes.NetworkRouter, error)
	SaveNetworkRouter(ctx context.Context, router *routerTypes.NetworkRouter) error
	DeleteNetworkRouter(ctx context.Context, accountID, routerID string) error

	GetNetworkResourcesByNetID(ctx context.Context, lockStrength LockingStrength, accountID, netID string) ([]*resourceTypes.NetworkResource, error)
	GetNetworkResourcesByAccountID(ctx context.Context, lockStrength LockingStrength, accountID string) ([]*resourceTypes.NetworkResource, error)
	GetNetworkResourceByID(ctx context.Context, lockStrength LockingStrength, accountID, resourceID string) (*resourceTypes.NetworkResource, error)
	GetNetworkResourceByName(ctx context.Context, lockStrength LockingStrength, accountID, resourceName string) (*resourceTypes.NetworkResource, error)
	SaveNetworkResource(ctx context.Context, resource *resourceTypes.NetworkResource) error
	DeleteNetworkResource(ctx context.Context, accountID, resourceID string) error
	GetPeerByIP(ctx context.Context, lockStrength LockingStrength, accountID string, ip net.IP) (*nbpeer.Peer, error)
	GetPeerIdByLabel(ctx context.Context, lockStrength LockingStrength, accountID string, hostname string) (string, error)
	GetAccountGroupPeers(ctx context.Context, lockStrength LockingStrength, accountID string) (map[string]map[string]struct{}, error)
	IsPrimaryAccount(ctx context.Context, accountID string) (bool, string, error)
	MarkAccountPrimary(ctx context.Context, accountID string) error
	UpdateAccountNetwork(ctx context.Context, accountID string, ipNet net.IPNet) error
	GetPolicyRulesByResourceID(ctx context.Context, lockStrength LockingStrength, accountID string, peerID string) ([]*types.PolicyRule, error)

	// SetFieldEncrypt sets the field encryptor for encrypting sensitive user data.
	SetFieldEncrypt(enc *crypt.FieldEncrypt)
	GetUserIDByPeerKey(ctx context.Context, lockStrength LockingStrength, peerKey string) (string, error)
}

const (
	postgresDsnEnv = "NETBIRD_STORE_ENGINE_POSTGRES_DSN"
	mysqlDsnEnv    = "NETBIRD_STORE_ENGINE_MYSQL_DSN"
)

var supportedEngines = []types.Engine{types.SqliteStoreEngine, types.PostgresStoreEngine, types.MysqlStoreEngine}

func getStoreEngineFromEnv() types.Engine {
	// NETBIRD_STORE_ENGINE supposed to be used in tests. Otherwise, rely on the config file.
	kind, ok := os.LookupEnv("NETBIRD_STORE_ENGINE")
	if !ok {
		return ""
	}

	value := types.Engine(strings.ToLower(kind))
	if slices.Contains(supportedEngines, value) {
		return value
	}

	return types.SqliteStoreEngine
}

// getStoreEngine determines the store engine to use.
// If no engine is specified, it attempts to retrieve it from the environment.
// If still not specified, it defaults to using SQLite.
// Additionally, it handles the migration from a JSON store file to SQLite if applicable.
func getStoreEngine(ctx context.Context, dataDir string, kind types.Engine) types.Engine {
	if kind == "" {
		kind = getStoreEngineFromEnv()
		if kind == "" {
			kind = types.SqliteStoreEngine

			// Migrate if it is the first run with a JSON file existing and no SQLite file present
			jsonStoreFile := filepath.Join(dataDir, storeFileName)
			sqliteStoreFile := filepath.Join(dataDir, storeSqliteFileName)

			if util.FileExists(jsonStoreFile) && !util.FileExists(sqliteStoreFile) {
				log.WithContext(ctx).Warnf("unsupported store engine specified, but found %s. Automatically migrating to SQLite.", jsonStoreFile)

				// Attempt to migratePreAuto from JSON store to SQLite
				if err := MigrateFileStoreToSqlite(ctx, dataDir); err != nil {
					log.WithContext(ctx).Errorf("failed to migratePreAuto filestore to SQLite: %v", err)
					kind = types.FileStoreEngine
				}
			}
		}
	}

	return kind
}

// NewStore creates a new store based on the provided engine type, data directory, and telemetry metrics
func NewStore(ctx context.Context, kind types.Engine, dataDir string, metrics telemetry.AppMetrics, skipMigration bool) (Store, error) {
	kind = getStoreEngine(ctx, dataDir, kind)

	if err := checkFileStoreEngine(kind, dataDir); err != nil {
		return nil, err
	}

	switch kind {
	case types.SqliteStoreEngine:
		log.WithContext(ctx).Info("using SQLite store engine")
		return NewSqliteStore(ctx, dataDir, metrics, skipMigration)
	case types.PostgresStoreEngine:
		log.WithContext(ctx).Info("using Postgres store engine")
		return newPostgresStore(ctx, metrics, skipMigration)
	case types.MysqlStoreEngine:
		log.WithContext(ctx).Info("using MySQL store engine")
		return newMysqlStore(ctx, metrics, skipMigration)
	default:
		return nil, fmt.Errorf("unsupported kind of store: %s", kind)
	}
}

func checkFileStoreEngine(kind types.Engine, dataDir string) error {
	if kind == types.FileStoreEngine {
		storeFile := filepath.Join(dataDir, storeFileName)
		if util.FileExists(storeFile) {
			return fmt.Errorf("%s is not supported. Please refer to the documentation for migrating to SQLite: "+
				"https://docs.netbird.io/selfhosted/sqlite-store#migrating-from-json-store-to-sq-lite-store", types.FileStoreEngine)
		}
	}
	return nil
}

// migratePreAuto migrates the SQLite database to the latest schema
func migratePreAuto(ctx context.Context, db *gorm.DB) error {
	migrations := getMigrationsPreAuto(ctx)

	for _, m := range migrations {
		if err := m(db); err != nil {
			return err
		}
	}

	return nil
}

func getMigrationsPreAuto(ctx context.Context) []migrationFunc {
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
		func(db *gorm.DB) error {
			return migration.DropIndex[networkTypes.Network](ctx, db, "idx_networks_id")
		},
		func(db *gorm.DB) error {
			return migration.DropIndex[resourceTypes.NetworkResource](ctx, db, "idx_network_resources_id")
		},
		func(db *gorm.DB) error {
			return migration.DropIndex[routerTypes.NetworkRouter](ctx, db, "idx_network_routers_id")
		},
		func(db *gorm.DB) error {
			return migration.MigrateNewField[types.User](ctx, db, "name", "")
		},
		func(db *gorm.DB) error {
			return migration.MigrateNewField[types.User](ctx, db, "email", "")
		},
		func(db *gorm.DB) error {
			return migration.RemoveDuplicatePeerKeys(ctx, db)
		},
	}
}

// migratePostAuto migrates the SQLite database to the latest schema
func migratePostAuto(ctx context.Context, db *gorm.DB) error {
	migrations := getMigrationsPostAuto(ctx)

	for _, m := range migrations {
		if err := m(db); err != nil {
			return err
		}
	}

	return nil
}

func getMigrationsPostAuto(ctx context.Context) []migrationFunc {
	return []migrationFunc{
		func(db *gorm.DB) error {
			return migration.CreateIndexIfNotExists[nbpeer.Peer](ctx, db, "idx_account_ip", "account_id", "ip")
		},
		func(db *gorm.DB) error {
			return migration.CreateIndexIfNotExists[nbpeer.Peer](ctx, db, "idx_account_dnslabel", "account_id", "dns_label")
		},
		func(db *gorm.DB) error {
			return migration.MigrateJsonToTable[types.Group](ctx, db, "peers", func(accountID, id, value string) any {
				return &types.GroupPeer{
					AccountID: accountID,
					GroupID:   id,
					PeerID:    value,
				}
			})
		},
		func(db *gorm.DB) error {
			return migration.DropIndex[nbpeer.Peer](ctx, db, "idx_peers_key")
		},
		func(db *gorm.DB) error {
			return migration.CreateIndexIfNotExists[nbpeer.Peer](ctx, db, "idx_peers_key_unique", "key")
		},
	}
}

// NewTestStoreFromSQL is only used in tests. It will create a test database base of the store engine set in env.
// Optionally it can load a SQL file to the database. If the filename is empty it will return an empty database
func NewTestStoreFromSQL(ctx context.Context, filename string, dataDir string) (Store, func(), error) {
	kind := getStoreEngineFromEnv()
	if kind == "" {
		kind = types.SqliteStoreEngine
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
		err = LoadSQL(db, filename)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to load SQL file: %v", err)
		}
	}

	store, err := NewSqlStore(ctx, db, types.SqliteStoreEngine, nil, false)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create test store: %v", err)
	}

	err = addAllGroupToAccount(ctx, store)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to add all group to account: %v", err)
	}

	var sqlStore Store
	var cleanup func()

	maxRetries := 2
	for i := 0; i < maxRetries; i++ {
		sqlStore, cleanup, err = getSqlStoreEngine(ctx, store, kind)
		if err == nil {
			return sqlStore, cleanup, nil
		}
		if i < maxRetries-1 {
			time.Sleep(100 * time.Millisecond)
		}
	}
	return nil, nil, fmt.Errorf("failed to create test store after %d attempts: %v", maxRetries, err)
}

func addAllGroupToAccount(ctx context.Context, store Store) error {
	allAccounts := store.GetAllAccounts(ctx)
	for _, account := range allAccounts {
		shouldSave := false

		_, err := account.GetGroupAll()
		if err != nil {
			if err := account.AddAllGroup(false); err != nil {
				return err
			}
			shouldSave = true
		}

		if shouldSave {
			err = store.SaveAccount(ctx, account)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func getSqlStoreEngine(ctx context.Context, store *SqlStore, kind types.Engine) (Store, func(), error) {
	var cleanup func()
	var err error
	switch kind {
	case types.PostgresStoreEngine:
		store, cleanup, err = newReusedPostgresStore(ctx, store, kind)
	case types.MysqlStoreEngine:
		store, cleanup, err = newReusedMysqlStore(ctx, store, kind)
	default:
		cleanup = func() {
			// sqlite doesn't need to be cleaned up
		}
	}
	if err != nil {
		return nil, cleanup, fmt.Errorf("failed to create test store: %v", err)
	}

	closeConnection := func() {
		cleanup()
		store.Close(ctx)
		if store.pool != nil {
			store.pool.Close()
		}
	}

	return store, closeConnection, nil
}

func newReusedPostgresStore(ctx context.Context, store *SqlStore, kind types.Engine) (*SqlStore, func(), error) {
	dsn, ok := os.LookupEnv(postgresDsnEnv)
	if !ok || dsn == "" {
		var err error
		_, dsn, err = testutil.CreatePostgresTestContainer()
		if err != nil {
			return nil, nil, err
		}
	}

	if dsn == "" {
		return nil, nil, fmt.Errorf("%s is not set", postgresDsnEnv)
	}

	db, err := openDBWithRetry(dsn, kind, 5)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to open postgres connection: %v", err)
	}

	dsn, cleanup, err := createRandomDB(dsn, db, kind)

	sqlDB, _ := db.DB()
	if sqlDB != nil {
		sqlDB.Close()
	}

	if err != nil {
		return nil, nil, err
	}

	store, err = NewPostgresqlStoreFromSqlStore(ctx, store, dsn, nil)
	if err != nil {
		return nil, nil, err
	}

	return store, cleanup, nil
}

func newReusedMysqlStore(ctx context.Context, store *SqlStore, kind types.Engine) (*SqlStore, func(), error) {
	dsn, ok := os.LookupEnv(mysqlDsnEnv)
	if !ok || dsn == "" {
		var err error
		_, dsn, err = testutil.CreateMysqlTestContainer()
		if err != nil {
			return nil, nil, err
		}
	}

	if dsn == "" {
		return nil, nil, fmt.Errorf("%s is not set", mysqlDsnEnv)
	}

	db, err := openDBWithRetry(dsn, kind, 5)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to open mysql connection: %v", err)
	}

	sqlDB, err := db.DB()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get underlying sql.DB: %v", err)
	}
	sqlDB.SetMaxOpenConns(1)
	sqlDB.SetMaxIdleConns(1)

	dsn, cleanup, err := createRandomDB(dsn, db, kind)

	sqlDB.Close()

	if err != nil {
		return nil, nil, err
	}

	store, err = NewMysqlStoreFromSqlStore(ctx, store, dsn, nil)
	if err != nil {
		return nil, nil, err
	}

	return store, cleanup, nil
}

func openDBWithRetry(dsn string, engine types.Engine, maxRetries int) (*gorm.DB, error) {
	var db *gorm.DB
	var err error

	for i := range maxRetries {
		switch engine {
		case types.PostgresStoreEngine:
			db, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
		case types.MysqlStoreEngine:
			db, err = gorm.Open(mysql.Open(dsn+"?charset=utf8&parseTime=True&loc=Local"), &gorm.Config{})
		}

		if err == nil {
			return db, nil
		}

		if i < maxRetries-1 {
			waitTime := time.Duration(100*(i+1)) * time.Millisecond
			time.Sleep(waitTime)
		}
	}

	return nil, err
}

func createRandomDB(dsn string, db *gorm.DB, engine types.Engine) (string, func(), error) {
	dbName := fmt.Sprintf("test_db_%s", strings.ReplaceAll(uuid.New().String(), "-", "_"))

	if err := db.Exec(fmt.Sprintf("CREATE DATABASE %s", dbName)).Error; err != nil {
		return "", nil, fmt.Errorf("failed to create database: %v", err)
	}

	originalDSN := dsn

	cleanup := func() {
		var dropDB *gorm.DB
		var err error

		switch engine {
		case types.PostgresStoreEngine:
			dropDB, err = gorm.Open(postgres.Open(originalDSN), &gorm.Config{
				SkipDefaultTransaction: true,
				PrepareStmt:            false,
			})
			if err != nil {
				log.Errorf("failed to connect for dropping database %s: %v", dbName, err)
				return
			}
			defer func() {
				if sqlDB, _ := dropDB.DB(); sqlDB != nil {
					sqlDB.Close()
				}
			}()

			if sqlDB, _ := dropDB.DB(); sqlDB != nil {
				sqlDB.SetMaxOpenConns(1)
				sqlDB.SetMaxIdleConns(0)
				sqlDB.SetConnMaxLifetime(time.Second)
			}

			err = dropDB.Exec(fmt.Sprintf("DROP DATABASE IF EXISTS %s WITH (FORCE)", dbName)).Error

		case types.MysqlStoreEngine:
			dropDB, err = gorm.Open(mysql.Open(originalDSN+"?charset=utf8&parseTime=True&loc=Local"), &gorm.Config{
				SkipDefaultTransaction: true,
				PrepareStmt:            false,
			})
			if err != nil {
				log.Errorf("failed to connect for dropping database %s: %v", dbName, err)
				return
			}
			defer func() {
				if sqlDB, _ := dropDB.DB(); sqlDB != nil {
					sqlDB.Close()
				}
			}()

			if sqlDB, _ := dropDB.DB(); sqlDB != nil {
				sqlDB.SetMaxOpenConns(1)
				sqlDB.SetMaxIdleConns(0)
				sqlDB.SetConnMaxLifetime(time.Second)
			}

			err = dropDB.Exec(fmt.Sprintf("DROP DATABASE IF EXISTS %s", dbName)).Error
		}

		if err != nil {
			log.Errorf("failed to drop database %s: %v", dbName, err)
		}
	}

	return replaceDBName(dsn, dbName), cleanup, nil
}

func replaceDBName(dsn, newDBName string) string {
	re := regexp.MustCompile(`(?P<pre>[:/@])(?P<dbname>[^/?]+)(?P<post>\?|$)`)
	return re.ReplaceAllString(dsn, `${pre}`+newDBName+`${post}`)
}

func LoadSQL(db *gorm.DB, filepath string) error {
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

	store, err := NewSqliteStoreFromFileStore(ctx, fstore, dataDir, nil, true)
	if err != nil {
		return fmt.Errorf("failed creating file store: %s: %v", dataDir, err)
	}

	sqliteStoreAccounts := len(store.GetAllAccounts(ctx))
	if fsStoreAccounts != sqliteStoreAccounts {
		return fmt.Errorf("failed to migratePreAuto accounts from file to sqlite. Expected accounts: %d, got: %d",
			fsStoreAccounts, sqliteStoreAccounts)
	}

	return nil
}
