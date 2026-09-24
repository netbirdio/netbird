package store

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	nbdns "github.com/netbirdio/netbird/dns"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/types"
	nbroute "github.com/netbirdio/netbird/route"
)

func runTestForAllEngines(t *testing.T, testDataFile string, f func(t *testing.T, store Store)) {
	t.Helper()
	for _, engine := range supportedEngines {
		if os.Getenv("NETBIRD_STORE_ENGINE") != "" && os.Getenv("NETBIRD_STORE_ENGINE") != string(engine) {
			continue
		}
		t.Setenv("NETBIRD_STORE_ENGINE", string(engine))
		store, cleanUp, err := NewTestStoreFromSQL(context.Background(), testDataFile, t.TempDir())
		assert.NoError(t, err, "engine: ", string(engine))
		t.Cleanup(cleanUp)
		assert.NoError(t, err)
		t.Run(string(engine), func(t *testing.T) {
			f(t, store)
		})
		os.Unsetenv("NETBIRD_STORE_ENGINE")
	}
}

func Test_NewStore(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("The SQLite store is not properly supported by Windows yet")
	}

	runTestForAllEngines(t, "", func(t *testing.T, store Store) {
		if store == nil {
			t.Fatalf("expected to create a new Store")
		}
		if len(store.GetAllAccounts(context.Background())) != 0 {
			t.Fatalf("expected to create a new empty Accounts map when creating a new FileStore")
		}
	})
}

func TestMigrate(t *testing.T) {
	if (os.Getenv("CI") == "true" && runtime.GOOS == "darwin") || runtime.GOOS == "windows" {
		t.Skip("skip CI tests on darwin and windows")
	}

	// TODO: figure out why this fails on postgres
	t.Setenv("NETBIRD_STORE_ENGINE", string(types.SqliteStoreEngine))

	store, cleanUp, err := NewTestStoreFromSQL(context.Background(), "", t.TempDir())
	t.Cleanup(cleanUp)
	assert.NoError(t, err)

	err = migratePreAuto(context.Background(), store.(*SqlStore).db)
	require.NoError(t, err, "Migration should not fail on empty db")

	_, ipnet, err := net.ParseCIDR("10.0.0.0/24")
	require.NoError(t, err, "Failed to parse CIDR")

	type network struct {
		types.Network
		Net net.IPNet `gorm:"serializer:gob"`
	}

	type location struct {
		nbpeer.Location
		ConnectionIP net.IP
	}

	type peer struct {
		nbpeer.Peer
		Location location `gorm:"embedded;embeddedPrefix:location_"`
	}

	type account struct {
		types.Account
		Network *network `gorm:"embedded;embeddedPrefix:network_"`
		Peers   []peer   `gorm:"foreignKey:AccountID;references:id"`
	}

	act := &account{
		Network: &network{
			Net: *ipnet,
		},
		Peers: []peer{
			{Location: location{ConnectionIP: net.IP{10, 0, 0, 1}}},
		},
	}

	err = store.(*SqlStore).db.Save(act).Error
	require.NoError(t, err, "Failed to insert Gob data")

	type route struct {
		nbroute.Route
		Network    netip.Prefix `gorm:"serializer:gob"`
		PeerGroups []string     `gorm:"serializer:gob"`
	}

	prefix := netip.MustParsePrefix("11.0.0.0/24")
	rt := &route{
		Network:    prefix,
		PeerGroups: []string{"group1", "group2"},
		Route:      nbroute.Route{ID: "route1"},
	}

	err = store.(*SqlStore).db.Save(rt).Error
	require.NoError(t, err, "Failed to insert Gob data")

	err = migratePreAuto(context.Background(), store.(*SqlStore).db)
	require.NoError(t, err, "Migration should not fail on gob populated db")

	err = migratePreAuto(context.Background(), store.(*SqlStore).db)
	require.NoError(t, err, "Migration should not fail on migrated db")

	err = store.(*SqlStore).db.Delete(rt).Where("id = ?", "route1").Error
	require.NoError(t, err, "Failed to delete Gob data")

	prefix = netip.MustParsePrefix("12.0.0.0/24")
	nRT := &nbroute.Route{
		Network: prefix,
		ID:      "route2",
		Peer:    "peer-id",
	}

	err = store.(*SqlStore).db.Save(nRT).Error
	require.NoError(t, err, "Failed to insert json nil slice data")

	err = migratePreAuto(context.Background(), store.(*SqlStore).db)
	require.NoError(t, err, "Migration should not fail on json nil slice populated db")

	err = migratePreAuto(context.Background(), store.(*SqlStore).db)
	require.NoError(t, err, "Migration should not fail on migrated db")

}

func newAccount(store Store, id int) error {
	str := fmt.Sprintf("%s-%d", uuid.New().String(), id)
	account := newAccountWithId(context.Background(), str, str+"-testuser", "example.com")
	setupKey, _ := types.GenerateDefaultSetupKey()
	account.SetupKeys[setupKey.Key] = setupKey
	account.Peers["p"+str] = &nbpeer.Peer{
		Key:    "peerkey" + str,
		IP:     netip.AddrFrom4([4]byte{127, 0, 0, 1}),
		IPv6:   netip.MustParseAddr("fd00::1"),
		Meta:   nbpeer.PeerSystemMeta{},
		Name:   "peer name",
		Status: &nbpeer.PeerStatus{Connected: true, LastSeen: time.Now().UTC()},
	}

	return store.SaveAccount(context.Background(), account)
}

func TestPostgresql_NewStore(t *testing.T) {
	if (os.Getenv("CI") == "true" && runtime.GOOS == "darwin") || runtime.GOOS == "windows" {
		t.Skip("skip CI tests on darwin and windows")
	}

	t.Setenv("NETBIRD_STORE_ENGINE", string(types.PostgresStoreEngine))
	store, cleanUp, err := NewTestStoreFromSQL(context.Background(), "", t.TempDir())
	t.Cleanup(cleanUp)
	assert.NoError(t, err)

	if len(store.GetAllAccounts(context.Background())) != 0 {
		t.Errorf("expected to create a new empty Accounts map when creating a new FileStore")
	}
}

func TestSqlite_CreateAndGetObjectInTransaction(t *testing.T) {
	t.Setenv("NETBIRD_STORE_ENGINE", string(types.SqliteStoreEngine))
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/extended-store.sql", t.TempDir())
	t.Cleanup(cleanup)
	if err != nil {
		t.Fatal(err)
	}

	group := &types.Group{
		ID:        "group-id",
		AccountID: "bf1c8084-ba50-4ce7-9439-34653001fc3b",
		Name:      "group-name",
		Issued:    "api",
		Peers:     nil,
	}
	err = store.ExecuteInTransaction(context.Background(), func(transaction Store) error {
		err := transaction.CreateGroup(context.Background(), group)
		if err != nil {
			t.Fatal("failed to save group")
			return err
		}
		group, err = transaction.GetGroupByID(context.Background(), LockingStrengthUpdate, group.AccountID, group.ID)
		if err != nil {
			t.Fatal("failed to get group")
			return err
		}
		t.Logf("group: %v", group)
		return nil
	})
	assert.NoError(t, err)
}

// newAccountWithId creates a new Account with a default SetupKey (doesn't store in a Store) and provided id
func newAccountWithId(ctx context.Context, accountID, userID, domain string) *types.Account {
	log.WithContext(ctx).Debugf("creating new account")

	network := types.NewNetwork()
	peers := make(map[string]*nbpeer.Peer)
	users := make(map[string]*types.User)
	routes := make(map[nbroute.ID]*nbroute.Route)
	setupKeys := map[string]*types.SetupKey{}
	nameServersGroups := make(map[string]*nbdns.NameServerGroup)

	owner := types.NewOwnerUser(userID, "", "")
	owner.AccountID = accountID
	users[userID] = owner

	dnsSettings := types.DNSSettings{
		DisabledManagementGroups: make([]string, 0),
	}
	log.WithContext(ctx).Debugf("created new account %s", accountID)

	acc := &types.Account{
		Id:               accountID,
		CreatedAt:        time.Now().UTC(),
		SetupKeys:        setupKeys,
		Network:          network,
		Peers:            peers,
		Users:            users,
		CreatedBy:        userID,
		Domain:           domain,
		Routes:           routes,
		NameServerGroups: nameServersGroups,
		DNSSettings:      dnsSettings,
		Settings: &types.Settings{
			PeerLoginExpirationEnabled: true,
			PeerLoginExpiration:        types.DefaultPeerLoginExpiration,
			GroupsPropagationEnabled:   true,
			RegularUsersViewBlocked:    true,

			PeerInactivityExpirationEnabled: false,
			PeerInactivityExpiration:        types.DefaultPeerInactivityExpiration,
		},
		Onboarding: types.AccountOnboarding{SignupFormPending: true, OnboardingFlowPending: true},
	}

	if err := acc.AddAllGroup(false); err != nil {
		log.WithContext(ctx).Errorf("error adding all group to account %s: %v", acc.Id, err)
	}
	return acc
}

func TestSqlStore_DatabaseBlocking(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/store_with_expired_peers.sql", t.TempDir())
	t.Cleanup(cleanup)
	if err != nil {
		t.Fatal(err)
	}

	concurrentReads := 40

	testRunSuccessful := false
	wgSuccess := sync.WaitGroup{}
	wgSuccess.Add(concurrentReads)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	start := make(chan struct{})

	for i := 0; i < concurrentReads/2; i++ {
		go func() {
			t.Logf("Entered routine 1-%d", i)

			<-start
			err := store.ExecuteInTransaction(context.Background(), func(tx Store) error {
				_, err := tx.GetAccountIDByPeerID(context.Background(), LockingStrengthNone, "cfvprsrlo1hqoo49ohog")
				return err
			})
			if err != nil {
				t.Errorf("Failed, got error: %v", err)
				return
			}

			t.Log("Got User from routine 1")
			wgSuccess.Done()
		}()
	}

	for i := 0; i < concurrentReads/2; i++ {
		go func() {
			t.Logf("Entered routine 2-%d", i)

			<-start
			_, err := store.GetAccountIDByPeerID(context.Background(), LockingStrengthNone, "cfvprsrlo1hqoo49ohog")
			if err != nil {
				t.Errorf("Failed, got error: %v", err)
				return
			}

			t.Log("Got User from routine 2")
			wgSuccess.Done()
		}()
	}

	time.Sleep(200 * time.Millisecond)
	close(start)
	t.Log("Started routines")

	go func() {
		wgSuccess.Wait()
		testRunSuccessful = true
	}()

	<-ctx.Done()
	if !testRunSuccessful {
		t.Fatalf("Test failed")
	}

	t.Logf("Test completed")
}

func TestSqlStore_ExecuteInTransaction_Timeout(t *testing.T) {
	if os.Getenv("NETBIRD_STORE_ENGINE") == "mysql" {
		t.Skip("Skipping timeout test for MySQL")
	}

	t.Setenv("NB_STORE_TRANSACTION_TIMEOUT", "1s")

	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "", t.TempDir())
	require.NoError(t, err)
	t.Cleanup(cleanup)

	sqlStore, ok := store.(*SqlStore)
	require.True(t, ok)
	assert.Equal(t, 1*time.Second, sqlStore.transactionTimeout)

	ctx := context.Background()
	err = sqlStore.ExecuteInTransaction(ctx, func(transaction Store) error {
		// Sleep for 2 seconds to exceed the 1 second timeout
		time.Sleep(2 * time.Second)
		return nil
	})

	// The transaction should fail with an error (either timeout or already rolled back)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "transaction has already been committed or rolled back", "expected transaction rolled back error, got: %v", err)
}

// TestNewSqliteStore_BusyTimeoutApplied opens a fresh SQLite store and verifies
// that the _busy_timeout DSN parameter took effect at the driver level. Without
// this, lock contention on the single SQLite connection waits indefinitely on
// the Go side and can be hidden behind the 5-minute transactionTimeout.
func TestNewSqliteStore_BusyTimeoutApplied(t *testing.T) {
	dir := t.TempDir()
	store, err := NewSqliteStore(context.Background(), dir, nil, true)
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = store.Close(context.Background())
	})

	sqlDB, err := store.db.DB()
	require.NoError(t, err)
	row := sqlDB.QueryRow("PRAGMA busy_timeout")
	var busyTimeout int
	require.NoError(t, row.Scan(&busyTimeout))
	assert.Equal(t, 30000, busyTimeout, "SQLite busy_timeout must be set via DSN so it survives connection recycling")
}

// TestNewSqliteStore_BusyTimeoutRespectsUserOverride confirms that an operator
// passing _busy_timeout or its mattn alias _timeout via NB_STORE_ENGINE_SQLITE_FILE
// wins over our 30s default. This guards the DSN merge logic in NewSqliteStore.
func TestNewSqliteStore_BusyTimeoutRespectsUserOverride(t *testing.T) {
	cases := []struct {
		name     string
		envFile  string
		expected int
	}{
		{name: "explicit _busy_timeout wins", envFile: "store.db?_busy_timeout=5000", expected: 5000},
		{name: "alias _timeout wins", envFile: "store.db?_timeout=7000", expected: 7000},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("NB_STORE_ENGINE_SQLITE_FILE", tc.envFile)
			dir := t.TempDir()
			store, err := NewSqliteStore(context.Background(), dir, nil, true)
			require.NoError(t, err)
			t.Cleanup(func() {
				_ = store.Close(context.Background())
			})

			sqlDB, err := store.db.DB()
			require.NoError(t, err)
			row := sqlDB.QueryRow("PRAGMA busy_timeout")
			var busyTimeout int
			require.NoError(t, row.Scan(&busyTimeout))
			assert.Equal(t, tc.expected, busyTimeout)
		})
	}
}
