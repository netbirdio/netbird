package store

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"os"
	"reflect"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	nbdns "github.com/netbirdio/netbird/dns"
	proxydomain "github.com/netbirdio/netbird/management/internals/modules/reverseproxy/domain"
	rpservice "github.com/netbirdio/netbird/management/internals/modules/reverseproxy/service"
	resourceTypes "github.com/netbirdio/netbird/management/server/networks/resources/types"
	routerTypes "github.com/netbirdio/netbird/management/server/networks/routers/types"
	networkTypes "github.com/netbirdio/netbird/management/server/networks/types"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/types"
	nbroute "github.com/netbirdio/netbird/route"
	"github.com/netbirdio/netbird/shared/management/status"
	"github.com/netbirdio/netbird/shared/testing_helpers"
)

func Test_SaveAccount_Large(t *testing.T) {
	if (os.Getenv("CI") == "true" && runtime.GOOS == "darwin") || runtime.GOOS == "windows" {
		t.Skip("skip CI tests on darwin and windows")
	}

	runTestForAllEngines(t, "", func(t *testing.T, store Store) {
		runLargeTest(t, store)
	})
}

func runLargeTest(t *testing.T, store Store) {
	t.Helper()

	account := newAccountWithId(context.Background(), "account_id", "testuser", "")
	groupALL, err := account.GetGroupAll()
	if err != nil {
		t.Fatal(err)
	}
	setupKey, _ := types.GenerateDefaultSetupKey()
	account.SetupKeys[setupKey.Key] = setupKey
	const numPerAccount = 6000
	for n := 0; n < numPerAccount; n++ {
		netIP := sequentialIPv4(n)
		peerID := fmt.Sprintf("%s-peer-%d", account.Id, n)
		addr, _ := netip.AddrFromSlice(netIP)

		peer := &nbpeer.Peer{
			ID:         peerID,
			Key:        peerID,
			IP:         addr.Unmap(),
			Name:       peerID,
			DNSLabel:   peerID,
			UserID:     "testuser",
			Status:     &nbpeer.PeerStatus{Connected: false, LastSeen: time.Now()},
			SSHEnabled: false,
		}
		account.Peers[peerID] = peer
		group, _ := account.GetGroupAll()
		group.Peers = append(group.Peers, peerID)
		user := &types.User{
			Id:        fmt.Sprintf("%s-user-%d", account.Id, n),
			AccountID: account.Id,
		}
		account.Users[user.Id] = user
		route := &nbroute.Route{
			ID:          nbroute.ID(fmt.Sprintf("network-id-%d", n)),
			Description: "base route",
			NetID:       nbroute.NetID(fmt.Sprintf("network-id-%d", n)),
			Network:     netip.MustParsePrefix(netIP.String() + "/24"),
			NetworkType: nbroute.IPv4Network,
			Metric:      9999,
			Masquerade:  false,
			Enabled:     true,
			Groups:      []string{groupALL.ID},
		}
		account.Routes[route.ID] = route

		group = &types.Group{
			ID:        fmt.Sprintf("group-id-%d", n),
			AccountID: account.Id,
			Name:      fmt.Sprintf("group-id-%d", n),
			Issued:    "api",
			Peers:     nil,
		}
		account.Groups[group.ID] = group

		nameserver := &nbdns.NameServerGroup{
			ID:                   fmt.Sprintf("nameserver-id-%d", n),
			AccountID:            account.Id,
			Name:                 fmt.Sprintf("nameserver-id-%d", n),
			Description:          "",
			NameServers:          []nbdns.NameServer{{IP: netip.MustParseAddr(netIP.String()), NSType: nbdns.UDPNameServerType}},
			Groups:               []string{group.ID},
			Primary:              false,
			Domains:              nil,
			Enabled:              false,
			SearchDomainsEnabled: false,
		}
		account.NameServerGroups[nameserver.ID] = nameserver

		setupKey, _ := types.GenerateDefaultSetupKey()
		_, exists := account.SetupKeys[setupKey.Key]
		if exists {
			t.Errorf("setup key already exists")
		}
		account.SetupKeys[setupKey.Key] = setupKey
	}

	err = store.SaveAccount(context.Background(), account)
	require.NoError(t, err)

	if len(store.GetAllAccounts(context.Background())) != 1 {
		t.Errorf("expecting 1 Accounts to be stored after SaveAccount()")
	}

	a, err := store.GetAccount(context.Background(), account.Id)
	if a == nil {
		t.Errorf("expecting Account to be stored after SaveAccount(): %v", err)
	}

	if a != nil && len(a.Policies) != 1 {
		t.Errorf("expecting Account to have one policy stored after SaveAccount(), got %d", len(a.Policies))
	}

	if a != nil && len(a.Policies[0].Rules) != 1 {
		t.Errorf("expecting Account to have one policy rule stored after SaveAccount(), got %d", len(a.Policies[0].Rules))
		return
	}

	if a != nil && len(a.Peers) != numPerAccount {
		t.Errorf("expecting Account to have %d peers stored after SaveAccount(), got %d",
			numPerAccount, len(a.Peers))
		return
	}

	if a != nil && len(a.Users) != numPerAccount+1 {
		t.Errorf("expecting Account to have %d users stored after SaveAccount(), got %d",
			numPerAccount+1, len(a.Users))
		return
	}

	if a != nil && len(a.Routes) != numPerAccount {
		t.Errorf("expecting Account to have %d routes stored after SaveAccount(), got %d",
			numPerAccount, len(a.Routes))
		return
	}

	if a != nil && len(a.NameServerGroups) != numPerAccount {
		t.Errorf("expecting Account to have %d NameServerGroups stored after SaveAccount(), got %d",
			numPerAccount, len(a.NameServerGroups))
		return
	}

	if a != nil && len(a.NameServerGroups) != numPerAccount {
		t.Errorf("expecting Account to have %d NameServerGroups stored after SaveAccount(), got %d",
			numPerAccount, len(a.NameServerGroups))
		return
	}

	if a != nil && len(a.SetupKeys) != numPerAccount+1 {
		t.Errorf("expecting Account to have %d SetupKeys stored after SaveAccount(), got %d",
			numPerAccount+1, len(a.SetupKeys))
		return
	}
}

// sequentialIPv4 returns a unique IPv4 address for the given index, avoiding
// the random collisions that would otherwise violate the unique (account_id, ip)
// index when generating a large number of peers.
func sequentialIPv4(n int) net.IP {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, 0x0A000000+uint32(n))
	return net.IP(b)
}

func Test_SaveAccount(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("The SQLite store is not properly supported by Windows yet")
	}

	runTestForAllEngines(t, "", func(t *testing.T, store Store) {
		account := newAccountWithId(context.Background(), "account_id", "testuser", "")
		setupKey, _ := types.GenerateDefaultSetupKey()
		account.SetupKeys[setupKey.Key] = setupKey
		account.Peers["testpeer"] = &nbpeer.Peer{
			Key:    "peerkey",
			IP:     netip.AddrFrom4([4]byte{127, 0, 0, 1}),
			IPv6:   netip.MustParseAddr("fd00::1"),
			Meta:   nbpeer.PeerSystemMeta{},
			Name:   "peer name",
			Status: &nbpeer.PeerStatus{Connected: true, LastSeen: time.Now().UTC()},
		}

		err := store.SaveAccount(context.Background(), account)
		require.NoError(t, err)

		account2 := newAccountWithId(context.Background(), "account_id2", "testuser2", "")
		setupKey, _ = types.GenerateDefaultSetupKey()
		account2.SetupKeys[setupKey.Key] = setupKey
		account2.Peers["testpeer2"] = &nbpeer.Peer{
			Key:    "peerkey2",
			IP:     netip.AddrFrom4([4]byte{127, 0, 0, 2}),
			IPv6:   netip.MustParseAddr("fd00::2"),
			Meta:   nbpeer.PeerSystemMeta{},
			Name:   "peer name 2",
			Status: &nbpeer.PeerStatus{Connected: true, LastSeen: time.Now().UTC()},
		}

		err = store.SaveAccount(context.Background(), account2)
		require.NoError(t, err)

		if len(store.GetAllAccounts(context.Background())) != 2 {
			t.Errorf("expecting 2 Accounts to be stored after SaveAccount()")
		}

		a, err := store.GetAccount(context.Background(), account.Id)
		if a == nil {
			t.Errorf("expecting Account to be stored after SaveAccount(): %v", err)
		}

		if a != nil && len(a.Policies) != 1 {
			t.Errorf("expecting Account to have one policy stored after SaveAccount(), got %d", len(a.Policies))
		}

		if a != nil && len(a.Policies[0].Rules) != 1 {
			t.Errorf("expecting Account to have one policy rule stored after SaveAccount(), got %d", len(a.Policies[0].Rules))
			return
		}

		if a, err := store.GetAccountByPeerPubKey(context.Background(), "peerkey"); a == nil {
			t.Errorf("expecting PeerKeyID2AccountID index updated after SaveAccount(): %v", err)
		}

		if a, err := store.GetAccountByUser(context.Background(), "testuser"); a == nil {
			t.Errorf("expecting UserID2AccountID index updated after SaveAccount(): %v", err)
		}

		if a, err := store.GetAccountByPeerID(context.Background(), "testpeer"); a == nil {
			t.Errorf("expecting PeerID2AccountID index updated after SaveAccount(): %v", err)
		}

		if a, err := store.GetAccountBySetupKey(context.Background(), setupKey.Key); a == nil {
			t.Errorf("expecting SetupKeyID2AccountID index updated after SaveAccount(): %v", err)
		}
	})
}

func Test_AccountSettings_SaveAndRetrieve(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("The SQLite store is not properly supported by Windows yet")
	}

	populateFields := testing_helpers.NewPopulateFields().WithCustomFieldSetter(
		reflect.PointerTo(reflect.TypeOf(types.ExtraSettings{})), func(this *testing_helpers.PopulateFields, field reflect.Value) (int, error) {
			es := types.ExtraSettings{}
			reflectedEs := reflect.ValueOf(&es).Elem()
			n, err := this.PopulateAll(reflectedEs)
			if err != nil {
				return n, err
			}
			field.Set(reflectedEs.Addr())
			return n, nil
		}).WithCustomFieldSetter(
		reflect.PointerTo(reflect.TypeOf(types.DashboardFeatures{})), func(this *testing_helpers.PopulateFields, field reflect.Value) (int, error) {
			t := true
			df := types.DashboardFeatures{AgentNetwork: &t}
			reflectedDf := reflect.ValueOf(&df).Elem()
			field.Set(reflectedDf.Addr())
			return 1, nil
		}).WithSkippedTag("gorm", "-")

	runTestForAllEngines(t, "", func(t *testing.T, store Store) {
		account := newAccountWithId(context.Background(), "account_id", "testuser", "")
		setupKey, _ := types.GenerateDefaultSetupKey()
		account.SetupKeys[setupKey.Key] = setupKey

		settings := types.Settings{}
		numOfExportedFields, err := populateFields.PopulateAll(reflect.ValueOf(&settings).Elem())
		assert.NoError(t, err)
		assert.Equal(t, 27, numOfExportedFields)
		account.Settings = &settings

		err = store.SaveAccount(context.Background(), account)
		assert.NoError(t, err)

		accountFromDb, err := store.GetAccount(context.Background(), account.Id)
		assert.NoError(t, err)
		assert.NotNil(t, accountFromDb)
		assert.NotNil(t, accountFromDb.Settings)

		assert.True(t, reflect.DeepEqual(&settings, accountFromDb.Settings), "created settings and settings retrieved from the db should match")
	})
}

func TestSqlite_DeleteAccount(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("The SQLite store is not properly supported by Windows yet")
	}

	t.Setenv("NETBIRD_STORE_ENGINE", string(types.SqliteStoreEngine))
	store, cleanUp, err := NewTestStoreFromSQL(context.Background(), "", t.TempDir())
	t.Cleanup(cleanUp)
	assert.NoError(t, err)

	testUserID := "testuser"
	user := types.NewAdminUser(testUserID)
	user.PATs = map[string]*types.PersonalAccessToken{"testtoken": {
		ID:   "testtoken",
		Name: "test token",
	}}

	account := newAccountWithId(context.Background(), "account_id", testUserID, "")
	setupKey, _ := types.GenerateDefaultSetupKey()
	account.SetupKeys[setupKey.Key] = setupKey
	account.Peers["testpeer"] = &nbpeer.Peer{
		Key:    "peerkey",
		IP:     netip.AddrFrom4([4]byte{127, 0, 0, 1}),
		IPv6:   netip.MustParseAddr("fd00::1"),
		Meta:   nbpeer.PeerSystemMeta{},
		Name:   "peer name",
		Status: &nbpeer.PeerStatus{Connected: true, LastSeen: time.Now().UTC()},
	}
	account.Users[testUserID] = user
	account.Networks = []*networkTypes.Network{
		{
			ID:          "network_id",
			AccountID:   account.Id,
			Name:        "network name",
			Description: "network description",
		},
	}
	account.NetworkRouters = []*routerTypes.NetworkRouter{
		{
			ID:         "router_id",
			NetworkID:  account.Networks[0].ID,
			AccountID:  account.Id,
			PeerGroups: []string{"group_id"},
			Masquerade: true,
			Metric:     1,
		},
	}
	account.NetworkResources = []*resourceTypes.NetworkResource{
		{
			ID:          "resource_id",
			NetworkID:   account.Networks[0].ID,
			AccountID:   account.Id,
			Name:        "Name",
			Description: "Description",
			Type:        "Domain",
			Address:     "example.com",
		},
	}

	account.Services = []*rpservice.Service{
		{
			ID:        "service_id",
			AccountID: account.Id,
			Name:      "test service",
			Domain:    "svc.example.com",
			Enabled:   true,
			Targets: []*rpservice.Target{
				{
					AccountID: account.Id,
					ServiceID: "service_id",
					Host:      "localhost",
					Port:      8080,
					Protocol:  "http",
					Enabled:   true,
				},
			},
		},
	}

	account.Domains = []*proxydomain.Domain{
		{
			ID:        "domain_id",
			Domain:    "custom.example.com",
			AccountID: account.Id,
			Validated: true,
		},
	}

	err = store.SaveAccount(context.Background(), account)
	require.NoError(t, err)

	if len(store.GetAllAccounts(context.Background())) != 1 {
		t.Errorf("expecting 1 Accounts to be stored after SaveAccount()")
	}

	o, err := store.GetAccountOnboarding(context.Background(), account.Id)
	require.NoError(t, err)
	require.Equal(t, o.AccountID, account.Id)

	err = store.DeleteAccount(context.Background(), account)
	require.NoError(t, err)

	_, err = store.GetAccountOnboarding(context.Background(), account.Id)
	require.Error(t, err, "expecting error after removing DeleteAccount when getting onboarding")

	if len(store.GetAllAccounts(context.Background())) != 0 {
		t.Errorf("expecting 0 Accounts to be stored after DeleteAccount()")
	}

	_, err = store.GetAccountByPeerPubKey(context.Background(), "peerkey")
	require.Error(t, err, "expecting error after removing DeleteAccount when getting account by peer public key")

	_, err = store.GetAccountByUser(context.Background(), "testuser")
	require.Error(t, err, "expecting error after removing DeleteAccount when getting account by user")

	_, err = store.GetAccountByPeerID(context.Background(), "testpeer")
	require.Error(t, err, "expecting error after removing DeleteAccount when getting account by peer id")

	_, err = store.GetAccountBySetupKey(context.Background(), setupKey.Key)
	require.Error(t, err, "expecting error after removing DeleteAccount when getting account by setup key")

	_, err = store.GetAccount(context.Background(), account.Id)
	require.Error(t, err, "expecting error after removing DeleteAccount when getting account by id")

	for _, policy := range account.Policies {
		var rules []*types.PolicyRule
		err = store.(*SqlStore).db.Model(&types.PolicyRule{}).Find(&rules, "policy_id = ?", policy.ID).Error
		require.NoError(t, err, "expecting no error after removing DeleteAccount when searching for policy rules")
		require.Len(t, rules, 0, "expecting no policy rules to be found after removing DeleteAccount")

	}

	for _, accountUser := range account.Users {
		var pats []*types.PersonalAccessToken
		err = store.(*SqlStore).db.Model(&types.PersonalAccessToken{}).Find(&pats, "user_id = ?", accountUser.Id).Error
		require.NoError(t, err, "expecting no error after removing DeleteAccount when searching for personal access token")
		require.Len(t, pats, 0, "expecting no personal access token to be found after removing DeleteAccount")

	}

	for _, network := range account.Networks {
		routers, err := store.GetNetworkRoutersByNetID(context.Background(), LockingStrengthNone, account.Id, network.ID)
		require.NoError(t, err, "expecting no error after removing DeleteAccount when searching for network routers")
		require.Len(t, routers, 0, "expecting no network routers to be found after DeleteAccount")

		resources, err := store.GetNetworkResourcesByNetID(context.Background(), LockingStrengthNone, account.Id, network.ID)
		require.NoError(t, err, "expecting no error after removing DeleteAccount when searching for network resources")
		require.Len(t, resources, 0, "expecting no network resources to be found after DeleteAccount")
	}

	domains, err := store.ListCustomDomains(context.Background(), account.Id)
	require.NoError(t, err, "expecting no error after DeleteAccount when searching for custom domains")
	require.Len(t, domains, 0, "expecting no custom domains to be found after DeleteAccount")

	var services []*rpservice.Service
	err = store.(*SqlStore).db.Model(&rpservice.Service{}).Find(&services, "account_id = ?", account.Id).Error
	require.NoError(t, err, "expecting no error after DeleteAccount when searching for services")
	require.Len(t, services, 0, "expecting no services to be found after DeleteAccount")

	var targets []*rpservice.Target
	err = store.(*SqlStore).db.Model(&rpservice.Target{}).Find(&targets, "account_id = ?", account.Id).Error
	require.NoError(t, err, "expecting no error after DeleteAccount when searching for service targets")
	require.Len(t, targets, 0, "expecting no service targets to be found after DeleteAccount")
}

func Test_GetAccount(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("The SQLite store is not properly supported by Windows yet")
	}

	runTestForAllEngines(t, "../testdata/store.sql", func(t *testing.T, store Store) {
		id := "bf1c8084-ba50-4ce7-9439-34653001fc3b"

		account, err := store.GetAccount(context.Background(), id)
		require.NoError(t, err)
		require.Equal(t, id, account.Id, "account id should match")
		require.Equal(t, false, account.Onboarding.OnboardingFlowPending)

		id = "9439-34653001fc3b-bf1c8084-ba50-4ce7"

		account, err = store.GetAccount(context.Background(), id)
		require.NoError(t, err)
		require.Equal(t, id, account.Id, "account id should match")
		require.Equal(t, true, account.Onboarding.OnboardingFlowPending)

		_, err = store.GetAccount(context.Background(), "non-existing-account")
		assert.Error(t, err)
		parsedErr, ok := status.FromError(err)
		require.True(t, ok)
		require.Equal(t, status.NotFound, parsedErr.Type(), "should return not found error")

	})
}

func Test_TestGetAccountByPrivateDomain(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("The SQLite store is not properly supported by Windows yet")
	}

	runTestForAllEngines(t, "../testdata/store.sql", func(t *testing.T, store Store) {
		existingDomain := "test.com"

		account, err := store.GetAccountByPrivateDomain(context.Background(), existingDomain)
		require.NoError(t, err, "should found account")
		require.Equal(t, existingDomain, account.Domain, "domains should match")

		_, err = store.GetAccountByPrivateDomain(context.Background(), "missing-domain.com")
		require.Error(t, err, "should return error on domain lookup")
		parsedErr, ok := status.FromError(err)
		require.True(t, ok)
		require.Equal(t, status.NotFound, parsedErr.Type(), "should return not found error")
	})
}

func TestPostgresql_SaveAccount(t *testing.T) {
	if (os.Getenv("CI") == "true" && runtime.GOOS == "darwin") || runtime.GOOS == "windows" {
		t.Skip("skip CI tests on darwin and windows")
	}

	t.Setenv("NETBIRD_STORE_ENGINE", string(types.PostgresStoreEngine))
	store, cleanUp, err := NewTestStoreFromSQL(context.Background(), "", t.TempDir())
	t.Cleanup(cleanUp)
	assert.NoError(t, err)

	account := newAccountWithId(context.Background(), "account_id", "testuser", "")
	setupKey, _ := types.GenerateDefaultSetupKey()
	account.SetupKeys[setupKey.Key] = setupKey
	account.Peers["testpeer"] = &nbpeer.Peer{
		Key:    "peerkey",
		IP:     netip.AddrFrom4([4]byte{127, 0, 0, 1}),
		IPv6:   netip.MustParseAddr("fd00::1"),
		Meta:   nbpeer.PeerSystemMeta{},
		Name:   "peer name",
		Status: &nbpeer.PeerStatus{Connected: true, LastSeen: time.Now().UTC()},
	}

	err = store.SaveAccount(context.Background(), account)
	require.NoError(t, err)

	account2 := newAccountWithId(context.Background(), "account_id2", "testuser2", "")
	setupKey, _ = types.GenerateDefaultSetupKey()
	account2.SetupKeys[setupKey.Key] = setupKey
	account2.Peers["testpeer2"] = &nbpeer.Peer{
		Key:    "peerkey2",
		IP:     netip.AddrFrom4([4]byte{127, 0, 0, 2}),
		IPv6:   netip.MustParseAddr("fd00::2"),
		Meta:   nbpeer.PeerSystemMeta{},
		Name:   "peer name 2",
		Status: &nbpeer.PeerStatus{Connected: true, LastSeen: time.Now().UTC()},
	}

	err = store.SaveAccount(context.Background(), account2)
	require.NoError(t, err)

	if len(store.GetAllAccounts(context.Background())) != 2 {
		t.Errorf("expecting 2 Accounts to be stored after SaveAccount()")
	}

	a, err := store.GetAccount(context.Background(), account.Id)
	if a == nil {
		t.Errorf("expecting Account to be stored after SaveAccount(): %v", err)
	}

	if a != nil && len(a.Policies) != 1 {
		t.Errorf("expecting Account to have one policy stored after SaveAccount(), got %d", len(a.Policies))
	}

	if a != nil && len(a.Policies[0].Rules) != 1 {
		t.Errorf("expecting Account to have one policy rule stored after SaveAccount(), got %d", len(a.Policies[0].Rules))
		return
	}

	if a, err := store.GetAccountByPeerPubKey(context.Background(), "peerkey"); a == nil {
		t.Errorf("expecting PeerKeyID2AccountID index updated after SaveAccount(): %v", err)
	}

	if a, err := store.GetAccountByUser(context.Background(), "testuser"); a == nil {
		t.Errorf("expecting UserID2AccountID index updated after SaveAccount(): %v", err)
	}

	if a, err := store.GetAccountByPeerID(context.Background(), "testpeer"); a == nil {
		t.Errorf("expecting PeerID2AccountID index updated after SaveAccount(): %v", err)
	}

	if a, err := store.GetAccountBySetupKey(context.Background(), setupKey.Key); a == nil {
		t.Errorf("expecting SetupKeyID2AccountID index updated after SaveAccount(): %v", err)
	}
}

func TestPostgresql_DeleteAccount(t *testing.T) {
	if (os.Getenv("CI") == "true" && runtime.GOOS == "darwin") || runtime.GOOS == "windows" {
		t.Skip("skip CI tests on darwin and windows")
	}

	t.Setenv("NETBIRD_STORE_ENGINE", string(types.PostgresStoreEngine))
	store, cleanUp, err := NewTestStoreFromSQL(context.Background(), "", t.TempDir())
	t.Cleanup(cleanUp)
	assert.NoError(t, err)

	testUserID := "testuser"
	user := types.NewAdminUser(testUserID)
	user.PATs = map[string]*types.PersonalAccessToken{"testtoken": {
		ID:   "testtoken",
		Name: "test token",
	}}

	account := newAccountWithId(context.Background(), "account_id", testUserID, "")
	setupKey, _ := types.GenerateDefaultSetupKey()
	account.SetupKeys[setupKey.Key] = setupKey
	account.Peers["testpeer"] = &nbpeer.Peer{
		Key:    "peerkey",
		IP:     netip.AddrFrom4([4]byte{127, 0, 0, 1}),
		IPv6:   netip.MustParseAddr("fd00::1"),
		Meta:   nbpeer.PeerSystemMeta{},
		Name:   "peer name",
		Status: &nbpeer.PeerStatus{Connected: true, LastSeen: time.Now().UTC()},
	}
	account.Users[testUserID] = user

	err = store.SaveAccount(context.Background(), account)
	require.NoError(t, err)

	if len(store.GetAllAccounts(context.Background())) != 1 {
		t.Errorf("expecting 1 Accounts to be stored after SaveAccount()")
	}

	err = store.DeleteAccount(context.Background(), account)
	require.NoError(t, err)

	if len(store.GetAllAccounts(context.Background())) != 0 {
		t.Errorf("expecting 0 Accounts to be stored after DeleteAccount()")
	}

	_, err = store.GetAccountByPeerPubKey(context.Background(), "peerkey")
	require.Error(t, err, "expecting error after removing DeleteAccount when getting account by peer public key")

	_, err = store.GetAccountByUser(context.Background(), "testuser")
	require.Error(t, err, "expecting error after removing DeleteAccount when getting account by user")

	_, err = store.GetAccountByPeerID(context.Background(), "testpeer")
	require.Error(t, err, "expecting error after removing DeleteAccount when getting account by peer id")

	_, err = store.GetAccountBySetupKey(context.Background(), setupKey.Key)
	require.Error(t, err, "expecting error after removing DeleteAccount when getting account by setup key")

	_, err = store.GetAccount(context.Background(), account.Id)
	require.Error(t, err, "expecting error after removing DeleteAccount when getting account by id")

	for _, policy := range account.Policies {
		var rules []*types.PolicyRule
		err = store.(*SqlStore).db.Model(&types.PolicyRule{}).Find(&rules, "policy_id = ?", policy.ID).Error
		require.NoError(t, err, "expecting no error after removing DeleteAccount when searching for policy rules")
		require.Len(t, rules, 0, "expecting no policy rules to be found after removing DeleteAccount")

	}

	for _, accountUser := range account.Users {
		var pats []*types.PersonalAccessToken
		err = store.(*SqlStore).db.Model(&types.PersonalAccessToken{}).Find(&pats, "user_id = ?", accountUser.Id).Error
		require.NoError(t, err, "expecting no error after removing DeleteAccount when searching for personal access token")
		require.Len(t, pats, 0, "expecting no personal access token to be found after removing DeleteAccount")

	}

}

func TestPostgresql_TestGetAccountByPrivateDomain(t *testing.T) {
	if (os.Getenv("CI") == "true" && runtime.GOOS == "darwin") || runtime.GOOS == "windows" {
		t.Skip("skip CI tests on darwin and windows")
	}

	t.Setenv("NETBIRD_STORE_ENGINE", string(types.PostgresStoreEngine))
	store, cleanUp, err := NewTestStoreFromSQL(context.Background(), "../testdata/store.sql", t.TempDir())
	t.Cleanup(cleanUp)
	assert.NoError(t, err)

	existingDomain := "test.com"

	account, err := store.GetAccountByPrivateDomain(context.Background(), existingDomain)
	require.NoError(t, err, "should found account")
	require.Equal(t, existingDomain, account.Domain, "domains should match")

	_, err = store.GetAccountByPrivateDomain(context.Background(), "missing-domain.com")
	require.Error(t, err, "should return error on domain lookup")
}

func TestSqlite_GetAccountNetwork(t *testing.T) {
	t.Setenv("NETBIRD_STORE_ENGINE", string(types.SqliteStoreEngine))
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/extended-store.sql", t.TempDir())
	t.Cleanup(cleanup)
	if err != nil {
		t.Fatal(err)
	}

	existingAccountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"

	_, err = store.GetAccount(context.Background(), existingAccountID)
	require.NoError(t, err)

	network, err := store.GetAccountNetwork(context.Background(), LockingStrengthNone, existingAccountID)
	require.NoError(t, err)
	ip := net.IP{100, 64, 0, 0}.To16()
	assert.Equal(t, ip, network.Net.IP)
	assert.Equal(t, net.IPMask{255, 255, 0, 0}, network.Net.Mask)
	assert.Equal(t, "", network.Dns)
	assert.Equal(t, "af1c8024-ha40-4ce2-9418-34653101fc3c", network.Identifier)
	assert.Equal(t, uint64(0), network.Serial)
}

func TestSqlStore_SaveAccountPersistsAgentNetworkOnly(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"
	account, err := store.GetAccount(context.Background(), accountID)
	require.NoError(t, err)
	require.False(t, account.Settings.AgentNetworkOnly, "setting should default to false")

	account.Settings.AgentNetworkOnly = true
	require.NoError(t, store.SaveAccount(context.Background(), account))

	reloaded, err := store.GetAccount(context.Background(), accountID)
	require.NoError(t, err)
	require.True(t, reloaded.Settings.AgentNetworkOnly, "setting should survive a save/load round-trip")

	reloaded.Settings.AgentNetworkOnly = false
	require.NoError(t, store.SaveAccount(context.Background(), reloaded))

	disabled, err := store.GetAccount(context.Background(), accountID)
	require.NoError(t, err)
	require.False(t, disabled.Settings.AgentNetworkOnly, "disabling should persist")
}

func TestSqlStore_SaveAccountPersistsDashboardFeatures(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"
	account, err := store.GetAccount(context.Background(), accountID)
	require.NoError(t, err)
	require.Nil(t, account.Settings.DashboardFeatures, "dashboard features should default to unset")

	agentNetwork := true
	account.Settings.DashboardFeatures = &types.DashboardFeatures{AgentNetwork: &agentNetwork}
	require.NoError(t, store.SaveAccount(context.Background(), account))

	reloaded, err := store.GetAccount(context.Background(), accountID)
	require.NoError(t, err)
	require.NotNil(t, reloaded.Settings.DashboardFeatures, "dashboard features should survive a save/load round-trip")
	require.NotNil(t, reloaded.Settings.DashboardFeatures.AgentNetwork, "agent network flag should be set")
	require.True(t, *reloaded.Settings.DashboardFeatures.AgentNetwork, "agent network flag should persist as true")

	disabled := false
	reloaded.Settings.DashboardFeatures = &types.DashboardFeatures{AgentNetwork: &disabled}
	require.NoError(t, store.SaveAccount(context.Background(), reloaded))

	reloadedDisabled, err := store.GetAccount(context.Background(), accountID)
	require.NoError(t, err)
	require.NotNil(t, reloadedDisabled.Settings.DashboardFeatures.AgentNetwork, "agent network flag should remain set")
	require.False(t, *reloadedDisabled.Settings.DashboardFeatures.AgentNetwork, "explicit false should persist")
}

func TestSqlStore_UpdateAccountDomainAttributes(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/extended-store.sql", t.TempDir())
	t.Cleanup(cleanup)
	if err != nil {
		t.Fatal(err)
	}
	accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"
	t.Run("Should update attributes with public domain", func(t *testing.T) {
		require.NoError(t, err)
		domain := "example.com"
		category := "public"
		IsDomainPrimaryAccount := false
		err = store.UpdateAccountDomainAttributes(context.Background(), accountID, domain, category, IsDomainPrimaryAccount)
		require.NoError(t, err)
		account, err := store.GetAccount(context.Background(), accountID)
		require.NoError(t, err)
		require.Equal(t, domain, account.Domain)
		require.Equal(t, category, account.DomainCategory)
		require.Equal(t, IsDomainPrimaryAccount, account.IsDomainPrimaryAccount)
	})

	t.Run("Should update attributes with private domain", func(t *testing.T) {
		require.NoError(t, err)
		domain := "test.com"
		category := "private"
		IsDomainPrimaryAccount := true
		err = store.UpdateAccountDomainAttributes(context.Background(), accountID, domain, category, IsDomainPrimaryAccount)
		require.NoError(t, err)
		account, err := store.GetAccount(context.Background(), accountID)
		require.NoError(t, err)
		require.Equal(t, domain, account.Domain)
		require.Equal(t, category, account.DomainCategory)
		require.Equal(t, IsDomainPrimaryAccount, account.IsDomainPrimaryAccount)
	})

	t.Run("Should fail when account does not exist", func(t *testing.T) {
		require.NoError(t, err)
		domain := "test.com"
		category := "private"
		IsDomainPrimaryAccount := true
		err = store.UpdateAccountDomainAttributes(context.Background(), "non-existing-account-id", domain, category, IsDomainPrimaryAccount)
		require.Error(t, err)
	})

}

func TestSqlStore_GetDNSSettings(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	tests := []struct {
		name        string
		accountID   string
		expectError bool
	}{
		{
			name:        "retrieve existing account dns settings",
			accountID:   "bf1c8084-ba50-4ce7-9439-34653001fc3b",
			expectError: false,
		},
		{
			name:        "retrieve non-existing account dns settings",
			accountID:   "non-existing",
			expectError: true,
		},
		{
			name:        "retrieve dns settings with empty account ID",
			accountID:   "",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dnsSettings, err := store.GetAccountDNSSettings(context.Background(), LockingStrengthNone, tt.accountID)
			if tt.expectError {
				require.Error(t, err)
				sErr, ok := status.FromError(err)
				require.True(t, ok)
				require.Equal(t, sErr.Type(), status.NotFound)
				require.Nil(t, dnsSettings)
			} else {
				require.NoError(t, err)
				require.NotNil(t, dnsSettings)
			}
		})
	}
}

func TestSqlStore_SaveDNSSettings(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"

	dnsSettings, err := store.GetAccountDNSSettings(context.Background(), LockingStrengthNone, accountID)
	require.NoError(t, err)

	dnsSettings.DisabledManagementGroups = []string{"groupA", "groupB"}
	err = store.SaveDNSSettings(context.Background(), accountID, dnsSettings)
	require.NoError(t, err)

	saveDNSSettings, err := store.GetAccountDNSSettings(context.Background(), LockingStrengthNone, accountID)
	require.NoError(t, err)
	require.Equal(t, saveDNSSettings, dnsSettings)
}

func TestSqlStore_GetAccountCreatedBy(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	tests := []struct {
		name        string
		accountID   string
		expectError bool
		createdBy   string
	}{
		{
			name:        "existing account ID",
			accountID:   "bf1c8084-ba50-4ce7-9439-34653001fc3b",
			expectError: false,
			createdBy:   "edafee4e-63fb-11ec-90d6-0242ac120003",
		},
		{
			name:        "non-existing account ID",
			accountID:   "nonexistent",
			expectError: true,
		},
		{
			name:        "empty account ID",
			accountID:   "",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			createdBy, err := store.GetAccountCreatedBy(context.Background(), LockingStrengthNone, tt.accountID)
			if tt.expectError {
				require.Error(t, err)
				sErr, ok := status.FromError(err)
				require.True(t, ok)
				require.Equal(t, sErr.Type(), status.NotFound)
				require.Empty(t, createdBy)
			} else {
				require.NoError(t, err)
				require.NotNil(t, createdBy)
				require.Equal(t, tt.createdBy, createdBy)
			}
		})
	}

}

func TestSqlStore_GetAccountMeta(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/extended-store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"
	accountMeta, err := store.GetAccountMeta(context.Background(), LockingStrengthNone, accountID)
	require.NoError(t, err)
	require.NotNil(t, accountMeta)
	require.Equal(t, accountID, accountMeta.AccountID)
	require.Equal(t, "edafee4e-63fb-11ec-90d6-0242ac120003", accountMeta.CreatedBy)
	require.Equal(t, "test.com", accountMeta.Domain)
	require.Equal(t, "private", accountMeta.DomainCategory)
	require.Equal(t, time.Date(2024, time.October, 2, 14, 1, 38, 210000000, time.UTC), accountMeta.CreatedAt.UTC())
}

func TestSqlStore_GetAnyAccountID(t *testing.T) {
	t.Run("should return account ID when accounts exist", func(t *testing.T) {
		store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/extended-store.sql", t.TempDir())
		t.Cleanup(cleanup)
		require.NoError(t, err)

		accountID, err := store.GetAnyAccountID(context.Background())
		require.NoError(t, err)
		assert.Equal(t, "bf1c8084-ba50-4ce7-9439-34653001fc3b", accountID)
	})

	t.Run("should return error when no accounts exist", func(t *testing.T) {
		store, cleanup, err := NewTestStoreFromSQL(context.Background(), "", t.TempDir())
		t.Cleanup(cleanup)
		require.NoError(t, err)

		accountID, err := store.GetAnyAccountID(context.Background())
		require.Error(t, err)
		sErr, ok := status.FromError(err)
		assert.True(t, ok)
		assert.Equal(t, sErr.Type(), status.NotFound)
		assert.Empty(t, accountID)
	})
}
