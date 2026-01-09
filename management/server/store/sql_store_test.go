package store

import (
	"context"
	"crypto/sha256"
	b64 "encoding/base64"
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"net/netip"
	"os"
	"runtime"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	nbdns "github.com/netbirdio/netbird/dns"
	resourceTypes "github.com/netbirdio/netbird/management/server/networks/resources/types"
	routerTypes "github.com/netbirdio/netbird/management/server/networks/routers/types"
	networkTypes "github.com/netbirdio/netbird/management/server/networks/types"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/posture"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/management/server/util"
	nbroute "github.com/netbirdio/netbird/route"
	"github.com/netbirdio/netbird/shared/management/status"
	"github.com/netbirdio/netbird/util/crypt"
)

func runTestForAllEngines(t *testing.T, testDataFile string, f func(t *testing.T, store Store)) {
	t.Helper()
	for _, engine := range supportedEngines {
		if os.Getenv("NETBIRD_STORE_ENGINE") != "" && os.Getenv("NETBIRD_STORE_ENGINE") != string(engine) {
			continue
		}
		t.Setenv("NETBIRD_STORE_ENGINE", string(engine))
		store, cleanUp, err := NewTestStoreFromSQL(context.Background(), testDataFile, t.TempDir())
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
		netIP := randomIPv4()
		peerID := fmt.Sprintf("%s-peer-%d", account.Id, n)

		peer := &nbpeer.Peer{
			ID:         peerID,
			Key:        peerID,
			IP:         netIP,
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

func randomIPv4() net.IP {
	rand.New(rand.NewSource(time.Now().UnixNano()))
	b := make([]byte, 4)
	for i := range b {
		b[i] = byte(rand.Intn(256))
	}
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
			IP:     net.IP{127, 0, 0, 1},
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
			IP:     net.IP{127, 0, 0, 2},
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
		IP:     net.IP{127, 0, 0, 1},
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

func TestSqlStore_SavePeer(t *testing.T) {
	store, cleanUp, err := NewTestStoreFromSQL(context.Background(), "../testdata/store.sql", t.TempDir())
	t.Cleanup(cleanUp)
	assert.NoError(t, err)

	account, err := store.GetAccount(context.Background(), "bf1c8084-ba50-4ce7-9439-34653001fc3b")
	require.NoError(t, err)

	// save status of non-existing peer
	peer := &nbpeer.Peer{
		Key:       "peerkey",
		ID:        "testpeer",
		IP:        net.IP{127, 0, 0, 1},
		Meta:      nbpeer.PeerSystemMeta{Hostname: "testingpeer"},
		Name:      "peer name",
		Status:    &nbpeer.PeerStatus{Connected: true, LastSeen: time.Now().UTC()},
		CreatedAt: time.Now().UTC(),
	}
	ctx := context.Background()
	err = store.SavePeer(ctx, account.Id, peer)
	assert.Error(t, err)
	parsedErr, ok := status.FromError(err)
	require.True(t, ok)
	require.Equal(t, status.NotFound, parsedErr.Type(), "should return not found error")

	// save new status of existing peer
	account.Peers[peer.ID] = peer

	err = store.SaveAccount(context.Background(), account)
	require.NoError(t, err)

	updatedPeer := peer.Copy()
	updatedPeer.Status.Connected = false
	updatedPeer.Meta.Hostname = "updatedpeer"

	err = store.SavePeer(ctx, account.Id, updatedPeer)
	require.NoError(t, err)

	account, err = store.GetAccount(context.Background(), account.Id)
	require.NoError(t, err)

	actual := account.Peers[peer.ID]
	assert.Equal(t, updatedPeer.Meta, actual.Meta)
	assert.Equal(t, updatedPeer.Status.Connected, actual.Status.Connected)
	assert.Equal(t, updatedPeer.Status.LoginExpired, actual.Status.LoginExpired)
	assert.Equal(t, updatedPeer.Status.RequiresApproval, actual.Status.RequiresApproval)
	assert.WithinDurationf(t, updatedPeer.Status.LastSeen, actual.Status.LastSeen.UTC(), time.Millisecond, "LastSeen should be equal")
}

func TestSqlStore_SavePeerStatus(t *testing.T) {
	store, cleanUp, err := NewTestStoreFromSQL(context.Background(), "../testdata/store.sql", t.TempDir())
	t.Cleanup(cleanUp)
	assert.NoError(t, err)

	account, err := store.GetAccount(context.Background(), "bf1c8084-ba50-4ce7-9439-34653001fc3b")
	require.NoError(t, err)

	// save status of non-existing peer
	newStatus := nbpeer.PeerStatus{Connected: false, LastSeen: time.Now().UTC()}
	err = store.SavePeerStatus(context.Background(), account.Id, "non-existing-peer", newStatus)
	assert.Error(t, err)
	parsedErr, ok := status.FromError(err)
	require.True(t, ok)
	require.Equal(t, status.NotFound, parsedErr.Type(), "should return not found error")

	// save new status of existing peer
	account.Peers["testpeer"] = &nbpeer.Peer{
		Key:    "peerkey",
		ID:     "testpeer",
		IP:     net.IP{127, 0, 0, 1},
		Meta:   nbpeer.PeerSystemMeta{},
		Name:   "peer name",
		Status: &nbpeer.PeerStatus{Connected: true, LastSeen: time.Now().UTC()},
	}

	err = store.SaveAccount(context.Background(), account)
	require.NoError(t, err)

	err = store.SavePeerStatus(context.Background(), account.Id, "testpeer", newStatus)
	require.NoError(t, err)

	account, err = store.GetAccount(context.Background(), account.Id)
	require.NoError(t, err)

	actual := account.Peers["testpeer"].Status
	assert.Equal(t, newStatus.Connected, actual.Connected)
	assert.Equal(t, newStatus.LoginExpired, actual.LoginExpired)
	assert.Equal(t, newStatus.RequiresApproval, actual.RequiresApproval)
	assert.WithinDurationf(t, newStatus.LastSeen, actual.LastSeen.UTC(), time.Millisecond, "LastSeen should be equal")

	newStatus.Connected = true

	err = store.SavePeerStatus(context.Background(), account.Id, "testpeer", newStatus)
	require.NoError(t, err)

	account, err = store.GetAccount(context.Background(), account.Id)
	require.NoError(t, err)

	actual = account.Peers["testpeer"].Status
	assert.Equal(t, newStatus.Connected, actual.Connected)
	assert.Equal(t, newStatus.LoginExpired, actual.LoginExpired)
	assert.Equal(t, newStatus.RequiresApproval, actual.RequiresApproval)
	assert.WithinDurationf(t, newStatus.LastSeen, actual.LastSeen.UTC(), time.Millisecond, "LastSeen should be equal")
}

func TestSqlStore_SavePeerLocation(t *testing.T) {
	store, cleanUp, err := NewTestStoreFromSQL(context.Background(), "../testdata/store.sql", t.TempDir())
	t.Cleanup(cleanUp)
	assert.NoError(t, err)

	account, err := store.GetAccount(context.Background(), "bf1c8084-ba50-4ce7-9439-34653001fc3b")
	require.NoError(t, err)

	peer := &nbpeer.Peer{
		AccountID: account.Id,
		ID:        "testpeer",
		Location: nbpeer.Location{
			ConnectionIP: net.ParseIP("0.0.0.0"),
			CountryCode:  "YY",
			CityName:     "City",
			GeoNameID:    1,
		},
		CreatedAt: time.Now().UTC(),
		Meta:      nbpeer.PeerSystemMeta{},
	}
	// error is expected as peer is not in store yet
	err = store.SavePeerLocation(context.Background(), account.Id, peer)
	assert.Error(t, err)

	account.Peers[peer.ID] = peer
	err = store.SaveAccount(context.Background(), account)
	require.NoError(t, err)

	peer.Location.ConnectionIP = net.ParseIP("35.1.1.1")
	peer.Location.CountryCode = "DE"
	peer.Location.CityName = "Berlin"
	peer.Location.GeoNameID = 2950159

	err = store.SavePeerLocation(context.Background(), account.Id, account.Peers[peer.ID])
	assert.NoError(t, err)

	account, err = store.GetAccount(context.Background(), account.Id)
	require.NoError(t, err)

	actual := account.Peers[peer.ID].Location
	assert.Equal(t, peer.Location, actual)

	peer.ID = "non-existing-peer"
	err = store.SavePeerLocation(context.Background(), account.Id, peer)
	assert.Error(t, err)
	parsedErr, ok := status.FromError(err)
	require.True(t, ok)
	require.Equal(t, status.NotFound, parsedErr.Type(), "should return not found error")
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

func Test_GetTokenIDByHashedToken(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("The SQLite store is not properly supported by Windows yet")
	}

	runTestForAllEngines(t, "../testdata/store.sql", func(t *testing.T, store Store) {
		hashed := "SoMeHaShEdToKeN"
		id := "9dj38s35-63fb-11ec-90d6-0242ac120003"

		token, err := store.GetTokenIDByHashedToken(context.Background(), hashed)
		require.NoError(t, err)
		require.Equal(t, id, token)

		_, err = store.GetTokenIDByHashedToken(context.Background(), "non-existing-hash")
		require.Error(t, err)
		parsedErr, ok := status.FromError(err)
		require.True(t, ok)
		require.Equal(t, status.NotFound, parsedErr.Type(), "should return not found error")
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
		IP:     net.IP{127, 0, 0, 1},
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
		IP:     net.IP{127, 0, 0, 1},
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
		IP:     net.IP{127, 0, 0, 2},
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
		IP:     net.IP{127, 0, 0, 1},
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

func TestPostgresql_GetTokenIDByHashedToken(t *testing.T) {
	if (os.Getenv("CI") == "true" && runtime.GOOS == "darwin") || runtime.GOOS == "windows" {
		t.Skip("skip CI tests on darwin and windows")
	}

	t.Setenv("NETBIRD_STORE_ENGINE", string(types.PostgresStoreEngine))
	store, cleanUp, err := NewTestStoreFromSQL(context.Background(), "../testdata/store.sql", t.TempDir())
	t.Cleanup(cleanUp)
	assert.NoError(t, err)

	hashed := "SoMeHaShEdToKeN"
	id := "9dj38s35-63fb-11ec-90d6-0242ac120003"

	token, err := store.GetTokenIDByHashedToken(context.Background(), hashed)
	require.NoError(t, err)
	require.Equal(t, id, token)
}

func TestSqlite_GetTakenIPs(t *testing.T) {
	t.Setenv("NETBIRD_STORE_ENGINE", string(types.SqliteStoreEngine))
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/extended-store.sql", t.TempDir())
	defer cleanup()
	if err != nil {
		t.Fatal(err)
	}

	existingAccountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"

	_, err = store.GetAccount(context.Background(), existingAccountID)
	require.NoError(t, err)

	takenIPs, err := store.GetTakenIPs(context.Background(), LockingStrengthNone, existingAccountID)
	require.NoError(t, err)
	assert.Equal(t, []net.IP{}, takenIPs)

	peer1 := &nbpeer.Peer{
		ID:        "peer1",
		AccountID: existingAccountID,
		Key:       "key1",
		DNSLabel:  "peer1",
		IP:        net.IP{1, 1, 1, 1},
	}
	err = store.AddPeerToAccount(context.Background(), peer1)
	require.NoError(t, err)

	takenIPs, err = store.GetTakenIPs(context.Background(), LockingStrengthNone, existingAccountID)
	require.NoError(t, err)
	ip1 := net.IP{1, 1, 1, 1}.To16()
	assert.Equal(t, []net.IP{ip1}, takenIPs)

	peer2 := &nbpeer.Peer{
		ID:        "peer1second",
		AccountID: existingAccountID,
		Key:       "key2",
		DNSLabel:  "peer1-1",
		IP:        net.IP{2, 2, 2, 2},
	}
	err = store.AddPeerToAccount(context.Background(), peer2)
	require.NoError(t, err)

	takenIPs, err = store.GetTakenIPs(context.Background(), LockingStrengthNone, existingAccountID)
	require.NoError(t, err)
	ip2 := net.IP{2, 2, 2, 2}.To16()
	assert.Equal(t, []net.IP{ip1, ip2}, takenIPs)
}

func TestSqlite_GetPeerLabelsInAccount(t *testing.T) {
	runTestForAllEngines(t, "../testdata/extended-store.sql", func(t *testing.T, store Store) {
		existingAccountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"
		peerHostname := "peer1"

		_, err := store.GetAccount(context.Background(), existingAccountID)
		require.NoError(t, err)

		labels, err := store.GetPeerLabelsInAccount(context.Background(), LockingStrengthNone, existingAccountID, peerHostname)
		require.NoError(t, err)
		assert.Equal(t, []string{}, labels)

		peer1 := &nbpeer.Peer{
			ID:        "peer1",
			AccountID: existingAccountID,
			Key:       "key1",
			DNSLabel:  "peer1",
			IP:        net.IP{1, 1, 1, 1},
		}
		err = store.AddPeerToAccount(context.Background(), peer1)
		require.NoError(t, err)

		labels, err = store.GetPeerLabelsInAccount(context.Background(), LockingStrengthNone, existingAccountID, peerHostname)
		require.NoError(t, err)
		assert.Equal(t, []string{"peer1"}, labels)

		peer2 := &nbpeer.Peer{
			ID:        "peer1second",
			AccountID: existingAccountID,
			Key:       "key2",
			DNSLabel:  "peer1-1",
			IP:        net.IP{2, 2, 2, 2},
		}
		err = store.AddPeerToAccount(context.Background(), peer2)
		require.NoError(t, err)

		labels, err = store.GetPeerLabelsInAccount(context.Background(), LockingStrengthNone, existingAccountID, peerHostname)
		require.NoError(t, err)

		expected := []string{"peer1", "peer1-1"}
		sort.Strings(expected)
		sort.Strings(labels)
		assert.Equal(t, expected, labels)
	})
}

func Test_AddPeerWithSameDnsLabel(t *testing.T) {
	runTestForAllEngines(t, "../testdata/extended-store.sql", func(t *testing.T, store Store) {
		existingAccountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"

		_, err := store.GetAccount(context.Background(), existingAccountID)
		require.NoError(t, err)

		peer1 := &nbpeer.Peer{
			ID:        "peer1",
			AccountID: existingAccountID,
			Key:       "key1",
			DNSLabel:  "peer1.domain.test",
		}
		err = store.AddPeerToAccount(context.Background(), peer1)
		require.NoError(t, err)

		peer2 := &nbpeer.Peer{
			ID:        "peer1second",
			AccountID: existingAccountID,
			Key:       "key2",
			DNSLabel:  "peer1.domain.test",
		}
		err = store.AddPeerToAccount(context.Background(), peer2)
		require.Error(t, err)
	})
}

func Test_AddPeerWithSameIP(t *testing.T) {
	runTestForAllEngines(t, "../testdata/extended-store.sql", func(t *testing.T, store Store) {
		existingAccountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"

		_, err := store.GetAccount(context.Background(), existingAccountID)
		require.NoError(t, err)

		peer1 := &nbpeer.Peer{
			ID:        "peer1",
			AccountID: existingAccountID,
			Key:       "key1",
			IP:        net.IP{1, 1, 1, 1},
		}
		err = store.AddPeerToAccount(context.Background(), peer1)
		require.NoError(t, err)

		peer2 := &nbpeer.Peer{
			ID:        "peer1second",
			AccountID: existingAccountID,
			Key:       "key2",
			IP:        net.IP{1, 1, 1, 1},
		}
		err = store.AddPeerToAccount(context.Background(), peer2)
		require.Error(t, err)
	})
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

func TestSqlite_GetSetupKeyBySecret(t *testing.T) {
	t.Setenv("NETBIRD_STORE_ENGINE", string(types.SqliteStoreEngine))
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/extended-store.sql", t.TempDir())
	t.Cleanup(cleanup)
	if err != nil {
		t.Fatal(err)
	}

	existingAccountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"

	plainKey := "A2C8E62B-38F5-4553-B31E-DD66C696CEBB"
	hashedKey := sha256.Sum256([]byte(plainKey))
	encodedHashedKey := b64.StdEncoding.EncodeToString(hashedKey[:])

	_, err = store.GetAccount(context.Background(), existingAccountID)
	require.NoError(t, err)

	setupKey, err := store.GetSetupKeyBySecret(context.Background(), LockingStrengthNone, encodedHashedKey)
	require.NoError(t, err)
	assert.Equal(t, encodedHashedKey, setupKey.Key)
	assert.Equal(t, types.HiddenKey(plainKey, 4), setupKey.KeySecret)
	assert.Equal(t, "bf1c8084-ba50-4ce7-9439-34653001fc3b", setupKey.AccountID)
	assert.Equal(t, "Default key", setupKey.Name)
}

func TestSqlite_incrementSetupKeyUsage(t *testing.T) {
	t.Setenv("NETBIRD_STORE_ENGINE", string(types.SqliteStoreEngine))
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/extended-store.sql", t.TempDir())
	t.Cleanup(cleanup)
	if err != nil {
		t.Fatal(err)
	}

	existingAccountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"

	plainKey := "A2C8E62B-38F5-4553-B31E-DD66C696CEBB"
	hashedKey := sha256.Sum256([]byte(plainKey))
	encodedHashedKey := b64.StdEncoding.EncodeToString(hashedKey[:])

	_, err = store.GetAccount(context.Background(), existingAccountID)
	require.NoError(t, err)

	setupKey, err := store.GetSetupKeyBySecret(context.Background(), LockingStrengthNone, encodedHashedKey)
	require.NoError(t, err)
	assert.Equal(t, 0, setupKey.UsedTimes)

	err = store.IncrementSetupKeyUsage(context.Background(), setupKey.Id)
	require.NoError(t, err)

	setupKey, err = store.GetSetupKeyBySecret(context.Background(), LockingStrengthNone, encodedHashedKey)
	require.NoError(t, err)
	assert.Equal(t, 1, setupKey.UsedTimes)

	err = store.IncrementSetupKeyUsage(context.Background(), setupKey.Id)
	require.NoError(t, err)

	setupKey, err = store.GetSetupKeyBySecret(context.Background(), LockingStrengthNone, encodedHashedKey)
	require.NoError(t, err)
	assert.Equal(t, 2, setupKey.UsedTimes)
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

func TestSqlStore_GetAccountUsers(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/extended-store.sql", t.TempDir())
	t.Cleanup(cleanup)
	if err != nil {
		t.Fatal(err)
	}
	accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"
	account, err := store.GetAccount(context.Background(), accountID)
	require.NoError(t, err)
	users, err := store.GetAccountUsers(context.Background(), LockingStrengthNone, accountID)
	require.NoError(t, err)
	require.Len(t, users, len(account.Users))
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

func TestSqlite_GetGroupByName(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/extended-store.sql", t.TempDir())
	t.Cleanup(cleanup)
	if err != nil {
		t.Fatal(err)
	}
	accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"

	group, err := store.GetGroupByName(context.Background(), LockingStrengthNone, accountID, "All")
	require.NoError(t, err)
	require.True(t, group.IsGroupAll())
}

func Test_DeleteSetupKeySuccessfully(t *testing.T) {
	t.Setenv("NETBIRD_STORE_ENGINE", string(types.SqliteStoreEngine))
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/extended-store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"
	setupKeyID := "A2C8E62B-38F5-4553-B31E-DD66C696CEBB"

	err = store.DeleteSetupKey(context.Background(), accountID, setupKeyID)
	require.NoError(t, err)

	_, err = store.GetSetupKeyByID(context.Background(), LockingStrengthNone, setupKeyID, accountID)
	require.Error(t, err)
}

func Test_DeleteSetupKeyFailsForNonExistingKey(t *testing.T) {
	t.Setenv("NETBIRD_STORE_ENGINE", string(types.SqliteStoreEngine))
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/extended-store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"
	nonExistingKeyID := "non-existing-key-id"

	err = store.DeleteSetupKey(context.Background(), accountID, nonExistingKeyID)
	require.Error(t, err)
}

func TestSqlStore_GetGroupsByIDs(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/extended-store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"

	tests := []struct {
		name          string
		groupIDs      []string
		expectedCount int
	}{
		{
			name:          "retrieve existing groups by existing IDs",
			groupIDs:      []string{"cfefqs706sqkneg59g4g", "cfefqs706sqkneg59g3g"},
			expectedCount: 2,
		},
		{
			name:          "empty group IDs list",
			groupIDs:      []string{},
			expectedCount: 0,
		},
		{
			name:          "non-existing group IDs",
			groupIDs:      []string{"nonexistent1", "nonexistent2"},
			expectedCount: 0,
		},
		{
			name:          "mixed existing and non-existing group IDs",
			groupIDs:      []string{"cfefqs706sqkneg59g4g", "nonexistent"},
			expectedCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			groups, err := store.GetGroupsByIDs(context.Background(), LockingStrengthNone, accountID, tt.groupIDs)
			require.NoError(t, err)
			require.Len(t, groups, tt.expectedCount)
		})
	}
}

func TestSqlStore_CreateGroup(t *testing.T) {
	t.Setenv("NETBIRD_STORE_ENGINE", string(types.MysqlStoreEngine))
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/extended-store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"

	group := &types.Group{
		ID:         "group-id",
		AccountID:  accountID,
		Issued:     "api",
		Peers:      []string{},
		Resources:  []types.Resource{},
		GroupPeers: []types.GroupPeer{},
	}
	err = store.CreateGroup(context.Background(), group)
	require.NoError(t, err)

	savedGroup, err := store.GetGroupByID(context.Background(), LockingStrengthNone, accountID, "group-id")
	require.NoError(t, err)
	require.Equal(t, savedGroup, group)
}

func TestSqlStore_CreateUpdateGroups(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/extended-store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"

	groups := []*types.Group{
		{
			ID:         "group-1",
			AccountID:  accountID,
			Issued:     "api",
			Peers:      []string{},
			Resources:  []types.Resource{},
			GroupPeers: []types.GroupPeer{},
		},
		{
			ID:         "group-2",
			AccountID:  accountID,
			Issued:     "integration",
			Peers:      []string{},
			Resources:  []types.Resource{},
			GroupPeers: []types.GroupPeer{},
		},
	}
	err = store.CreateGroups(context.Background(), accountID, groups)
	require.NoError(t, err)

	groups[1].Peers = []string{}
	err = store.UpdateGroups(context.Background(), accountID, groups)
	require.NoError(t, err)

	group, err := store.GetGroupByID(context.Background(), LockingStrengthNone, accountID, groups[1].ID)
	require.NoError(t, err)
	require.Equal(t, groups[1], group)
}

func TestSqlStore_DeleteGroup(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/extended-store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"

	tests := []struct {
		name        string
		groupID     string
		expectError bool
	}{
		{
			name:        "delete existing group",
			groupID:     "cfefqs706sqkneg59g4g",
			expectError: false,
		},
		{
			name:        "delete non-existing group",
			groupID:     "non-existing-group-id",
			expectError: true,
		},
		{
			name:        "delete with empty group ID",
			groupID:     "",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := store.DeleteGroup(context.Background(), accountID, tt.groupID)
			if tt.expectError {
				require.Error(t, err)
				sErr, ok := status.FromError(err)
				require.True(t, ok)
				require.Equal(t, sErr.Type(), status.NotFound)
			} else {
				require.NoError(t, err)

				group, err := store.GetGroupByID(context.Background(), LockingStrengthNone, accountID, tt.groupID)
				require.Error(t, err)
				require.Nil(t, group)
			}
		})
	}
}

func TestSqlStore_DeleteGroups(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/extended-store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"

	tests := []struct {
		name        string
		groupIDs    []string
		expectError bool
	}{
		{
			name:        "delete multiple existing groups",
			groupIDs:    []string{"cfefqs706sqkneg59g4g", "cfefqs706sqkneg59g3g"},
			expectError: false,
		},
		{
			name:        "delete non-existing groups",
			groupIDs:    []string{"non-existing-id-1", "non-existing-id-2"},
			expectError: false,
		},
		{
			name:        "delete with empty group IDs list",
			groupIDs:    []string{},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := store.DeleteGroups(context.Background(), accountID, tt.groupIDs)
			if tt.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)

				for _, groupID := range tt.groupIDs {
					group, err := store.GetGroupByID(context.Background(), LockingStrengthNone, accountID, groupID)
					require.Error(t, err)
					require.Nil(t, group)
				}
			}
		})
	}
}

func TestSqlStore_GetPeerByID(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/store_policy_migrate.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"
	tests := []struct {
		name        string
		peerID      string
		expectError bool
	}{
		{
			name:        "retrieve existing peer",
			peerID:      "cfefqs706sqkneg59g4g",
			expectError: false,
		},
		{
			name:        "retrieve non-existing peer",
			peerID:      "non-existing",
			expectError: true,
		},
		{
			name:        "retrieve with empty peer ID",
			peerID:      "",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			peer, err := store.GetPeerByID(context.Background(), LockingStrengthNone, accountID, tt.peerID)
			if tt.expectError {
				require.Error(t, err)
				sErr, ok := status.FromError(err)
				require.True(t, ok)
				require.Equal(t, sErr.Type(), status.NotFound)
				require.Nil(t, peer)
			} else {
				require.NoError(t, err)
				require.NotNil(t, peer)
				require.Equal(t, tt.peerID, peer.ID)
			}
		})
	}
}

func TestSqlStore_GetPeersByIDs(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/store_policy_migrate.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"
	tests := []struct {
		name          string
		peerIDs       []string
		expectedCount int
	}{
		{
			name:          "retrieve existing peers by existing IDs",
			peerIDs:       []string{"cfefqs706sqkneg59g4g", "cfeg6sf06sqkneg59g50"},
			expectedCount: 2,
		},
		{
			name:          "empty peer IDs list",
			peerIDs:       []string{},
			expectedCount: 0,
		},
		{
			name:          "non-existing peer IDs",
			peerIDs:       []string{"nonexistent1", "nonexistent2"},
			expectedCount: 0,
		},
		{
			name:          "mixed existing and non-existing peer IDs",
			peerIDs:       []string{"cfeg6sf06sqkneg59g50", "nonexistent"},
			expectedCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			peers, err := store.GetPeersByIDs(context.Background(), LockingStrengthNone, accountID, tt.peerIDs)
			require.NoError(t, err)
			require.Len(t, peers, tt.expectedCount)
		})
	}
}

func TestSqlStore_GetPostureChecksByID(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/extended-store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"
	tests := []struct {
		name            string
		postureChecksID string
		expectError     bool
	}{
		{
			name:            "retrieve existing posture checks",
			postureChecksID: "csplshq7qv948l48f7t0",
			expectError:     false,
		},
		{
			name:            "retrieve non-existing posture checks",
			postureChecksID: "non-existing",
			expectError:     true,
		},
		{
			name:            "retrieve with empty posture checks ID",
			postureChecksID: "",
			expectError:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			postureChecks, err := store.GetPostureChecksByID(context.Background(), LockingStrengthNone, accountID, tt.postureChecksID)
			if tt.expectError {
				require.Error(t, err)
				sErr, ok := status.FromError(err)
				require.True(t, ok)
				require.Equal(t, sErr.Type(), status.NotFound)
				require.Nil(t, postureChecks)
			} else {
				require.NoError(t, err)
				require.NotNil(t, postureChecks)
				require.Equal(t, tt.postureChecksID, postureChecks.ID)
			}
		})
	}
}

func TestSqlStore_GetPostureChecksByIDs(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/extended-store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"

	tests := []struct {
		name            string
		postureCheckIDs []string
		expectedCount   int
	}{
		{
			name:            "retrieve existing posture checks by existing IDs",
			postureCheckIDs: []string{"csplshq7qv948l48f7t0", "cspnllq7qv95uq1r4k90"},
			expectedCount:   2,
		},
		{
			name:            "empty posture check IDs list",
			postureCheckIDs: []string{},
			expectedCount:   0,
		},
		{
			name:            "non-existing posture check IDs",
			postureCheckIDs: []string{"nonexistent1", "nonexistent2"},
			expectedCount:   0,
		},
		{
			name:            "mixed existing and non-existing posture check IDs",
			postureCheckIDs: []string{"cspnllq7qv95uq1r4k90", "nonexistent"},
			expectedCount:   1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			groups, err := store.GetPostureChecksByIDs(context.Background(), LockingStrengthNone, accountID, tt.postureCheckIDs)
			require.NoError(t, err)
			require.Len(t, groups, tt.expectedCount)
		})
	}
}

func TestSqlStore_SavePostureChecks(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/extended-store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"

	postureChecks := &posture.Checks{
		ID:        "posture-checks-id",
		AccountID: accountID,
		Checks: posture.ChecksDefinition{
			NBVersionCheck: &posture.NBVersionCheck{
				MinVersion: "0.31.0",
			},
			OSVersionCheck: &posture.OSVersionCheck{
				Ios: &posture.MinVersionCheck{
					MinVersion: "13.0.1",
				},
				Linux: &posture.MinKernelVersionCheck{
					MinKernelVersion: "5.3.3-dev",
				},
			},
			GeoLocationCheck: &posture.GeoLocationCheck{
				Locations: []posture.Location{
					{
						CountryCode: "DE",
						CityName:    "Berlin",
					},
				},
				Action: posture.CheckActionAllow,
			},
		},
	}
	err = store.SavePostureChecks(context.Background(), postureChecks)
	require.NoError(t, err)

	savePostureChecks, err := store.GetPostureChecksByID(context.Background(), LockingStrengthNone, accountID, "posture-checks-id")
	require.NoError(t, err)
	require.Equal(t, savePostureChecks, postureChecks)
}

func TestSqlStore_DeletePostureChecks(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/extended-store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"

	tests := []struct {
		name            string
		postureChecksID string
		expectError     bool
	}{
		{
			name:            "delete existing posture checks",
			postureChecksID: "csplshq7qv948l48f7t0",
			expectError:     false,
		},
		{
			name:            "delete non-existing posture checks",
			postureChecksID: "non-existing-posture-checks-id",
			expectError:     true,
		},
		{
			name:            "delete with empty posture checks ID",
			postureChecksID: "",
			expectError:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err = store.DeletePostureChecks(context.Background(), accountID, tt.postureChecksID)
			if tt.expectError {
				require.Error(t, err)
				sErr, ok := status.FromError(err)
				require.True(t, ok)
				require.Equal(t, sErr.Type(), status.NotFound)
			} else {
				require.NoError(t, err)
				group, err := store.GetPostureChecksByID(context.Background(), LockingStrengthNone, accountID, tt.postureChecksID)
				require.Error(t, err)
				require.Nil(t, group)
			}
		})
	}
}

func TestSqlStore_GetPolicyByID(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"
	tests := []struct {
		name        string
		policyID    string
		expectError bool
	}{
		{
			name:        "retrieve existing policy",
			policyID:    "cs1tnh0hhcjnqoiuebf0",
			expectError: false,
		},
		{
			name:        "retrieve non-existing policy checks",
			policyID:    "non-existing",
			expectError: true,
		},
		{
			name:        "retrieve with empty policy ID",
			policyID:    "",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy, err := store.GetPolicyByID(context.Background(), LockingStrengthNone, accountID, tt.policyID)
			if tt.expectError {
				require.Error(t, err)
				sErr, ok := status.FromError(err)
				require.True(t, ok)
				require.Equal(t, sErr.Type(), status.NotFound)
				require.Nil(t, policy)
			} else {
				require.NoError(t, err)
				require.NotNil(t, policy)
				require.Equal(t, tt.policyID, policy.ID)
			}
		})
	}
}

func TestSqlStore_CreatePolicy(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"

	policy := &types.Policy{
		ID:        "policy-id",
		AccountID: accountID,
		Enabled:   true,
		Rules: []*types.PolicyRule{
			{
				Enabled:       true,
				Sources:       []string{"groupA"},
				Destinations:  []string{"groupC"},
				Bidirectional: true,
				Action:        types.PolicyTrafficActionAccept,
			},
		},
	}
	err = store.CreatePolicy(context.Background(), policy)
	require.NoError(t, err)

	savePolicy, err := store.GetPolicyByID(context.Background(), LockingStrengthNone, accountID, policy.ID)
	require.NoError(t, err)
	require.Equal(t, savePolicy, policy)

}

func TestSqlStore_SavePolicy(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"
	policyID := "cs1tnh0hhcjnqoiuebf0"

	policy, err := store.GetPolicyByID(context.Background(), LockingStrengthNone, accountID, policyID)
	require.NoError(t, err)

	policy.Enabled = false
	policy.Description = "policy"
	policy.Rules[0].Sources = []string{"group"}
	policy.Rules[0].Ports = []string{"80", "443"}
	err = store.SavePolicy(context.Background(), policy)
	require.NoError(t, err)

	savePolicy, err := store.GetPolicyByID(context.Background(), LockingStrengthNone, accountID, policy.ID)
	require.NoError(t, err)
	require.Equal(t, savePolicy, policy)
}

func TestSqlStore_DeletePolicy(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"
	policyID := "cs1tnh0hhcjnqoiuebf0"

	err = store.DeletePolicy(context.Background(), accountID, policyID)
	require.NoError(t, err)

	policy, err := store.GetPolicyByID(context.Background(), LockingStrengthNone, accountID, policyID)
	require.Error(t, err)
	require.Nil(t, policy)
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

func TestSqlStore_GetAccountNameServerGroups(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/extended-store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	tests := []struct {
		name          string
		accountID     string
		expectedCount int
	}{
		{
			name:          "retrieve name server groups by existing account ID",
			accountID:     "bf1c8084-ba50-4ce7-9439-34653001fc3b",
			expectedCount: 1,
		},
		{
			name:          "non-existing account ID",
			accountID:     "nonexistent",
			expectedCount: 0,
		},
		{
			name:          "empty account ID",
			accountID:     "",
			expectedCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			peers, err := store.GetAccountNameServerGroups(context.Background(), LockingStrengthNone, tt.accountID)
			require.NoError(t, err)
			require.Len(t, peers, tt.expectedCount)
		})
	}

}

func TestSqlStore_GetNameServerByID(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/extended-store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"
	tests := []struct {
		name        string
		nsGroupID   string
		expectError bool
	}{
		{
			name:        "retrieve existing nameserver group",
			nsGroupID:   "csqdelq7qv97ncu7d9t0",
			expectError: false,
		},
		{
			name:        "retrieve non-existing nameserver group",
			nsGroupID:   "non-existing",
			expectError: true,
		},
		{
			name:        "retrieve with empty nameserver group ID",
			nsGroupID:   "",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nsGroup, err := store.GetNameServerGroupByID(context.Background(), LockingStrengthNone, accountID, tt.nsGroupID)
			if tt.expectError {
				require.Error(t, err)
				sErr, ok := status.FromError(err)
				require.True(t, ok)
				require.Equal(t, sErr.Type(), status.NotFound)
				require.Nil(t, nsGroup)
			} else {
				require.NoError(t, err)
				require.NotNil(t, nsGroup)
				require.Equal(t, tt.nsGroupID, nsGroup.ID)
			}
		})
	}
}

func TestSqlStore_SaveNameServerGroup(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/extended-store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"

	nsGroup := &nbdns.NameServerGroup{
		ID:        "ns-group-id",
		AccountID: accountID,
		Name:      "NS Group",
		NameServers: []nbdns.NameServer{
			{
				IP:     netip.MustParseAddr("8.8.8.8"),
				NSType: 1,
				Port:   53,
			},
		},
		Groups:               []string{"groupA"},
		Primary:              true,
		Enabled:              true,
		SearchDomainsEnabled: false,
	}

	err = store.SaveNameServerGroup(context.Background(), nsGroup)
	require.NoError(t, err)

	saveNSGroup, err := store.GetNameServerGroupByID(context.Background(), LockingStrengthNone, accountID, nsGroup.ID)
	require.NoError(t, err)
	require.Equal(t, saveNSGroup, nsGroup)
}

func TestSqlStore_DeleteNameServerGroup(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/extended-store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"
	nsGroupID := "csqdelq7qv97ncu7d9t0"

	err = store.DeleteNameServerGroup(context.Background(), accountID, nsGroupID)
	require.NoError(t, err)

	nsGroup, err := store.GetNameServerGroupByID(context.Background(), LockingStrengthNone, accountID, nsGroupID)
	require.Error(t, err)
	require.Nil(t, nsGroup)
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

func TestSqlStore_GetAccountNetworks(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	tests := []struct {
		name          string
		accountID     string
		expectedCount int
	}{
		{
			name:          "retrieve networks by existing account ID",
			accountID:     "bf1c8084-ba50-4ce7-9439-34653001fc3b",
			expectedCount: 1,
		},

		{
			name:          "retrieve networks by non-existing account ID",
			accountID:     "non-existent",
			expectedCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			networks, err := store.GetAccountNetworks(context.Background(), LockingStrengthNone, tt.accountID)
			require.NoError(t, err)
			require.Len(t, networks, tt.expectedCount)
		})
	}
}

func TestSqlStore_GetNetworkByID(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"
	tests := []struct {
		name        string
		networkID   string
		expectError bool
	}{
		{
			name:        "retrieve existing network ID",
			networkID:   "ct286bi7qv930dsrrug0",
			expectError: false,
		},
		{
			name:        "retrieve non-existing network ID",
			networkID:   "non-existing",
			expectError: true,
		},
		{
			name:        "retrieve network with empty ID",
			networkID:   "",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			network, err := store.GetNetworkByID(context.Background(), LockingStrengthNone, accountID, tt.networkID)
			if tt.expectError {
				require.Error(t, err)
				sErr, ok := status.FromError(err)
				require.True(t, ok)
				require.Equal(t, sErr.Type(), status.NotFound)
				require.Nil(t, network)
			} else {
				require.NoError(t, err)
				require.NotNil(t, network)
				require.Equal(t, tt.networkID, network.ID)
			}
		})
	}
}

func TestSqlStore_SaveNetwork(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"
	network := &networkTypes.Network{
		ID:        "net-id",
		AccountID: accountID,
		Name:      "net",
	}

	err = store.SaveNetwork(context.Background(), network)
	require.NoError(t, err)

	savedNet, err := store.GetNetworkByID(context.Background(), LockingStrengthNone, accountID, network.ID)
	require.NoError(t, err)
	require.Equal(t, network, savedNet)
}

func TestSqlStore_DeleteNetwork(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"
	networkID := "ct286bi7qv930dsrrug0"

	err = store.DeleteNetwork(context.Background(), accountID, networkID)
	require.NoError(t, err)

	network, err := store.GetNetworkByID(context.Background(), LockingStrengthNone, accountID, networkID)
	require.Error(t, err)
	sErr, ok := status.FromError(err)
	require.True(t, ok)
	require.Equal(t, status.NotFound, sErr.Type())
	require.Nil(t, network)
}

func TestSqlStore_GetNetworkRoutersByNetID(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"

	tests := []struct {
		name          string
		networkID     string
		expectedCount int
	}{
		{
			name:          "retrieve routers by existing network ID",
			networkID:     "ct286bi7qv930dsrrug0",
			expectedCount: 1,
		},
		{
			name:          "retrieve routers by non-existing network ID",
			networkID:     "non-existent",
			expectedCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			routers, err := store.GetNetworkRoutersByNetID(context.Background(), LockingStrengthNone, accountID, tt.networkID)
			require.NoError(t, err)
			require.Len(t, routers, tt.expectedCount)
		})
	}
}

func TestSqlStore_GetNetworkRouterByID(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"
	tests := []struct {
		name            string
		networkRouterID string
		expectError     bool
	}{
		{
			name:            "retrieve existing network router ID",
			networkRouterID: "ctc20ji7qv9ck2sebc80",
			expectError:     false,
		},
		{
			name:            "retrieve non-existing network router ID",
			networkRouterID: "non-existing",
			expectError:     true,
		},
		{
			name:            "retrieve network with empty router ID",
			networkRouterID: "",
			expectError:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			networkRouter, err := store.GetNetworkRouterByID(context.Background(), LockingStrengthNone, accountID, tt.networkRouterID)
			if tt.expectError {
				require.Error(t, err)
				sErr, ok := status.FromError(err)
				require.True(t, ok)
				require.Equal(t, sErr.Type(), status.NotFound)
				require.Nil(t, networkRouter)
			} else {
				require.NoError(t, err)
				require.NotNil(t, networkRouter)
				require.Equal(t, tt.networkRouterID, networkRouter.ID)
			}
		})
	}
}

func TestSqlStore_SaveNetworkRouter(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"
	networkID := "ct286bi7qv930dsrrug0"

	netRouter, err := routerTypes.NewNetworkRouter(accountID, networkID, "", []string{"net-router-grp"}, true, 0, true)
	require.NoError(t, err)

	err = store.SaveNetworkRouter(context.Background(), netRouter)
	require.NoError(t, err)

	savedNetRouter, err := store.GetNetworkRouterByID(context.Background(), LockingStrengthNone, accountID, netRouter.ID)
	require.NoError(t, err)
	require.Equal(t, netRouter, savedNetRouter)
}

func TestSqlStore_DeleteNetworkRouter(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"
	netRouterID := "ctc20ji7qv9ck2sebc80"

	err = store.DeleteNetworkRouter(context.Background(), accountID, netRouterID)
	require.NoError(t, err)

	netRouter, err := store.GetNetworkByID(context.Background(), LockingStrengthNone, accountID, netRouterID)
	require.Error(t, err)
	sErr, ok := status.FromError(err)
	require.True(t, ok)
	require.Equal(t, status.NotFound, sErr.Type())
	require.Nil(t, netRouter)
}

func TestSqlStore_GetNetworkResourcesByNetID(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"

	tests := []struct {
		name          string
		networkID     string
		expectedCount int
	}{
		{
			name:          "retrieve resources by existing network ID",
			networkID:     "ct286bi7qv930dsrrug0",
			expectedCount: 1,
		},
		{
			name:          "retrieve resources by non-existing network ID",
			networkID:     "non-existent",
			expectedCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			netResources, err := store.GetNetworkResourcesByNetID(context.Background(), LockingStrengthNone, accountID, tt.networkID)
			require.NoError(t, err)
			require.Len(t, netResources, tt.expectedCount)
		})
	}
}

func TestSqlStore_GetNetworkResourceByID(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"
	tests := []struct {
		name          string
		netResourceID string
		expectError   bool
	}{
		{
			name:          "retrieve existing network resource ID",
			netResourceID: "ctc4nci7qv9061u6ilfg",
			expectError:   false,
		},
		{
			name:          "retrieve non-existing network resource ID",
			netResourceID: "non-existing",
			expectError:   true,
		},
		{
			name:          "retrieve network with empty resource ID",
			netResourceID: "",
			expectError:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			netResource, err := store.GetNetworkResourceByID(context.Background(), LockingStrengthNone, accountID, tt.netResourceID)
			if tt.expectError {
				require.Error(t, err)
				sErr, ok := status.FromError(err)
				require.True(t, ok)
				require.Equal(t, sErr.Type(), status.NotFound)
				require.Nil(t, netResource)
			} else {
				require.NoError(t, err)
				require.NotNil(t, netResource)
				require.Equal(t, tt.netResourceID, netResource.ID)
			}
		})
	}
}

func TestSqlStore_SaveNetworkResource(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"
	networkID := "ct286bi7qv930dsrrug0"

	netResource, err := resourceTypes.NewNetworkResource(accountID, networkID, "resource-name", "", "example.com", []string{}, true)
	require.NoError(t, err)

	err = store.SaveNetworkResource(context.Background(), netResource)
	require.NoError(t, err)

	savedNetResource, err := store.GetNetworkResourceByID(context.Background(), LockingStrengthNone, accountID, netResource.ID)
	require.NoError(t, err)
	require.Equal(t, netResource.ID, savedNetResource.ID)
	require.Equal(t, netResource.Name, savedNetResource.Name)
	require.Equal(t, netResource.NetworkID, savedNetResource.NetworkID)
	require.Equal(t, netResource.Type, resourceTypes.NetworkResourceType("domain"))
	require.Equal(t, netResource.Domain, "example.com")
	require.Equal(t, netResource.AccountID, savedNetResource.AccountID)
	require.Equal(t, netResource.Prefix, netip.Prefix{})
}

func TestSqlStore_DeleteNetworkResource(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"
	netResourceID := "ctc4nci7qv9061u6ilfg"

	err = store.DeleteNetworkResource(context.Background(), accountID, netResourceID)
	require.NoError(t, err)

	netResource, err := store.GetNetworkByID(context.Background(), LockingStrengthNone, accountID, netResourceID)
	require.Error(t, err)
	sErr, ok := status.FromError(err)
	require.True(t, ok)
	require.Equal(t, status.NotFound, sErr.Type())
	require.Nil(t, netResource)
}

func TestSqlStore_AddAndRemoveResourceFromGroup(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/store.sql", t.TempDir())
	require.NoError(t, err)
	t.Cleanup(cleanup)

	accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"
	resourceId := "ctc4nci7qv9061u6ilfg"
	groupID := "cs1tnh0hhcjnqoiuebeg"

	res := &types.Resource{
		ID:   resourceId,
		Type: "host",
	}
	err = store.AddResourceToGroup(context.Background(), accountID, groupID, res)
	require.NoError(t, err)

	group, err := store.GetGroupByID(context.Background(), LockingStrengthNone, accountID, groupID)
	require.NoError(t, err)
	require.Contains(t, group.Resources, *res)

	groups, err := store.GetResourceGroups(context.Background(), LockingStrengthNone, accountID, resourceId)
	require.NoError(t, err)
	require.Len(t, groups, 1)

	err = store.RemoveResourceFromGroup(context.Background(), accountID, groupID, res.ID)
	require.NoError(t, err)

	group, err = store.GetGroupByID(context.Background(), LockingStrengthNone, accountID, groupID)
	require.NoError(t, err)
	require.NotContains(t, group.Resources, *res)
}

func TestSqlStore_AddPeerToGroup(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/store_policy_migrate.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"
	peerID := "cfefqs706sqkneg59g4g"
	groupID := "cfefqs706sqkneg59g4h"

	group, err := store.GetGroupByID(context.Background(), LockingStrengthNone, accountID, groupID)
	require.NoError(t, err, "failed to get group")
	require.Len(t, group.Peers, 0, "group should have 0 peers")

	err = store.AddPeerToGroup(context.Background(), accountID, peerID, groupID)
	require.NoError(t, err, "failed to add peer to group")

	group, err = store.GetGroupByID(context.Background(), LockingStrengthNone, accountID, groupID)
	require.NoError(t, err, "failed to get group")
	require.Len(t, group.Peers, 1, "group should have 1 peers")
	require.Contains(t, group.Peers, peerID)
}

func TestSqlStore_AddPeerToAllGroup(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/store_policy_migrate.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"
	groupID := "cfefqs706sqkneg59g3g"

	peer := &nbpeer.Peer{
		ID:        "peer1",
		AccountID: accountID,
		DNSLabel:  "peer1.domain.test",
	}

	group, err := store.GetGroupByID(context.Background(), LockingStrengthNone, accountID, groupID)
	require.NoError(t, err, "failed to get group")
	require.Len(t, group.Peers, 2, "group should have 2 peers")
	require.NotContains(t, group.Peers, peer.ID)

	err = store.AddPeerToAccount(context.Background(), peer)
	require.NoError(t, err, "failed to add peer to account")

	err = store.AddPeerToAllGroup(context.Background(), accountID, peer.ID)
	require.NoError(t, err, "failed to add peer to all group")

	group, err = store.GetGroupByID(context.Background(), LockingStrengthNone, accountID, groupID)
	require.NoError(t, err, "failed to get group")
	require.Len(t, group.Peers, 3, "group should have  peers")
	require.Contains(t, group.Peers, peer.ID)
}

func TestSqlStore_AddPeerToAccount(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/store_policy_migrate.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"

	peer := &nbpeer.Peer{
		ID:        "peer1",
		AccountID: accountID,
		Key:       "key",
		IP:        net.IP{1, 1, 1, 1},
		Meta: nbpeer.PeerSystemMeta{
			Hostname:  "hostname",
			GoOS:      "linux",
			Kernel:    "Linux",
			Core:      "21.04",
			Platform:  "x86_64",
			OS:        "Ubuntu",
			WtVersion: "development",
			UIVersion: "development",
		},
		Name:     "peer.test",
		DNSLabel: "peer",
		Status: &nbpeer.PeerStatus{
			LastSeen:         time.Now().UTC(),
			Connected:        true,
			LoginExpired:     false,
			RequiresApproval: false,
		},
		SSHKey:                      "ssh-key",
		SSHEnabled:                  false,
		LoginExpirationEnabled:      true,
		InactivityExpirationEnabled: false,
		LastLogin:                   util.ToPtr(time.Now().UTC()),
		CreatedAt:                   time.Now().UTC(),
		Ephemeral:                   true,
	}
	err = store.AddPeerToAccount(context.Background(), peer)
	require.NoError(t, err, "failed to add peer to account")

	storedPeer, err := store.GetPeerByID(context.Background(), LockingStrengthNone, accountID, peer.ID)
	require.NoError(t, err, "failed to get peer")

	assert.Equal(t, peer.ID, storedPeer.ID)
	assert.Equal(t, peer.AccountID, storedPeer.AccountID)
	assert.Equal(t, peer.Key, storedPeer.Key)
	assert.Equal(t, peer.IP.String(), storedPeer.IP.String())
	assert.Equal(t, peer.Meta, storedPeer.Meta)
	assert.Equal(t, peer.Name, storedPeer.Name)
	assert.Equal(t, peer.DNSLabel, storedPeer.DNSLabel)
	assert.Equal(t, peer.SSHKey, storedPeer.SSHKey)
	assert.Equal(t, peer.SSHEnabled, storedPeer.SSHEnabled)
	assert.Equal(t, peer.LoginExpirationEnabled, storedPeer.LoginExpirationEnabled)
	assert.Equal(t, peer.InactivityExpirationEnabled, storedPeer.InactivityExpirationEnabled)
	assert.WithinDurationf(t, peer.GetLastLogin(), storedPeer.GetLastLogin().UTC(), time.Millisecond, "LastLogin should be equal")
	assert.WithinDurationf(t, peer.CreatedAt, storedPeer.CreatedAt.UTC(), time.Millisecond, "CreatedAt should be equal")
	assert.Equal(t, peer.Ephemeral, storedPeer.Ephemeral)
	assert.Equal(t, peer.Status.Connected, storedPeer.Status.Connected)
	assert.Equal(t, peer.Status.LoginExpired, storedPeer.Status.LoginExpired)
	assert.Equal(t, peer.Status.RequiresApproval, storedPeer.Status.RequiresApproval)
	assert.WithinDurationf(t, peer.Status.LastSeen, storedPeer.Status.LastSeen.UTC(), time.Millisecond, "LastSeen should be equal")
}

func TestSqlStore_GetPeerGroups(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/store_policy_migrate.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"
	peerID := "cfefqs706sqkneg59g4g"

	groups, err := store.GetPeerGroups(context.Background(), LockingStrengthNone, accountID, peerID)
	require.NoError(t, err)
	assert.Len(t, groups, 1)
	assert.Equal(t, groups[0].Name, "All")

	err = store.AddPeerToGroup(context.Background(), accountID, peerID, "cfefqs706sqkneg59g4h")
	require.NoError(t, err)

	groups, err = store.GetPeerGroups(context.Background(), LockingStrengthNone, accountID, peerID)
	require.NoError(t, err)
	assert.Len(t, groups, 2)
}

func TestSqlStore_GetAccountPeers(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/store_with_expired_peers.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	tests := []struct {
		name          string
		accountID     string
		nameFilter    string
		ipFilter      string
		expectedCount int
	}{
		{
			name:          "should retrieve peers for an existing account ID",
			accountID:     "bf1c8084-ba50-4ce7-9439-34653001fc3b",
			expectedCount: 4,
		},
		{
			name:          "should return no peers for a non-existing account ID",
			accountID:     "nonexistent",
			expectedCount: 0,
		},
		{
			name:          "should return no peers for an empty account ID",
			accountID:     "",
			expectedCount: 0,
		},
		{
			name:          "should filter peers by name",
			accountID:     "bf1c8084-ba50-4ce7-9439-34653001fc3b",
			nameFilter:    "expiredhost",
			expectedCount: 1,
		},
		{
			name:          "should filter peers by partial name",
			accountID:     "bf1c8084-ba50-4ce7-9439-34653001fc3b",
			nameFilter:    "host",
			expectedCount: 3,
		},
		{
			name:          "should filter peers by ip",
			accountID:     "bf1c8084-ba50-4ce7-9439-34653001fc3b",
			ipFilter:      "100.64.39.54",
			expectedCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			peers, err := store.GetAccountPeers(context.Background(), LockingStrengthNone, tt.accountID, tt.nameFilter, tt.ipFilter)
			require.NoError(t, err)
			require.Len(t, peers, tt.expectedCount)
		})
	}

}

func TestSqlStore_GetAccountPeersWithExpiration(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/store_with_expired_peers.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	tests := []struct {
		name          string
		accountID     string
		expectedCount int
	}{
		{
			name:          "should retrieve peers with expiration for an existing account ID",
			accountID:     "bf1c8084-ba50-4ce7-9439-34653001fc3b",
			expectedCount: 1,
		},
		{
			name:          "should return no peers with expiration for a non-existing account ID",
			accountID:     "nonexistent",
			expectedCount: 0,
		},
		{
			name:          "should return no peers with expiration for a empty account ID",
			accountID:     "",
			expectedCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			peers, err := store.GetAccountPeersWithExpiration(context.Background(), LockingStrengthNone, tt.accountID)
			require.NoError(t, err)
			require.Len(t, peers, tt.expectedCount)
		})
	}
}

func TestSqlStore_GetAccountPeersWithInactivity(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/store_with_expired_peers.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	tests := []struct {
		name          string
		accountID     string
		expectedCount int
	}{
		{
			name:          "should retrieve peers with inactivity for an existing account ID",
			accountID:     "bf1c8084-ba50-4ce7-9439-34653001fc3b",
			expectedCount: 1,
		},
		{
			name:          "should return no peers with inactivity for a non-existing account ID",
			accountID:     "nonexistent",
			expectedCount: 0,
		},
		{
			name:          "should return no peers with inactivity for an empty account ID",
			accountID:     "",
			expectedCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			peers, err := store.GetAccountPeersWithInactivity(context.Background(), LockingStrengthNone, tt.accountID)
			require.NoError(t, err)
			require.Len(t, peers, tt.expectedCount)
		})
	}
}

func TestSqlStore_GetAllEphemeralPeers(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/storev1.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	peers, err := store.GetAllEphemeralPeers(context.Background(), LockingStrengthNone)
	require.NoError(t, err)
	require.Len(t, peers, 1)
	require.True(t, peers[0].Ephemeral)
}

func TestSqlStore_GetUserPeers(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/store_with_expired_peers.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	tests := []struct {
		name          string
		accountID     string
		userID        string
		expectedCount int
	}{
		{
			name:          "should retrieve peers for existing account ID and user ID",
			accountID:     "bf1c8084-ba50-4ce7-9439-34653001fc3b",
			userID:        "f4f6d672-63fb-11ec-90d6-0242ac120003",
			expectedCount: 1,
		},
		{
			name:          "should return no peers for non-existing account ID with existing user ID",
			accountID:     "nonexistent",
			userID:        "f4f6d672-63fb-11ec-90d6-0242ac120003",
			expectedCount: 0,
		},
		{
			name:          "should return no peers for non-existing user ID with existing account ID",
			accountID:     "bf1c8084-ba50-4ce7-9439-34653001fc3b",
			userID:        "nonexistent_user",
			expectedCount: 0,
		},
		{
			name:          "should retrieve peers for another valid account ID and user ID",
			accountID:     "bf1c8084-ba50-4ce7-9439-34653001fc3b",
			userID:        "edafee4e-63fb-11ec-90d6-0242ac120003",
			expectedCount: 2,
		},
		{
			name:          "should return no peers for existing account ID with empty user ID",
			accountID:     "bf1c8084-ba50-4ce7-9439-34653001fc3b",
			userID:        "",
			expectedCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			peers, err := store.GetUserPeers(context.Background(), LockingStrengthNone, tt.accountID, tt.userID)
			require.NoError(t, err)
			require.Len(t, peers, tt.expectedCount)
		})
	}
}

func TestSqlStore_DeletePeer(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/store_with_expired_peers.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"
	peerID := "csrnkiq7qv9d8aitqd50"

	err = store.DeletePeer(context.Background(), accountID, peerID)
	require.NoError(t, err)

	peer, err := store.GetPeerByID(context.Background(), LockingStrengthNone, accountID, peerID)
	require.Error(t, err)
	require.Nil(t, peer)
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

func TestSqlStore_GetUserByUserID(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/extended-store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	tests := []struct {
		name        string
		userID      string
		expectError bool
	}{
		{
			name:        "retrieve existing user",
			userID:      "edafee4e-63fb-11ec-90d6-0242ac120003",
			expectError: false,
		},
		{
			name:        "retrieve non-existing user",
			userID:      "non-existing",
			expectError: true,
		},
		{
			name:        "retrieve with empty user ID",
			userID:      "",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			user, err := store.GetUserByUserID(context.Background(), LockingStrengthNone, tt.userID)
			if tt.expectError {
				require.Error(t, err)
				sErr, ok := status.FromError(err)
				require.True(t, ok)
				require.Equal(t, sErr.Type(), status.NotFound)
				require.Nil(t, user)
			} else {
				require.NoError(t, err)
				require.NotNil(t, user)
				require.Equal(t, tt.userID, user.Id)
			}
		})
	}
}

func TestSqlStore_GetUserByPATID(t *testing.T) {
	store, cleanUp, err := NewTestStoreFromSQL(context.Background(), "../testdata/store.sql", t.TempDir())
	t.Cleanup(cleanUp)
	assert.NoError(t, err)

	id := "9dj38s35-63fb-11ec-90d6-0242ac120003"

	user, err := store.GetUserByPATID(context.Background(), LockingStrengthNone, id)
	require.NoError(t, err)
	require.Equal(t, "f4f6d672-63fb-11ec-90d6-0242ac120003", user.Id)
}

func TestSqlStore_SaveUser(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/extended-store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"

	user := &types.User{
		Id:            "user-id",
		AccountID:     accountID,
		Role:          types.UserRoleAdmin,
		IsServiceUser: false,
		AutoGroups:    []string{"groupA", "groupB"},
		Blocked:       false,
		LastLogin:     util.ToPtr(time.Now().UTC()),
		CreatedAt:     time.Now().UTC().Add(-time.Hour),
		Issued:        types.UserIssuedIntegration,
	}
	err = store.SaveUser(context.Background(), user)
	require.NoError(t, err)

	saveUser, err := store.GetUserByUserID(context.Background(), LockingStrengthNone, user.Id)
	require.NoError(t, err)
	require.Equal(t, user.Id, saveUser.Id)
	require.Equal(t, user.AccountID, saveUser.AccountID)
	require.Equal(t, user.Role, saveUser.Role)
	require.Equal(t, user.AutoGroups, saveUser.AutoGroups)
	require.WithinDurationf(t, user.GetLastLogin(), saveUser.LastLogin.UTC(), time.Millisecond, "LastLogin should be equal")
	require.WithinDurationf(t, user.CreatedAt, saveUser.CreatedAt.UTC(), time.Millisecond, "CreatedAt should be equal")
	require.Equal(t, user.Issued, saveUser.Issued)
	require.Equal(t, user.Blocked, saveUser.Blocked)
	require.Equal(t, user.IsServiceUser, saveUser.IsServiceUser)
}

func TestSqlStore_SaveUsers(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/extended-store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"

	accountUsers, err := store.GetAccountUsers(context.Background(), LockingStrengthNone, accountID)
	require.NoError(t, err)
	require.Len(t, accountUsers, 2)

	users := []*types.User{
		{
			Id:         "user-1",
			AccountID:  accountID,
			Issued:     "api",
			AutoGroups: []string{"groupA", "groupB"},
		},
		{
			Id:         "user-2",
			AccountID:  accountID,
			Issued:     "integration",
			AutoGroups: []string{"groupA"},
		},
	}
	err = store.SaveUsers(context.Background(), users)
	require.NoError(t, err)

	accountUsers, err = store.GetAccountUsers(context.Background(), LockingStrengthNone, accountID)
	require.NoError(t, err)
	require.Len(t, accountUsers, 4)

	users[1].AutoGroups = []string{"groupA", "groupC"}
	err = store.SaveUsers(context.Background(), users)
	require.NoError(t, err)

	user, err := store.GetUserByUserID(context.Background(), LockingStrengthNone, users[1].Id)
	require.NoError(t, err)
	require.Equal(t, users[1].AutoGroups, user.AutoGroups)
}

func TestSqlStore_SaveUserWithEncryption(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/extended-store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	// Enable encryption
	key, err := crypt.GenerateKey()
	require.NoError(t, err)
	fieldEncrypt, err := crypt.NewFieldEncrypt(key)
	require.NoError(t, err)
	store.SetFieldEncrypt(fieldEncrypt)

	accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"

	// rawUser is used to read raw (potentially encrypted) data from the database
	// without any gorm hooks or automatic decryption
	type rawUser struct {
		Id    string
		Email string
		Name  string
	}

	t.Run("save user with empty email and name", func(t *testing.T) {
		user := &types.User{
			Id:         "user-empty-fields",
			AccountID:  accountID,
			Role:       types.UserRoleUser,
			Email:      "",
			Name:       "",
			AutoGroups: []string{"groupA"},
		}
		err = store.SaveUser(context.Background(), user)
		require.NoError(t, err)

		// Verify using direct database query that empty strings remain empty (not encrypted)
		var raw rawUser
		err = store.(*SqlStore).db.Table("users").Select("id, email, name").Where("id = ?", user.Id).First(&raw).Error
		require.NoError(t, err)
		require.Equal(t, "", raw.Email, "empty email should remain empty in database")
		require.Equal(t, "", raw.Name, "empty name should remain empty in database")

		// Verify manual decryption returns empty strings
		decryptedEmail, err := fieldEncrypt.Decrypt(raw.Email)
		require.NoError(t, err)
		require.Equal(t, "", decryptedEmail)

		decryptedName, err := fieldEncrypt.Decrypt(raw.Name)
		require.NoError(t, err)
		require.Equal(t, "", decryptedName)
	})

	t.Run("save user with email and name", func(t *testing.T) {
		user := &types.User{
			Id:         "user-with-fields",
			AccountID:  accountID,
			Role:       types.UserRoleAdmin,
			Email:      "test@example.com",
			Name:       "Test User",
			AutoGroups: []string{"groupB"},
		}
		err = store.SaveUser(context.Background(), user)
		require.NoError(t, err)

		// Verify using direct database query that the data is encrypted (not plaintext)
		var raw rawUser
		err = store.(*SqlStore).db.Table("users").Select("id, email, name").Where("id = ?", user.Id).First(&raw).Error
		require.NoError(t, err)
		require.NotEqual(t, "test@example.com", raw.Email, "email should be encrypted in database")
		require.NotEqual(t, "Test User", raw.Name, "name should be encrypted in database")

		// Verify manual decryption returns correct values
		decryptedEmail, err := fieldEncrypt.Decrypt(raw.Email)
		require.NoError(t, err)
		require.Equal(t, "test@example.com", decryptedEmail)

		decryptedName, err := fieldEncrypt.Decrypt(raw.Name)
		require.NoError(t, err)
		require.Equal(t, "Test User", decryptedName)
	})

	t.Run("save multiple users with mixed fields", func(t *testing.T) {
		users := []*types.User{
			{
				Id:        "batch-user-1",
				AccountID: accountID,
				Email:     "",
				Name:      "",
			},
			{
				Id:        "batch-user-2",
				AccountID: accountID,
				Email:     "batch@example.com",
				Name:      "Batch User",
			},
		}
		err = store.SaveUsers(context.Background(), users)
		require.NoError(t, err)

		// Verify first user (empty fields) using direct database query
		var raw1 rawUser
		err = store.(*SqlStore).db.Table("users").Select("id, email, name").Where("id = ?", "batch-user-1").First(&raw1).Error
		require.NoError(t, err)
		require.Equal(t, "", raw1.Email, "empty email should remain empty in database")
		require.Equal(t, "", raw1.Name, "empty name should remain empty in database")

		// Verify second user (with fields) using direct database query
		var raw2 rawUser
		err = store.(*SqlStore).db.Table("users").Select("id, email, name").Where("id = ?", "batch-user-2").First(&raw2).Error
		require.NoError(t, err)
		require.NotEqual(t, "batch@example.com", raw2.Email, "email should be encrypted in database")
		require.NotEqual(t, "Batch User", raw2.Name, "name should be encrypted in database")

		// Verify manual decryption returns empty strings for first user
		decryptedEmail1, err := fieldEncrypt.Decrypt(raw1.Email)
		require.NoError(t, err)
		require.Equal(t, "", decryptedEmail1)

		decryptedName1, err := fieldEncrypt.Decrypt(raw1.Name)
		require.NoError(t, err)
		require.Equal(t, "", decryptedName1)

		// Verify manual decryption returns correct values for second user
		decryptedEmail2, err := fieldEncrypt.Decrypt(raw2.Email)
		require.NoError(t, err)
		require.Equal(t, "batch@example.com", decryptedEmail2)

		decryptedName2, err := fieldEncrypt.Decrypt(raw2.Name)
		require.NoError(t, err)
		require.Equal(t, "Batch User", decryptedName2)
	})
}

func TestSqlStore_DeleteUser(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/extended-store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"
	userID := "f4f6d672-63fb-11ec-90d6-0242ac120003"

	err = store.DeleteUser(context.Background(), accountID, userID)
	require.NoError(t, err)

	user, err := store.GetUserByUserID(context.Background(), LockingStrengthNone, userID)
	require.Error(t, err)
	require.Nil(t, user)

	userPATs, err := store.GetUserPATs(context.Background(), LockingStrengthNone, userID)
	require.NoError(t, err)
	require.Len(t, userPATs, 0)
}

func TestSqlStore_GetPATByID(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/extended-store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	userID := "f4f6d672-63fb-11ec-90d6-0242ac120003"

	tests := []struct {
		name        string
		patID       string
		expectError bool
	}{
		{
			name:        "retrieve existing PAT",
			patID:       "9dj38s35-63fb-11ec-90d6-0242ac120003",
			expectError: false,
		},
		{
			name:        "retrieve non-existing PAT",
			patID:       "non-existing",
			expectError: true,
		},
		{
			name:        "retrieve with empty PAT ID",
			patID:       "",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pat, err := store.GetPATByID(context.Background(), LockingStrengthNone, userID, tt.patID)
			if tt.expectError {
				require.Error(t, err)
				sErr, ok := status.FromError(err)
				require.True(t, ok)
				require.Equal(t, sErr.Type(), status.NotFound)
				require.Nil(t, pat)
			} else {
				require.NoError(t, err)
				require.NotNil(t, pat)
				require.Equal(t, tt.patID, pat.ID)
			}
		})
	}
}

func TestSqlStore_GetUserPATs(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/extended-store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	userPATs, err := store.GetUserPATs(context.Background(), LockingStrengthNone, "f4f6d672-63fb-11ec-90d6-0242ac120003")
	require.NoError(t, err)
	require.Len(t, userPATs, 1)
}

func TestSqlStore_GetPATByHashedToken(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/extended-store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	pat, err := store.GetPATByHashedToken(context.Background(), LockingStrengthNone, "SoMeHaShEdToKeN")
	require.NoError(t, err)
	require.Equal(t, "9dj38s35-63fb-11ec-90d6-0242ac120003", pat.ID)
}

func TestSqlStore_MarkPATUsed(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/extended-store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	userID := "f4f6d672-63fb-11ec-90d6-0242ac120003"
	patID := "9dj38s35-63fb-11ec-90d6-0242ac120003"

	err = store.MarkPATUsed(context.Background(), patID)
	require.NoError(t, err)

	pat, err := store.GetPATByID(context.Background(), LockingStrengthNone, userID, patID)
	require.NoError(t, err)
	now := time.Now().UTC()
	require.WithinRange(t, pat.LastUsed.UTC(), now.Add(-15*time.Second), now, "LastUsed should be within 1 second of now")
}

func TestSqlStore_SavePAT(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/extended-store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	userID := "edafee4e-63fb-11ec-90d6-0242ac120003"

	pat := &types.PersonalAccessToken{
		ID:             "pat-id",
		UserID:         userID,
		Name:           "token",
		HashedToken:    "SoMeHaShEdToKeN",
		ExpirationDate: util.ToPtr(time.Now().UTC().Add(12 * time.Hour)),
		CreatedBy:      userID,
		CreatedAt:      time.Now().UTC().Add(time.Hour),
		LastUsed:       util.ToPtr(time.Now().UTC().Add(-15 * time.Minute)),
	}
	err = store.SavePAT(context.Background(), pat)
	require.NoError(t, err)

	savePAT, err := store.GetPATByID(context.Background(), LockingStrengthNone, userID, pat.ID)
	require.NoError(t, err)
	require.Equal(t, pat.ID, savePAT.ID)
	require.Equal(t, pat.UserID, savePAT.UserID)
	require.Equal(t, pat.HashedToken, savePAT.HashedToken)
	require.Equal(t, pat.CreatedBy, savePAT.CreatedBy)
	require.WithinDurationf(t, pat.GetExpirationDate(), savePAT.ExpirationDate.UTC(), time.Millisecond, "ExpirationDate should be equal")
	require.WithinDurationf(t, pat.CreatedAt, savePAT.CreatedAt.UTC(), time.Millisecond, "CreatedAt should be equal")
	require.WithinDurationf(t, pat.GetLastUsed(), savePAT.LastUsed.UTC(), time.Millisecond, "LastUsed should be equal")
}

func TestSqlStore_DeletePAT(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/extended-store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	userID := "f4f6d672-63fb-11ec-90d6-0242ac120003"
	patID := "9dj38s35-63fb-11ec-90d6-0242ac120003"

	err = store.DeletePAT(context.Background(), userID, patID)
	require.NoError(t, err)

	pat, err := store.GetPATByID(context.Background(), LockingStrengthNone, userID, patID)
	require.Error(t, err)
	require.Nil(t, pat)
}

func TestSqlStore_SaveUsers_LargeBatch(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/extended-store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"

	accountUsers, err := store.GetAccountUsers(context.Background(), LockingStrengthNone, accountID)
	require.NoError(t, err)
	require.Len(t, accountUsers, 2)

	usersToSave := make([]*types.User, 0)

	for i := 1; i <= 8000; i++ {
		usersToSave = append(usersToSave, &types.User{
			Id:        fmt.Sprintf("user-%d", i),
			AccountID: accountID,
			Role:      types.UserRoleUser,
		})
	}

	err = store.SaveUsers(context.Background(), usersToSave)
	require.NoError(t, err)

	accountUsers, err = store.GetAccountUsers(context.Background(), LockingStrengthNone, accountID)
	require.NoError(t, err)
	require.Equal(t, 8002, len(accountUsers))
}

func TestSqlStore_SaveGroups_LargeBatch(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/extended-store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"

	accountGroups, err := store.GetAccountGroups(context.Background(), LockingStrengthNone, accountID)
	require.NoError(t, err)
	require.Len(t, accountGroups, 3)

	groupsToSave := make([]*types.Group, 0)

	for i := 1; i <= 8000; i++ {
		groupsToSave = append(groupsToSave, &types.Group{
			ID:        fmt.Sprintf("%d", i),
			AccountID: accountID,
			Name:      fmt.Sprintf("group-%d", i),
		})
	}

	err = store.CreateGroups(context.Background(), accountID, groupsToSave)
	require.NoError(t, err)

	accountGroups, err = store.GetAccountGroups(context.Background(), LockingStrengthNone, accountID)
	require.NoError(t, err)
	require.Equal(t, 8003, len(accountGroups))
}
func TestSqlStore_GetAccountRoutes(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/extended-store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	tests := []struct {
		name          string
		accountID     string
		expectedCount int
	}{
		{
			name:          "retrieve routes by existing account ID",
			accountID:     "bf1c8084-ba50-4ce7-9439-34653001fc3b",
			expectedCount: 1,
		},
		{
			name:          "non-existing account ID",
			accountID:     "nonexistent",
			expectedCount: 0,
		},
		{
			name:          "empty account ID",
			accountID:     "",
			expectedCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			routes, err := store.GetAccountRoutes(context.Background(), LockingStrengthNone, tt.accountID)
			require.NoError(t, err)
			require.Len(t, routes, tt.expectedCount)
		})
	}
}

func TestSqlStore_GetRouteByID(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/extended-store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"
	tests := []struct {
		name        string
		routeID     string
		expectError bool
	}{
		{
			name:        "retrieve existing route",
			routeID:     "ct03t427qv97vmtmglog",
			expectError: false,
		},
		{
			name:        "retrieve non-existing route",
			routeID:     "non-existing",
			expectError: true,
		},
		{
			name:        "retrieve with empty route ID",
			routeID:     "",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			route, err := store.GetRouteByID(context.Background(), LockingStrengthNone, accountID, tt.routeID)
			if tt.expectError {
				require.Error(t, err)
				sErr, ok := status.FromError(err)
				require.True(t, ok)
				require.Equal(t, sErr.Type(), status.NotFound)
				require.Nil(t, route)
			} else {
				require.NoError(t, err)
				require.NotNil(t, route)
				require.Equal(t, tt.routeID, string(route.ID))
			}
		})
	}
}

func TestSqlStore_SaveRoute(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/extended-store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"

	route := &nbroute.Route{
		ID:                  "route-id",
		AccountID:           accountID,
		Network:             netip.MustParsePrefix("10.10.0.0/16"),
		NetID:               "netID",
		PeerGroups:          []string{"routeA"},
		NetworkType:         nbroute.IPv4Network,
		Masquerade:          true,
		Metric:              9999,
		Enabled:             true,
		Groups:              []string{"groupA"},
		AccessControlGroups: []string{},
	}
	err = store.SaveRoute(context.Background(), route)
	require.NoError(t, err)

	saveRoute, err := store.GetRouteByID(context.Background(), LockingStrengthNone, accountID, string(route.ID))
	require.NoError(t, err)
	require.Equal(t, route, saveRoute)

}

func TestSqlStore_DeleteRoute(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/extended-store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"
	routeID := "ct03t427qv97vmtmglog"

	err = store.DeleteRoute(context.Background(), accountID, routeID)
	require.NoError(t, err)

	route, err := store.GetRouteByID(context.Background(), LockingStrengthNone, accountID, routeID)
	require.Error(t, err)
	require.Nil(t, route)
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

func TestSqlStore_GetAccountOnboarding(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	accountID := "9439-34653001fc3b-bf1c8084-ba50-4ce7"
	a, err := store.GetAccount(context.Background(), accountID)
	require.NoError(t, err)
	t.Logf("Onboarding: %+v", a.Onboarding)
	err = store.SaveAccount(context.Background(), a)
	require.NoError(t, err)
	onboarding, err := store.GetAccountOnboarding(context.Background(), accountID)
	require.NoError(t, err)
	require.NotNil(t, onboarding)
	require.Equal(t, accountID, onboarding.AccountID)
	require.Equal(t, time.Date(2024, time.October, 2, 14, 1, 38, 210000000, time.UTC), onboarding.CreatedAt.UTC())
}

func TestSqlStore_SaveAccountOnboarding(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)
	t.Run("New onboarding should be saved correctly", func(t *testing.T) {
		accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"
		onboarding := &types.AccountOnboarding{
			AccountID:             accountID,
			SignupFormPending:     true,
			OnboardingFlowPending: true,
		}

		err = store.SaveAccountOnboarding(context.Background(), onboarding)
		require.NoError(t, err)

		savedOnboarding, err := store.GetAccountOnboarding(context.Background(), accountID)
		require.NoError(t, err)
		require.Equal(t, onboarding.SignupFormPending, savedOnboarding.SignupFormPending)
		require.Equal(t, onboarding.OnboardingFlowPending, savedOnboarding.OnboardingFlowPending)
	})

	t.Run("Existing onboarding should be updated correctly", func(t *testing.T) {
		accountID := "9439-34653001fc3b-bf1c8084-ba50-4ce7"
		onboarding, err := store.GetAccountOnboarding(context.Background(), accountID)
		require.NoError(t, err)

		onboarding.OnboardingFlowPending = !onboarding.OnboardingFlowPending
		onboarding.SignupFormPending = !onboarding.SignupFormPending

		err = store.SaveAccountOnboarding(context.Background(), onboarding)
		require.NoError(t, err)

		savedOnboarding, err := store.GetAccountOnboarding(context.Background(), accountID)
		require.NoError(t, err)
		require.Equal(t, onboarding.SignupFormPending, savedOnboarding.SignupFormPending)
		require.Equal(t, onboarding.OnboardingFlowPending, savedOnboarding.OnboardingFlowPending)
	})
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

func BenchmarkGetAccountPeers(b *testing.B) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/store_with_expired_peers.sql", b.TempDir())
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(cleanup)

	numberOfPeers := 1000
	numberOfGroups := 200
	numberOfPeersPerGroup := 500
	accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"

	peers := make([]*nbpeer.Peer, 0, numberOfPeers)
	for i := 0; i < numberOfPeers; i++ {
		peer := &nbpeer.Peer{
			ID:        fmt.Sprintf("peer-%d", i),
			AccountID: accountID,
			Key:       fmt.Sprintf("key-%d", i),
			DNSLabel:  fmt.Sprintf("peer%d.example.com", i),
			IP:        intToIPv4(uint32(i)),
		}
		err = store.AddPeerToAccount(context.Background(), peer)
		if err != nil {
			b.Fatalf("Failed to add peer: %v", err)
		}
		peers = append(peers, peer)
	}

	for i := 0; i < numberOfGroups; i++ {
		groupID := fmt.Sprintf("group-%d", i)
		group := &types.Group{
			ID:        groupID,
			AccountID: accountID,
		}
		err = store.CreateGroup(context.Background(), group)
		if err != nil {
			b.Fatalf("Failed to create group: %v", err)
		}
		for j := 0; j < numberOfPeersPerGroup; j++ {
			peerIndex := (i*numberOfPeersPerGroup + j) % numberOfPeers
			err = store.AddPeerToGroup(context.Background(), accountID, peers[peerIndex].ID, groupID)
			if err != nil {
				b.Fatalf("Failed to add peer to group: %v", err)
			}
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := store.GetPeerGroups(context.Background(), LockingStrengthNone, accountID, peers[i%numberOfPeers].ID)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func intToIPv4(n uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, n)
	return ip
}

func TestSqlStore_GetPeersByGroupIDs(t *testing.T) {
	accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"

	group1ID := "test-group-1"
	group2ID := "test-group-2"
	emptyGroupID := "empty-group"

	peer1 := "cfefqs706sqkneg59g4g"
	peer2 := "cfeg6sf06sqkneg59g50"

	tests := []struct {
		name          string
		groupIDs      []string
		expectedPeers []string
		expectedCount int
	}{
		{
			name:          "retrieve peers from single group with multiple peers",
			groupIDs:      []string{group1ID},
			expectedPeers: []string{peer1, peer2},
			expectedCount: 2,
		},
		{
			name:          "retrieve peers from single group with one peer",
			groupIDs:      []string{group2ID},
			expectedPeers: []string{peer1},
			expectedCount: 1,
		},
		{
			name:          "retrieve peers from multiple groups (with overlap)",
			groupIDs:      []string{group1ID, group2ID},
			expectedPeers: []string{peer1, peer2}, // should deduplicate
			expectedCount: 2,
		},
		{
			name:          "retrieve peers from existing 'All' group",
			groupIDs:      []string{"cfefqs706sqkneg59g3g"}, // All group from test data
			expectedPeers: []string{peer1, peer2},
			expectedCount: 2,
		},
		{
			name:          "retrieve peers from empty group",
			groupIDs:      []string{emptyGroupID},
			expectedPeers: []string{},
			expectedCount: 0,
		},
		{
			name:          "retrieve peers from non-existing group",
			groupIDs:      []string{"non-existing-group"},
			expectedPeers: []string{},
			expectedCount: 0,
		},
		{
			name:          "empty group IDs list",
			groupIDs:      []string{},
			expectedPeers: []string{},
			expectedCount: 0,
		},
		{
			name:          "mix of existing and non-existing groups",
			groupIDs:      []string{group1ID, "non-existing-group"},
			expectedPeers: []string{peer1, peer2},
			expectedCount: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/store_policy_migrate.sql", t.TempDir())
			t.Cleanup(cleanup)
			require.NoError(t, err)

			ctx := context.Background()

			groups := []*types.Group{
				{
					ID:        group1ID,
					AccountID: accountID,
				},
				{
					ID:        group2ID,
					AccountID: accountID,
				},
			}
			require.NoError(t, store.CreateGroups(ctx, accountID, groups))

			require.NoError(t, store.AddPeerToGroup(ctx, accountID, peer1, group1ID))
			require.NoError(t, store.AddPeerToGroup(ctx, accountID, peer2, group1ID))
			require.NoError(t, store.AddPeerToGroup(ctx, accountID, peer1, group2ID))

			peers, err := store.GetPeersByGroupIDs(ctx, accountID, tt.groupIDs)
			require.NoError(t, err)
			require.Len(t, peers, tt.expectedCount)

			if tt.expectedCount > 0 {
				actualPeerIDs := make([]string, len(peers))
				for i, peer := range peers {
					actualPeerIDs[i] = peer.ID
				}
				assert.ElementsMatch(t, tt.expectedPeers, actualPeerIDs)

				// Verify all returned peers belong to the correct account
				for _, peer := range peers {
					assert.Equal(t, accountID, peer.AccountID)
				}
			}
		})
	}
}

func TestSqlStore_GetUserIDByPeerKey(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/extended-store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	existingAccountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"
	userID := "test-user-123"
	peerKey := "peer-key-abc"

	peer := &nbpeer.Peer{
		ID:        "test-peer-1",
		Key:       peerKey,
		AccountID: existingAccountID,
		UserID:    userID,
		IP:        net.IP{10, 0, 0, 1},
		DNSLabel:  "test-peer-1",
	}

	err = store.AddPeerToAccount(context.Background(), peer)
	require.NoError(t, err)

	retrievedUserID, err := store.GetUserIDByPeerKey(context.Background(), LockingStrengthNone, peerKey)
	require.NoError(t, err)
	assert.Equal(t, userID, retrievedUserID)
}

func TestSqlStore_GetUserIDByPeerKey_NotFound(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/extended-store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	nonExistentPeerKey := "non-existent-peer-key"

	userID, err := store.GetUserIDByPeerKey(context.Background(), LockingStrengthNone, nonExistentPeerKey)
	require.Error(t, err)
	assert.Equal(t, "", userID)
}

func TestSqlStore_GetUserIDByPeerKey_NoUserID(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/extended-store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	existingAccountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"
	peerKey := "peer-key-abc"

	peer := &nbpeer.Peer{
		ID:        "test-peer-1",
		Key:       peerKey,
		AccountID: existingAccountID,
		UserID:    "",
		IP:        net.IP{10, 0, 0, 1},
		DNSLabel:  "test-peer-1",
	}

	err = store.AddPeerToAccount(context.Background(), peer)
	require.NoError(t, err)

	retrievedUserID, err := store.GetUserIDByPeerKey(context.Background(), LockingStrengthNone, peerKey)
	require.NoError(t, err)
	assert.Equal(t, "", retrievedUserID)
}

func TestSqlStore_ApproveAccountPeers(t *testing.T) {
	runTestForAllEngines(t, "", func(t *testing.T, store Store) {
		accountID := "test-account"
		ctx := context.Background()

		account := newAccountWithId(ctx, accountID, "testuser", "example.com")
		err := store.SaveAccount(ctx, account)
		require.NoError(t, err)

		peers := []*nbpeer.Peer{
			{
				ID:        "peer1",
				AccountID: accountID,
				DNSLabel:  "peer1.netbird.cloud",
				Key:       "peer1-key",
				IP:        net.ParseIP("100.64.0.1"),
				Status: &nbpeer.PeerStatus{
					RequiresApproval: true,
					LastSeen:         time.Now().UTC(),
				},
			},
			{
				ID:        "peer2",
				AccountID: accountID,
				DNSLabel:  "peer2.netbird.cloud",
				Key:       "peer2-key",
				IP:        net.ParseIP("100.64.0.2"),
				Status: &nbpeer.PeerStatus{
					RequiresApproval: true,
					LastSeen:         time.Now().UTC(),
				},
			},
			{
				ID:        "peer3",
				AccountID: accountID,
				DNSLabel:  "peer3.netbird.cloud",
				Key:       "peer3-key",
				IP:        net.ParseIP("100.64.0.3"),
				Status: &nbpeer.PeerStatus{
					RequiresApproval: false,
					LastSeen:         time.Now().UTC(),
				},
			},
		}

		for _, peer := range peers {
			err = store.AddPeerToAccount(ctx, peer)
			require.NoError(t, err)
		}

		t.Run("approve all pending peers", func(t *testing.T) {
			count, err := store.ApproveAccountPeers(ctx, accountID)
			require.NoError(t, err)
			assert.Equal(t, 2, count)

			allPeers, err := store.GetAccountPeers(ctx, LockingStrengthNone, accountID, "", "")
			require.NoError(t, err)

			for _, peer := range allPeers {
				assert.False(t, peer.Status.RequiresApproval, "peer %s should not require approval", peer.ID)
			}
		})

		t.Run("no peers to approve", func(t *testing.T) {
			count, err := store.ApproveAccountPeers(ctx, accountID)
			require.NoError(t, err)
			assert.Equal(t, 0, count)
		})

		t.Run("non-existent account", func(t *testing.T) {
			count, err := store.ApproveAccountPeers(ctx, "non-existent")
			require.NoError(t, err)
			assert.Equal(t, 0, count)
		})
	})
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
