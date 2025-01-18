package store

import (
	"context"
	"crypto/sha256"
	b64 "encoding/base64"
	"fmt"
	"math/rand"
	"net"
	"net/netip"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/rs/xid"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	nbdns "github.com/netbirdio/netbird/dns"
	resourceTypes "github.com/netbirdio/netbird/management/server/networks/resources/types"
	routerTypes "github.com/netbirdio/netbird/management/server/networks/routers/types"
	networkTypes "github.com/netbirdio/netbird/management/server/networks/types"
	"github.com/netbirdio/netbird/management/server/posture"
	"github.com/netbirdio/netbird/management/server/types"

	route2 "github.com/netbirdio/netbird/route"

	"github.com/netbirdio/netbird/management/server/status"

	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	nbroute "github.com/netbirdio/netbird/route"
)

func TestSqlite_NewStore(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("The SQLite store is not properly supported by Windows yet")
	}

	t.Setenv("NETBIRD_STORE_ENGINE", string(SqliteStoreEngine))
	store, cleanUp, err := NewTestStoreFromSQL(context.Background(), "", t.TempDir())
	t.Cleanup(cleanUp)
	assert.NoError(t, err)

	if len(store.GetAllAccounts(context.Background())) != 0 {
		t.Errorf("expected to create a new empty Accounts map when creating a new FileStore")
	}
}

func TestSqlite_SaveAccount_Large(t *testing.T) {
	if (os.Getenv("CI") == "true" && runtime.GOOS == "darwin") || runtime.GOOS == "windows" {
		t.Skip("skip CI tests on darwin and windows")
	}

	t.Run("SQLite", func(t *testing.T) {
		t.Setenv("NETBIRD_STORE_ENGINE", string(SqliteStoreEngine))
		store, cleanUp, err := NewTestStoreFromSQL(context.Background(), "", t.TempDir())
		t.Cleanup(cleanUp)
		assert.NoError(t, err)
		runLargeTest(t, store)
	})

	// create store outside to have a better time counter for the test
	t.Setenv("NETBIRD_STORE_ENGINE", string(SqliteStoreEngine))
	store, cleanUp, err := NewTestStoreFromSQL(context.Background(), "", t.TempDir())
	t.Cleanup(cleanUp)
	assert.NoError(t, err)
	t.Run("PostgreSQL", func(t *testing.T) {
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
		route := &route2.Route{
			ID:          route2.ID(fmt.Sprintf("network-id-%d", n)),
			Description: "base route",
			NetID:       route2.NetID(fmt.Sprintf("network-id-%d", n)),
			Network:     netip.MustParsePrefix(netIP.String() + "/24"),
			NetworkType: route2.IPv4Network,
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

func TestSqlite_SaveAccount(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("The SQLite store is not properly supported by Windows yet")
	}

	t.Setenv("NETBIRD_STORE_ENGINE", string(SqliteStoreEngine))
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

func TestSqlite_DeleteAccount(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("The SQLite store is not properly supported by Windows yet")
	}

	t.Setenv("NETBIRD_STORE_ENGINE", string(SqliteStoreEngine))
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

	for _, network := range account.Networks {
		routers, err := store.GetNetworkRoutersByNetID(context.Background(), LockingStrengthShare, account.Id, network.ID)
		require.NoError(t, err, "expecting no error after removing DeleteAccount when searching for network routers")
		require.Len(t, routers, 0, "expecting no network routers to be found after DeleteAccount")

		resources, err := store.GetNetworkResourcesByNetID(context.Background(), LockingStrengthShare, account.Id, network.ID)
		require.NoError(t, err, "expecting no error after removing DeleteAccount when searching for network resources")
		require.Len(t, resources, 0, "expecting no network resources to be found after DeleteAccount")
	}
}

func TestSqlite_GetAccount(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("The SQLite store is not properly supported by Windows yet")
	}

	t.Setenv("NETBIRD_STORE_ENGINE", string(SqliteStoreEngine))
	store, cleanUp, err := NewTestStoreFromSQL(context.Background(), "../testdata/store.sql", t.TempDir())
	t.Cleanup(cleanUp)
	assert.NoError(t, err)

	id := "bf1c8084-ba50-4ce7-9439-34653001fc3b"

	account, err := store.GetAccount(context.Background(), id)
	require.NoError(t, err)
	require.Equal(t, id, account.Id, "account id should match")

	_, err = store.GetAccount(context.Background(), "non-existing-account")
	assert.Error(t, err)
	parsedErr, ok := status.FromError(err)
	require.True(t, ok)
	require.Equal(t, status.NotFound, parsedErr.Type(), "should return not found error")
}

func TestSqlite_SavePeer(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("The SQLite store is not properly supported by Windows yet")
	}

	t.Setenv("NETBIRD_STORE_ENGINE", string(SqliteStoreEngine))
	store, cleanUp, err := NewTestStoreFromSQL(context.Background(), "../testdata/store.sql", t.TempDir())
	t.Cleanup(cleanUp)
	assert.NoError(t, err)

	account, err := store.GetAccount(context.Background(), "bf1c8084-ba50-4ce7-9439-34653001fc3b")
	require.NoError(t, err)

	// save status of non-existing peer
	peer := &nbpeer.Peer{
		Key:    "peerkey",
		ID:     "testpeer",
		IP:     net.IP{127, 0, 0, 1},
		Meta:   nbpeer.PeerSystemMeta{Hostname: "testingpeer"},
		Name:   "peer name",
		Status: &nbpeer.PeerStatus{Connected: true, LastSeen: time.Now().UTC()},
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
	assert.Equal(t, updatedPeer.Status, actual.Status)
	assert.Equal(t, updatedPeer.Meta, actual.Meta)
}

func TestSqlite_SavePeerStatus(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("The SQLite store is not properly supported by Windows yet")
	}

	t.Setenv("NETBIRD_STORE_ENGINE", string(SqliteStoreEngine))
	store, cleanUp, err := NewTestStoreFromSQL(context.Background(), "../testdata/store.sql", t.TempDir())
	t.Cleanup(cleanUp)
	assert.NoError(t, err)

	account, err := store.GetAccount(context.Background(), "bf1c8084-ba50-4ce7-9439-34653001fc3b")
	require.NoError(t, err)

	// save status of non-existing peer
	newStatus := nbpeer.PeerStatus{Connected: false, LastSeen: time.Now().UTC()}
	err = store.SavePeerStatus(account.Id, "non-existing-peer", newStatus)
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

	err = store.SavePeerStatus(account.Id, "testpeer", newStatus)
	require.NoError(t, err)

	account, err = store.GetAccount(context.Background(), account.Id)
	require.NoError(t, err)

	actual := account.Peers["testpeer"].Status
	assert.Equal(t, newStatus, *actual)

	newStatus.Connected = true

	err = store.SavePeerStatus(account.Id, "testpeer", newStatus)
	require.NoError(t, err)

	account, err = store.GetAccount(context.Background(), account.Id)
	require.NoError(t, err)

	actual = account.Peers["testpeer"].Status
	assert.Equal(t, newStatus, *actual)
}

func TestSqlite_SavePeerLocation(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("The SQLite store is not properly supported by Windows yet")
	}

	t.Setenv("NETBIRD_STORE_ENGINE", string(SqliteStoreEngine))
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
		Meta: nbpeer.PeerSystemMeta{},
	}
	// error is expected as peer is not in store yet
	err = store.SavePeerLocation(account.Id, peer)
	assert.Error(t, err)

	account.Peers[peer.ID] = peer
	err = store.SaveAccount(context.Background(), account)
	require.NoError(t, err)

	peer.Location.ConnectionIP = net.ParseIP("35.1.1.1")
	peer.Location.CountryCode = "DE"
	peer.Location.CityName = "Berlin"
	peer.Location.GeoNameID = 2950159

	err = store.SavePeerLocation(account.Id, account.Peers[peer.ID])
	assert.NoError(t, err)

	account, err = store.GetAccount(context.Background(), account.Id)
	require.NoError(t, err)

	actual := account.Peers[peer.ID].Location
	assert.Equal(t, peer.Location, actual)

	peer.ID = "non-existing-peer"
	err = store.SavePeerLocation(account.Id, peer)
	assert.Error(t, err)
	parsedErr, ok := status.FromError(err)
	require.True(t, ok)
	require.Equal(t, status.NotFound, parsedErr.Type(), "should return not found error")
}

func TestSqlite_TestGetAccountByPrivateDomain(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("The SQLite store is not properly supported by Windows yet")
	}

	t.Setenv("NETBIRD_STORE_ENGINE", string(SqliteStoreEngine))
	store, cleanUp, err := NewTestStoreFromSQL(context.Background(), "../testdata/store.sql", t.TempDir())
	t.Cleanup(cleanUp)
	assert.NoError(t, err)

	existingDomain := "test.com"

	account, err := store.GetAccountByPrivateDomain(context.Background(), existingDomain)
	require.NoError(t, err, "should found account")
	require.Equal(t, existingDomain, account.Domain, "domains should match")

	_, err = store.GetAccountByPrivateDomain(context.Background(), "missing-domain.com")
	require.Error(t, err, "should return error on domain lookup")
	parsedErr, ok := status.FromError(err)
	require.True(t, ok)
	require.Equal(t, status.NotFound, parsedErr.Type(), "should return not found error")
}

func TestSqlite_GetTokenIDByHashedToken(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("The SQLite store is not properly supported by Windows yet")
	}

	t.Setenv("NETBIRD_STORE_ENGINE", string(SqliteStoreEngine))
	store, cleanUp, err := NewTestStoreFromSQL(context.Background(), "../testdata/store.sql", t.TempDir())
	t.Cleanup(cleanUp)
	assert.NoError(t, err)

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
}

func TestSqlite_GetUserByTokenID(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("The SQLite store is not properly supported by Windows yet")
	}

	t.Setenv("NETBIRD_STORE_ENGINE", string(SqliteStoreEngine))
	store, cleanUp, err := NewTestStoreFromSQL(context.Background(), "../testdata/store.sql", t.TempDir())
	t.Cleanup(cleanUp)
	assert.NoError(t, err)

	id := "9dj38s35-63fb-11ec-90d6-0242ac120003"

	user, err := store.GetUserByTokenID(context.Background(), id)
	require.NoError(t, err)
	require.Equal(t, id, user.PATs[id].ID)

	_, err = store.GetUserByTokenID(context.Background(), "non-existing-id")
	require.Error(t, err)
	parsedErr, ok := status.FromError(err)
	require.True(t, ok)
	require.Equal(t, status.NotFound, parsedErr.Type(), "should return not found error")
}

func TestMigrate(t *testing.T) {
	if (os.Getenv("CI") == "true" && runtime.GOOS == "darwin") || runtime.GOOS == "windows" {
		t.Skip("skip CI tests on darwin and windows")
	}

	// TODO: figure out why this fails on postgres
	t.Setenv("NETBIRD_STORE_ENGINE", string(SqliteStoreEngine))

	store, cleanUp, err := NewTestStoreFromSQL(context.Background(), "", t.TempDir())
	t.Cleanup(cleanUp)
	assert.NoError(t, err)

	err = migrate(context.Background(), store.(*SqlStore).db)
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
		route2.Route
		Network    netip.Prefix `gorm:"serializer:gob"`
		PeerGroups []string     `gorm:"serializer:gob"`
	}

	prefix := netip.MustParsePrefix("11.0.0.0/24")
	rt := &route{
		Network:    prefix,
		PeerGroups: []string{"group1", "group2"},
		Route:      route2.Route{ID: "route1"},
	}

	err = store.(*SqlStore).db.Save(rt).Error
	require.NoError(t, err, "Failed to insert Gob data")

	err = migrate(context.Background(), store.(*SqlStore).db)
	require.NoError(t, err, "Migration should not fail on gob populated db")

	err = migrate(context.Background(), store.(*SqlStore).db)
	require.NoError(t, err, "Migration should not fail on migrated db")

	err = store.(*SqlStore).db.Delete(rt).Where("id = ?", "route1").Error
	require.NoError(t, err, "Failed to delete Gob data")

	prefix = netip.MustParsePrefix("12.0.0.0/24")
	nRT := &route2.Route{
		Network: prefix,
		ID:      "route2",
		Peer:    "peer-id",
	}

	err = store.(*SqlStore).db.Save(nRT).Error
	require.NoError(t, err, "Failed to insert json nil slice data")

	err = migrate(context.Background(), store.(*SqlStore).db)
	require.NoError(t, err, "Migration should not fail on json nil slice populated db")

	err = migrate(context.Background(), store.(*SqlStore).db)
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

	t.Setenv("NETBIRD_STORE_ENGINE", string(PostgresStoreEngine))
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

	t.Setenv("NETBIRD_STORE_ENGINE", string(PostgresStoreEngine))
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

	t.Setenv("NETBIRD_STORE_ENGINE", string(PostgresStoreEngine))
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

func TestPostgresql_SavePeerStatus(t *testing.T) {
	if (os.Getenv("CI") == "true" && runtime.GOOS == "darwin") || runtime.GOOS == "windows" {
		t.Skip("skip CI tests on darwin and windows")
	}

	t.Setenv("NETBIRD_STORE_ENGINE", string(PostgresStoreEngine))
	store, cleanUp, err := NewTestStoreFromSQL(context.Background(), "../testdata/store.sql", t.TempDir())
	t.Cleanup(cleanUp)
	assert.NoError(t, err)

	account, err := store.GetAccount(context.Background(), "bf1c8084-ba50-4ce7-9439-34653001fc3b")
	require.NoError(t, err)

	// save status of non-existing peer
	newStatus := nbpeer.PeerStatus{Connected: true, LastSeen: time.Now().UTC()}
	err = store.SavePeerStatus(account.Id, "non-existing-peer", newStatus)
	assert.Error(t, err)

	// save new status of existing peer
	account.Peers["testpeer"] = &nbpeer.Peer{
		Key:    "peerkey",
		ID:     "testpeer",
		IP:     net.IP{127, 0, 0, 1},
		Meta:   nbpeer.PeerSystemMeta{},
		Name:   "peer name",
		Status: &nbpeer.PeerStatus{Connected: false, LastSeen: time.Now().UTC()},
	}

	err = store.SaveAccount(context.Background(), account)
	require.NoError(t, err)

	err = store.SavePeerStatus(account.Id, "testpeer", newStatus)
	require.NoError(t, err)

	account, err = store.GetAccount(context.Background(), account.Id)
	require.NoError(t, err)

	actual := account.Peers["testpeer"].Status
	assert.Equal(t, newStatus.Connected, actual.Connected)
}

func TestPostgresql_TestGetAccountByPrivateDomain(t *testing.T) {
	if (os.Getenv("CI") == "true" && runtime.GOOS == "darwin") || runtime.GOOS == "windows" {
		t.Skip("skip CI tests on darwin and windows")
	}

	t.Setenv("NETBIRD_STORE_ENGINE", string(PostgresStoreEngine))
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

	t.Setenv("NETBIRD_STORE_ENGINE", string(PostgresStoreEngine))
	store, cleanUp, err := NewTestStoreFromSQL(context.Background(), "../testdata/store.sql", t.TempDir())
	t.Cleanup(cleanUp)
	assert.NoError(t, err)

	hashed := "SoMeHaShEdToKeN"
	id := "9dj38s35-63fb-11ec-90d6-0242ac120003"

	token, err := store.GetTokenIDByHashedToken(context.Background(), hashed)
	require.NoError(t, err)
	require.Equal(t, id, token)
}

func TestPostgresql_GetUserByTokenID(t *testing.T) {
	if (os.Getenv("CI") == "true" && runtime.GOOS == "darwin") || runtime.GOOS == "windows" {
		t.Skip("skip CI tests on darwin and windows")
	}

	t.Setenv("NETBIRD_STORE_ENGINE", string(PostgresStoreEngine))
	store, cleanUp, err := NewTestStoreFromSQL(context.Background(), "../testdata/store.sql", t.TempDir())
	t.Cleanup(cleanUp)
	assert.NoError(t, err)

	id := "9dj38s35-63fb-11ec-90d6-0242ac120003"

	user, err := store.GetUserByTokenID(context.Background(), id)
	require.NoError(t, err)
	require.Equal(t, id, user.PATs[id].ID)
}

func TestSqlite_GetTakenIPs(t *testing.T) {
	t.Setenv("NETBIRD_STORE_ENGINE", string(SqliteStoreEngine))
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/extended-store.sql", t.TempDir())
	defer cleanup()
	if err != nil {
		t.Fatal(err)
	}

	existingAccountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"

	_, err = store.GetAccount(context.Background(), existingAccountID)
	require.NoError(t, err)

	takenIPs, err := store.GetTakenIPs(context.Background(), LockingStrengthShare, existingAccountID)
	require.NoError(t, err)
	assert.Equal(t, []net.IP{}, takenIPs)

	peer1 := &nbpeer.Peer{
		ID:        "peer1",
		AccountID: existingAccountID,
		IP:        net.IP{1, 1, 1, 1},
	}
	err = store.AddPeerToAccount(context.Background(), peer1)
	require.NoError(t, err)

	takenIPs, err = store.GetTakenIPs(context.Background(), LockingStrengthShare, existingAccountID)
	require.NoError(t, err)
	ip1 := net.IP{1, 1, 1, 1}.To16()
	assert.Equal(t, []net.IP{ip1}, takenIPs)

	peer2 := &nbpeer.Peer{
		ID:        "peer2",
		AccountID: existingAccountID,
		IP:        net.IP{2, 2, 2, 2},
	}
	err = store.AddPeerToAccount(context.Background(), peer2)
	require.NoError(t, err)

	takenIPs, err = store.GetTakenIPs(context.Background(), LockingStrengthShare, existingAccountID)
	require.NoError(t, err)
	ip2 := net.IP{2, 2, 2, 2}.To16()
	assert.Equal(t, []net.IP{ip1, ip2}, takenIPs)

}

func TestSqlite_GetPeerLabelsInAccount(t *testing.T) {
	t.Setenv("NETBIRD_STORE_ENGINE", string(SqliteStoreEngine))
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/extended-store.sql", t.TempDir())
	if err != nil {
		return
	}
	t.Cleanup(cleanup)

	existingAccountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"

	_, err = store.GetAccount(context.Background(), existingAccountID)
	require.NoError(t, err)

	labels, err := store.GetPeerLabelsInAccount(context.Background(), LockingStrengthShare, existingAccountID)
	require.NoError(t, err)
	assert.Equal(t, []string{}, labels)

	peer1 := &nbpeer.Peer{
		ID:        "peer1",
		AccountID: existingAccountID,
		DNSLabel:  "peer1.domain.test",
	}
	err = store.AddPeerToAccount(context.Background(), peer1)
	require.NoError(t, err)

	labels, err = store.GetPeerLabelsInAccount(context.Background(), LockingStrengthShare, existingAccountID)
	require.NoError(t, err)
	assert.Equal(t, []string{"peer1.domain.test"}, labels)

	peer2 := &nbpeer.Peer{
		ID:        "peer2",
		AccountID: existingAccountID,
		DNSLabel:  "peer2.domain.test",
	}
	err = store.AddPeerToAccount(context.Background(), peer2)
	require.NoError(t, err)

	labels, err = store.GetPeerLabelsInAccount(context.Background(), LockingStrengthShare, existingAccountID)
	require.NoError(t, err)
	assert.Equal(t, []string{"peer1.domain.test", "peer2.domain.test"}, labels)
}

func TestSqlite_GetAccountNetwork(t *testing.T) {
	t.Setenv("NETBIRD_STORE_ENGINE", string(SqliteStoreEngine))
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/extended-store.sql", t.TempDir())
	t.Cleanup(cleanup)
	if err != nil {
		t.Fatal(err)
	}

	existingAccountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"

	_, err = store.GetAccount(context.Background(), existingAccountID)
	require.NoError(t, err)

	network, err := store.GetAccountNetwork(context.Background(), LockingStrengthShare, existingAccountID)
	require.NoError(t, err)
	ip := net.IP{100, 64, 0, 0}.To16()
	assert.Equal(t, ip, network.Net.IP)
	assert.Equal(t, net.IPMask{255, 255, 0, 0}, network.Net.Mask)
	assert.Equal(t, "", network.Dns)
	assert.Equal(t, "af1c8024-ha40-4ce2-9418-34653101fc3c", network.Identifier)
	assert.Equal(t, uint64(0), network.Serial)
}

func TestSqlite_GetSetupKeyBySecret(t *testing.T) {
	t.Setenv("NETBIRD_STORE_ENGINE", string(SqliteStoreEngine))
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

	setupKey, err := store.GetSetupKeyBySecret(context.Background(), LockingStrengthShare, encodedHashedKey)
	require.NoError(t, err)
	assert.Equal(t, encodedHashedKey, setupKey.Key)
	assert.Equal(t, types.HiddenKey(plainKey, 4), setupKey.KeySecret)
	assert.Equal(t, "bf1c8084-ba50-4ce7-9439-34653001fc3b", setupKey.AccountID)
	assert.Equal(t, "Default key", setupKey.Name)
}

func TestSqlite_incrementSetupKeyUsage(t *testing.T) {
	t.Setenv("NETBIRD_STORE_ENGINE", string(SqliteStoreEngine))
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

	setupKey, err := store.GetSetupKeyBySecret(context.Background(), LockingStrengthShare, encodedHashedKey)
	require.NoError(t, err)
	assert.Equal(t, 0, setupKey.UsedTimes)

	err = store.IncrementSetupKeyUsage(context.Background(), setupKey.Id)
	require.NoError(t, err)

	setupKey, err = store.GetSetupKeyBySecret(context.Background(), LockingStrengthShare, encodedHashedKey)
	require.NoError(t, err)
	assert.Equal(t, 1, setupKey.UsedTimes)

	err = store.IncrementSetupKeyUsage(context.Background(), setupKey.Id)
	require.NoError(t, err)

	setupKey, err = store.GetSetupKeyBySecret(context.Background(), LockingStrengthShare, encodedHashedKey)
	require.NoError(t, err)
	assert.Equal(t, 2, setupKey.UsedTimes)
}

func TestSqlite_CreateAndGetObjectInTransaction(t *testing.T) {
	t.Setenv("NETBIRD_STORE_ENGINE", string(SqliteStoreEngine))
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/extended-store.sql", t.TempDir())
	t.Cleanup(cleanup)
	if err != nil {
		t.Fatal(err)
	}

	group := &types.Group{
		ID:        "group-id",
		AccountID: "account-id",
		Name:      "group-name",
		Issued:    "api",
		Peers:     nil,
	}
	err = store.ExecuteInTransaction(context.Background(), func(transaction Store) error {
		err := transaction.SaveGroup(context.Background(), LockingStrengthUpdate, group)
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

func TestSqlite_GetAccoundUsers(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/extended-store.sql", t.TempDir())
	t.Cleanup(cleanup)
	if err != nil {
		t.Fatal(err)
	}
	accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"
	account, err := store.GetAccount(context.Background(), accountID)
	require.NoError(t, err)
	users, err := store.GetAccountUsers(context.Background(), LockingStrengthShare, accountID)
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

	group, err := store.GetGroupByName(context.Background(), LockingStrengthShare, accountID, "All")
	require.NoError(t, err)
	require.True(t, group.IsGroupAll())
}

func Test_DeleteSetupKeySuccessfully(t *testing.T) {
	t.Setenv("NETBIRD_STORE_ENGINE", string(SqliteStoreEngine))
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/extended-store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"
	setupKeyID := "A2C8E62B-38F5-4553-B31E-DD66C696CEBB"

	err = store.DeleteSetupKey(context.Background(), LockingStrengthUpdate, accountID, setupKeyID)
	require.NoError(t, err)

	_, err = store.GetSetupKeyByID(context.Background(), LockingStrengthShare, setupKeyID, accountID)
	require.Error(t, err)
}

func Test_DeleteSetupKeyFailsForNonExistingKey(t *testing.T) {
	t.Setenv("NETBIRD_STORE_ENGINE", string(SqliteStoreEngine))
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/extended-store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"
	nonExistingKeyID := "non-existing-key-id"

	err = store.DeleteSetupKey(context.Background(), LockingStrengthUpdate, accountID, nonExistingKeyID)
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
			groups, err := store.GetGroupsByIDs(context.Background(), LockingStrengthShare, accountID, tt.groupIDs)
			require.NoError(t, err)
			require.Len(t, groups, tt.expectedCount)
		})
	}
}

func TestSqlStore_SaveGroup(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/extended-store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"

	group := &types.Group{
		ID:        "group-id",
		AccountID: accountID,
		Issued:    "api",
		Peers:     []string{"peer1", "peer2"},
	}
	err = store.SaveGroup(context.Background(), LockingStrengthUpdate, group)
	require.NoError(t, err)

	savedGroup, err := store.GetGroupByID(context.Background(), LockingStrengthShare, accountID, "group-id")
	require.NoError(t, err)
	require.Equal(t, savedGroup, group)
}

func TestSqlStore_SaveGroups(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/extended-store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"

	groups := []*types.Group{
		{
			ID:        "group-1",
			AccountID: accountID,
			Issued:    "api",
			Peers:     []string{"peer1", "peer2"},
		},
		{
			ID:        "group-2",
			AccountID: accountID,
			Issued:    "integration",
			Peers:     []string{"peer3", "peer4"},
		},
	}
	err = store.SaveGroups(context.Background(), LockingStrengthUpdate, groups)
	require.NoError(t, err)
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
			err := store.DeleteGroup(context.Background(), LockingStrengthUpdate, accountID, tt.groupID)
			if tt.expectError {
				require.Error(t, err)
				sErr, ok := status.FromError(err)
				require.True(t, ok)
				require.Equal(t, sErr.Type(), status.NotFound)
			} else {
				require.NoError(t, err)

				group, err := store.GetGroupByID(context.Background(), LockingStrengthShare, accountID, tt.groupID)
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
			err := store.DeleteGroups(context.Background(), LockingStrengthUpdate, accountID, tt.groupIDs)
			if tt.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)

				for _, groupID := range tt.groupIDs {
					group, err := store.GetGroupByID(context.Background(), LockingStrengthShare, accountID, groupID)
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
			peer, err := store.GetPeerByID(context.Background(), LockingStrengthShare, accountID, tt.peerID)
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
			peers, err := store.GetPeersByIDs(context.Background(), LockingStrengthShare, accountID, tt.peerIDs)
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
			postureChecks, err := store.GetPostureChecksByID(context.Background(), LockingStrengthShare, accountID, tt.postureChecksID)
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
			groups, err := store.GetPostureChecksByIDs(context.Background(), LockingStrengthShare, accountID, tt.postureCheckIDs)
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
	err = store.SavePostureChecks(context.Background(), LockingStrengthUpdate, postureChecks)
	require.NoError(t, err)

	savePostureChecks, err := store.GetPostureChecksByID(context.Background(), LockingStrengthShare, accountID, "posture-checks-id")
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
			err = store.DeletePostureChecks(context.Background(), LockingStrengthUpdate, accountID, tt.postureChecksID)
			if tt.expectError {
				require.Error(t, err)
				sErr, ok := status.FromError(err)
				require.True(t, ok)
				require.Equal(t, sErr.Type(), status.NotFound)
			} else {
				require.NoError(t, err)
				group, err := store.GetPostureChecksByID(context.Background(), LockingStrengthShare, accountID, tt.postureChecksID)
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
			policy, err := store.GetPolicyByID(context.Background(), LockingStrengthShare, accountID, tt.policyID)
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
	err = store.CreatePolicy(context.Background(), LockingStrengthUpdate, policy)
	require.NoError(t, err)

	savePolicy, err := store.GetPolicyByID(context.Background(), LockingStrengthShare, accountID, policy.ID)
	require.NoError(t, err)
	require.Equal(t, savePolicy, policy)

}

func TestSqlStore_SavePolicy(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"
	policyID := "cs1tnh0hhcjnqoiuebf0"

	policy, err := store.GetPolicyByID(context.Background(), LockingStrengthShare, accountID, policyID)
	require.NoError(t, err)

	policy.Enabled = false
	policy.Description = "policy"
	policy.Rules[0].Sources = []string{"group"}
	policy.Rules[0].Ports = []string{"80", "443"}
	err = store.SavePolicy(context.Background(), LockingStrengthUpdate, policy)
	require.NoError(t, err)

	savePolicy, err := store.GetPolicyByID(context.Background(), LockingStrengthShare, accountID, policy.ID)
	require.NoError(t, err)
	require.Equal(t, savePolicy, policy)
}

func TestSqlStore_DeletePolicy(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"
	policyID := "cs1tnh0hhcjnqoiuebf0"

	err = store.DeletePolicy(context.Background(), LockingStrengthShare, accountID, policyID)
	require.NoError(t, err)

	policy, err := store.GetPolicyByID(context.Background(), LockingStrengthShare, accountID, policyID)
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
			dnsSettings, err := store.GetAccountDNSSettings(context.Background(), LockingStrengthShare, tt.accountID)
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

	dnsSettings, err := store.GetAccountDNSSettings(context.Background(), LockingStrengthShare, accountID)
	require.NoError(t, err)

	dnsSettings.DisabledManagementGroups = []string{"groupA", "groupB"}
	err = store.SaveDNSSettings(context.Background(), LockingStrengthUpdate, accountID, dnsSettings)
	require.NoError(t, err)

	saveDNSSettings, err := store.GetAccountDNSSettings(context.Background(), LockingStrengthShare, accountID)
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
			peers, err := store.GetAccountNameServerGroups(context.Background(), LockingStrengthShare, tt.accountID)
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
			nsGroup, err := store.GetNameServerGroupByID(context.Background(), LockingStrengthShare, accountID, tt.nsGroupID)
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

	err = store.SaveNameServerGroup(context.Background(), LockingStrengthUpdate, nsGroup)
	require.NoError(t, err)

	saveNSGroup, err := store.GetNameServerGroupByID(context.Background(), LockingStrengthShare, accountID, nsGroup.ID)
	require.NoError(t, err)
	require.Equal(t, saveNSGroup, nsGroup)
}

func TestSqlStore_DeleteNameServerGroup(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/extended-store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"
	nsGroupID := "csqdelq7qv97ncu7d9t0"

	err = store.DeleteNameServerGroup(context.Background(), LockingStrengthShare, accountID, nsGroupID)
	require.NoError(t, err)

	nsGroup, err := store.GetNameServerGroupByID(context.Background(), LockingStrengthShare, accountID, nsGroupID)
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

	owner := types.NewOwnerUser(userID)
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
	}

	if err := addAllGroup(acc); err != nil {
		log.WithContext(ctx).Errorf("error adding all group to account %s: %v", acc.Id, err)
	}
	return acc
}

// addAllGroup to account object if it doesn't exist
func addAllGroup(account *types.Account) error {
	if len(account.Groups) == 0 {
		allGroup := &types.Group{
			ID:     xid.New().String(),
			Name:   "All",
			Issued: types.GroupIssuedAPI,
		}
		for _, peer := range account.Peers {
			allGroup.Peers = append(allGroup.Peers, peer.ID)
		}
		account.Groups = map[string]*types.Group{allGroup.ID: allGroup}

		id := xid.New().String()

		defaultPolicy := &types.Policy{
			ID:          id,
			Name:        types.DefaultRuleName,
			Description: types.DefaultRuleDescription,
			Enabled:     true,
			Rules: []*types.PolicyRule{
				{
					ID:            id,
					Name:          types.DefaultRuleName,
					Description:   types.DefaultRuleDescription,
					Enabled:       true,
					Sources:       []string{allGroup.ID},
					Destinations:  []string{allGroup.ID},
					Bidirectional: true,
					Protocol:      types.PolicyRuleProtocolALL,
					Action:        types.PolicyTrafficActionAccept,
				},
			},
		}

		account.Policies = []*types.Policy{defaultPolicy}
	}
	return nil
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
			networks, err := store.GetAccountNetworks(context.Background(), LockingStrengthShare, tt.accountID)
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
			network, err := store.GetNetworkByID(context.Background(), LockingStrengthShare, accountID, tt.networkID)
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

	err = store.SaveNetwork(context.Background(), LockingStrengthUpdate, network)
	require.NoError(t, err)

	savedNet, err := store.GetNetworkByID(context.Background(), LockingStrengthShare, accountID, network.ID)
	require.NoError(t, err)
	require.Equal(t, network, savedNet)
}

func TestSqlStore_DeleteNetwork(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"
	networkID := "ct286bi7qv930dsrrug0"

	err = store.DeleteNetwork(context.Background(), LockingStrengthUpdate, accountID, networkID)
	require.NoError(t, err)

	network, err := store.GetNetworkByID(context.Background(), LockingStrengthShare, accountID, networkID)
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
			routers, err := store.GetNetworkRoutersByNetID(context.Background(), LockingStrengthShare, accountID, tt.networkID)
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
			networkRouter, err := store.GetNetworkRouterByID(context.Background(), LockingStrengthShare, accountID, tt.networkRouterID)
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

	err = store.SaveNetworkRouter(context.Background(), LockingStrengthUpdate, netRouter)
	require.NoError(t, err)

	savedNetRouter, err := store.GetNetworkRouterByID(context.Background(), LockingStrengthShare, accountID, netRouter.ID)
	require.NoError(t, err)
	require.Equal(t, netRouter, savedNetRouter)
}

func TestSqlStore_DeleteNetworkRouter(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"
	netRouterID := "ctc20ji7qv9ck2sebc80"

	err = store.DeleteNetworkRouter(context.Background(), LockingStrengthUpdate, accountID, netRouterID)
	require.NoError(t, err)

	netRouter, err := store.GetNetworkByID(context.Background(), LockingStrengthShare, accountID, netRouterID)
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
			netResources, err := store.GetNetworkResourcesByNetID(context.Background(), LockingStrengthShare, accountID, tt.networkID)
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
			netResource, err := store.GetNetworkResourceByID(context.Background(), LockingStrengthShare, accountID, tt.netResourceID)
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

	err = store.SaveNetworkResource(context.Background(), LockingStrengthUpdate, netResource)
	require.NoError(t, err)

	savedNetResource, err := store.GetNetworkResourceByID(context.Background(), LockingStrengthShare, accountID, netResource.ID)
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

	err = store.DeleteNetworkResource(context.Background(), LockingStrengthUpdate, accountID, netResourceID)
	require.NoError(t, err)

	netResource, err := store.GetNetworkByID(context.Background(), LockingStrengthShare, accountID, netResourceID)
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

	group, err := store.GetGroupByID(context.Background(), LockingStrengthShare, accountID, groupID)
	require.NoError(t, err)
	require.Contains(t, group.Resources, *res)

	groups, err := store.GetResourceGroups(context.Background(), LockingStrengthShare, accountID, resourceId)
	require.NoError(t, err)
	require.Len(t, groups, 1)

	err = store.RemoveResourceFromGroup(context.Background(), accountID, groupID, res.ID)
	require.NoError(t, err)

	group, err = store.GetGroupByID(context.Background(), LockingStrengthShare, accountID, groupID)
	require.NoError(t, err)
	require.NotContains(t, group.Resources, *res)
}
