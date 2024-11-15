package server

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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	nbdns "github.com/netbirdio/netbird/dns"
	nbgroup "github.com/netbirdio/netbird/management/server/group"

	route2 "github.com/netbirdio/netbird/route"

	"github.com/netbirdio/netbird/management/server/status"

	nbpeer "github.com/netbirdio/netbird/management/server/peer"
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
	setupKey, _ := GenerateDefaultSetupKey()
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
			UserID:     userID,
			Status:     &nbpeer.PeerStatus{Connected: false, LastSeen: time.Now()},
			SSHEnabled: false,
		}
		account.Peers[peerID] = peer
		group, _ := account.GetGroupAll()
		group.Peers = append(group.Peers, peerID)
		user := &User{
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

		group = &nbgroup.Group{
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

		setupKey, _ := GenerateDefaultSetupKey()
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
	setupKey, _ := GenerateDefaultSetupKey()
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
	setupKey, _ = GenerateDefaultSetupKey()
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
	user := NewAdminUser(testUserID)
	user.PATs = map[string]*PersonalAccessToken{"testtoken": {
		ID:   "testtoken",
		Name: "test token",
	}}

	account := newAccountWithId(context.Background(), "account_id", testUserID, "")
	setupKey, _ := GenerateDefaultSetupKey()
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
		var rules []*PolicyRule
		err = store.(*SqlStore).db.Model(&PolicyRule{}).Find(&rules, "policy_id = ?", policy.ID).Error
		require.NoError(t, err, "expecting no error after removing DeleteAccount when searching for policy rules")
		require.Len(t, rules, 0, "expecting no policy rules to be found after removing DeleteAccount")

	}

	for _, accountUser := range account.Users {
		var pats []*PersonalAccessToken
		err = store.(*SqlStore).db.Model(&PersonalAccessToken{}).Find(&pats, "user_id = ?", accountUser.Id).Error
		require.NoError(t, err, "expecting no error after removing DeleteAccount when searching for personal access token")
		require.Len(t, pats, 0, "expecting no personal access token to be found after removing DeleteAccount")

	}

}

func TestSqlite_GetAccount(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("The SQLite store is not properly supported by Windows yet")
	}

	t.Setenv("NETBIRD_STORE_ENGINE", string(SqliteStoreEngine))
	store, cleanUp, err := NewTestStoreFromSQL(context.Background(), "testdata/store.sql", t.TempDir())
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
	store, cleanUp, err := NewTestStoreFromSQL(context.Background(), "testdata/store.sql", t.TempDir())
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
	store, cleanUp, err := NewTestStoreFromSQL(context.Background(), "testdata/store.sql", t.TempDir())
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
	store, cleanUp, err := NewTestStoreFromSQL(context.Background(), "testdata/store.sql", t.TempDir())
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
	store, cleanUp, err := NewTestStoreFromSQL(context.Background(), "testdata/store.sql", t.TempDir())
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
	store, cleanUp, err := NewTestStoreFromSQL(context.Background(), "testdata/store.sql", t.TempDir())
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
	store, cleanUp, err := NewTestStoreFromSQL(context.Background(), "testdata/store.sql", t.TempDir())
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
		Network
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
		Account
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

func newSqliteStore(t *testing.T) *SqlStore {
	t.Helper()

	store, err := NewSqliteStore(context.Background(), t.TempDir(), nil)
	t.Cleanup(func() {
		store.Close(context.Background())
	})
	require.NoError(t, err)
	require.NotNil(t, store)

	return store
}

func newAccount(store Store, id int) error {
	str := fmt.Sprintf("%s-%d", uuid.New().String(), id)
	account := newAccountWithId(context.Background(), str, str+"-testuser", "example.com")
	setupKey, _ := GenerateDefaultSetupKey()
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
	setupKey, _ := GenerateDefaultSetupKey()
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
	setupKey, _ = GenerateDefaultSetupKey()
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
	user := NewAdminUser(testUserID)
	user.PATs = map[string]*PersonalAccessToken{"testtoken": {
		ID:   "testtoken",
		Name: "test token",
	}}

	account := newAccountWithId(context.Background(), "account_id", testUserID, "")
	setupKey, _ := GenerateDefaultSetupKey()
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
		var rules []*PolicyRule
		err = store.(*SqlStore).db.Model(&PolicyRule{}).Find(&rules, "policy_id = ?", policy.ID).Error
		require.NoError(t, err, "expecting no error after removing DeleteAccount when searching for policy rules")
		require.Len(t, rules, 0, "expecting no policy rules to be found after removing DeleteAccount")

	}

	for _, accountUser := range account.Users {
		var pats []*PersonalAccessToken
		err = store.(*SqlStore).db.Model(&PersonalAccessToken{}).Find(&pats, "user_id = ?", accountUser.Id).Error
		require.NoError(t, err, "expecting no error after removing DeleteAccount when searching for personal access token")
		require.Len(t, pats, 0, "expecting no personal access token to be found after removing DeleteAccount")

	}

}

func TestPostgresql_SavePeerStatus(t *testing.T) {
	if (os.Getenv("CI") == "true" && runtime.GOOS == "darwin") || runtime.GOOS == "windows" {
		t.Skip("skip CI tests on darwin and windows")
	}

	t.Setenv("NETBIRD_STORE_ENGINE", string(PostgresStoreEngine))
	store, cleanUp, err := NewTestStoreFromSQL(context.Background(), "testdata/store.sql", t.TempDir())
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
	store, cleanUp, err := NewTestStoreFromSQL(context.Background(), "testdata/store.sql", t.TempDir())
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
	store, cleanUp, err := NewTestStoreFromSQL(context.Background(), "testdata/store.sql", t.TempDir())
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
	store, cleanUp, err := NewTestStoreFromSQL(context.Background(), "testdata/store.sql", t.TempDir())
	t.Cleanup(cleanUp)
	assert.NoError(t, err)

	id := "9dj38s35-63fb-11ec-90d6-0242ac120003"

	user, err := store.GetUserByTokenID(context.Background(), id)
	require.NoError(t, err)
	require.Equal(t, id, user.PATs[id].ID)
}

func TestSqlite_GetTakenIPs(t *testing.T) {
	t.Setenv("NETBIRD_STORE_ENGINE", string(SqliteStoreEngine))
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "testdata/extended-store.sql", t.TempDir())
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
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "testdata/extended-store.sql", t.TempDir())
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
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "testdata/extended-store.sql", t.TempDir())
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
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "testdata/extended-store.sql", t.TempDir())
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
	assert.Equal(t, hiddenKey(plainKey, 4), setupKey.KeySecret)
	assert.Equal(t, "bf1c8084-ba50-4ce7-9439-34653001fc3b", setupKey.AccountID)
	assert.Equal(t, "Default key", setupKey.Name)
}

func TestSqlite_incrementSetupKeyUsage(t *testing.T) {
	t.Setenv("NETBIRD_STORE_ENGINE", string(SqliteStoreEngine))
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "testdata/extended-store.sql", t.TempDir())
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
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "testdata/extended-store.sql", t.TempDir())
	t.Cleanup(cleanup)
	if err != nil {
		t.Fatal(err)
	}

	group := &nbgroup.Group{
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
		group, err = transaction.GetGroupByID(context.Background(), LockingStrengthUpdate, group.ID, group.AccountID)
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
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "testdata/extended-store.sql", t.TempDir())
	t.Cleanup(cleanup)
	if err != nil {
		t.Fatal(err)
	}
	accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"
	account, err := store.GetAccount(context.Background(), accountID)
	require.NoError(t, err)
	users, err := store.GetAccountUsers(context.Background(), accountID)
	require.NoError(t, err)
	require.Len(t, users, len(account.Users))
}

func TestSqlStore_UpdateAccountDomainAttributes(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "testdata/extended-store.sql", t.TempDir())
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
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "testdata/extended-store.sql", t.TempDir())
	t.Cleanup(cleanup)
	if err != nil {
		t.Fatal(err)
	}
	accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"

	group, err := store.GetGroupByName(context.Background(), LockingStrengthShare, "All", accountID)
	require.NoError(t, err)
	require.Equal(t, "All", group.Name)
}

func Test_DeleteSetupKeySuccessfully(t *testing.T) {
	t.Setenv("NETBIRD_STORE_ENGINE", string(SqliteStoreEngine))
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "testdata/extended-store.sql", t.TempDir())
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
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "testdata/extended-store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"
	nonExistingKeyID := "non-existing-key-id"

	err = store.DeleteSetupKey(context.Background(), LockingStrengthUpdate, accountID, nonExistingKeyID)
	require.Error(t, err)
}
