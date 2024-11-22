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
	nbdns "github.com/netbirdio/netbird/dns"
	nbgroup "github.com/netbirdio/netbird/management/server/group"
	"github.com/netbirdio/netbird/management/server/posture"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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
		Status: &nbpeer.PeerStatus{Connected: true, LastSeen: time.Now().Local()},
	}
	ctx := context.Background()
	err = store.SavePeer(ctx, LockingStrengthUpdate, account.Id, peer)
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

	err = store.SavePeer(ctx, LockingStrengthUpdate, account.Id, updatedPeer)
	require.NoError(t, err)

	account, err = store.GetAccount(context.Background(), account.Id)
	require.NoError(t, err)

	actual := account.Peers[peer.ID]
	assert.Equal(t, updatedPeer.Meta, actual.Meta)
	assert.Equal(t, updatedPeer.Status.Connected, actual.Status.Connected)
	assert.Equal(t, updatedPeer.Status.LoginExpired, actual.Status.LoginExpired)
	assert.Equal(t, updatedPeer.Status.RequiresApproval, actual.Status.RequiresApproval)
	assert.WithinDurationf(t, updatedPeer.Status.LastSeen, actual.Status.LastSeen, time.Millisecond, "LastSeen should be equal")
}

func TestSqlite_SavePeerStatus(t *testing.T) {
	store, cleanUp, err := NewTestStoreFromSQL(context.Background(), "testdata/store.sql", t.TempDir())
	t.Cleanup(cleanUp)
	assert.NoError(t, err)

	account, err := store.GetAccount(context.Background(), "bf1c8084-ba50-4ce7-9439-34653001fc3b")
	require.NoError(t, err)

	// save status of non-existing peer
	newStatus := nbpeer.PeerStatus{Connected: false, LastSeen: time.Now().Local()}
	err = store.SavePeerStatus(context.Background(), LockingStrengthUpdate, account.Id, "non-existing-peer", newStatus)
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
		Status: &nbpeer.PeerStatus{Connected: true, LastSeen: time.Now().Local()},
	}

	err = store.SaveAccount(context.Background(), account)
	require.NoError(t, err)

	err = store.SavePeerStatus(context.Background(), LockingStrengthUpdate, account.Id, "testpeer", newStatus)
	require.NoError(t, err)

	account, err = store.GetAccount(context.Background(), account.Id)
	require.NoError(t, err)

	actual := account.Peers["testpeer"].Status
	assert.Equal(t, newStatus.Connected, actual.Connected)
	assert.Equal(t, newStatus.LoginExpired, actual.LoginExpired)
	assert.Equal(t, newStatus.RequiresApproval, actual.RequiresApproval)
	assert.WithinDurationf(t, newStatus.LastSeen, actual.LastSeen, time.Millisecond, "LastSeen should be equal")

	newStatus.Connected = true

	err = store.SavePeerStatus(context.Background(), LockingStrengthUpdate, account.Id, "testpeer", newStatus)
	require.NoError(t, err)

	account, err = store.GetAccount(context.Background(), account.Id)
	require.NoError(t, err)

	actual = account.Peers["testpeer"].Status
	assert.Equal(t, newStatus.Connected, actual.Connected)
	assert.Equal(t, newStatus.LoginExpired, actual.LoginExpired)
	assert.Equal(t, newStatus.RequiresApproval, actual.RequiresApproval)
	assert.WithinDurationf(t, newStatus.LastSeen, actual.LastSeen, time.Millisecond, "LastSeen should be equal")
}

func TestSqlite_SavePeerLocation(t *testing.T) {
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
	err = store.SavePeerLocation(context.Background(), LockingStrengthUpdate, account.Id, peer)
	assert.Error(t, err)

	account.Peers[peer.ID] = peer
	err = store.SaveAccount(context.Background(), account)
	require.NoError(t, err)

	peer.Location.ConnectionIP = net.ParseIP("35.1.1.1")
	peer.Location.CountryCode = "DE"
	peer.Location.CityName = "Berlin"
	peer.Location.GeoNameID = 2950159

	err = store.SavePeerLocation(context.Background(), LockingStrengthUpdate, account.Id, account.Peers[peer.ID])
	assert.NoError(t, err)

	account, err = store.GetAccount(context.Background(), account.Id)
	require.NoError(t, err)

	actual := account.Peers[peer.ID].Location
	assert.Equal(t, peer.Location, actual)

	peer.ID = "non-existing-peer"
	err = store.SavePeerLocation(context.Background(), LockingStrengthUpdate, account.Id, peer)
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
	err = store.SavePeerStatus(context.Background(), LockingStrengthUpdate, account.Id, "non-existing-peer", newStatus)
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

	err = store.SavePeerStatus(context.Background(), LockingStrengthUpdate, account.Id, "testpeer", newStatus)
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

func TestSqlite_GetAccountUsers(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "testdata/extended-store.sql", t.TempDir())
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

	group, err := store.GetGroupByName(context.Background(), LockingStrengthShare, accountID, "All")
	require.NoError(t, err)
	require.True(t, group.IsGroupAll())
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

func TestSqlStore_GetGroupsByIDs(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "testdata/extended-store.sql", t.TempDir())
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
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "testdata/extended-store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"

	group := &nbgroup.Group{
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
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "testdata/extended-store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"

	groups := []*nbgroup.Group{
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
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "testdata/extended-store.sql", t.TempDir())
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
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "testdata/extended-store.sql", t.TempDir())
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
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "testdata/store_policy_migrate.sql", t.TempDir())
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
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "testdata/store_policy_migrate.sql", t.TempDir())
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
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "testdata/extended-store.sql", t.TempDir())
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
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "testdata/extended-store.sql", t.TempDir())
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
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "testdata/extended-store.sql", t.TempDir())
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
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "testdata/extended-store.sql", t.TempDir())
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
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "testdata/store.sql", t.TempDir())
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
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "testdata/store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"

	policy := &Policy{
		ID:        "policy-id",
		AccountID: accountID,
		Enabled:   true,
		Rules: []*PolicyRule{
			{
				Enabled:       true,
				Sources:       []string{"groupA"},
				Destinations:  []string{"groupC"},
				Bidirectional: true,
				Action:        PolicyTrafficActionAccept,
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
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "testdata/store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"
	policyID := "cs1tnh0hhcjnqoiuebf0"

	policy, err := store.GetPolicyByID(context.Background(), LockingStrengthShare, accountID, policyID)
	require.NoError(t, err)

	policy.Enabled = false
	policy.Description = "policy"
	err = store.SavePolicy(context.Background(), LockingStrengthUpdate, policy)
	require.NoError(t, err)

	savePolicy, err := store.GetPolicyByID(context.Background(), LockingStrengthShare, accountID, policy.ID)
	require.NoError(t, err)
	require.Equal(t, savePolicy, policy)
}

func TestSqlStore_DeletePolicy(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "testdata/store.sql", t.TempDir())
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
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "testdata/store.sql", t.TempDir())
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
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "testdata/store.sql", t.TempDir())
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
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "testdata/extended-store.sql", t.TempDir())
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
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "testdata/extended-store.sql", t.TempDir())
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
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "testdata/extended-store.sql", t.TempDir())
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
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "testdata/extended-store.sql", t.TempDir())
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

func TestSqlStore_GetAccountPeers(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "testdata/store_with_expired_peers.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	tests := []struct {
		name          string
		accountID     string
		expectedCount int
	}{
		{
			name:          "retrieve peers by existing account ID",
			accountID:     "bf1c8084-ba50-4ce7-9439-34653001fc3b",
			expectedCount: 4,
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
			peers, err := store.GetAccountPeers(context.Background(), LockingStrengthShare, tt.accountID)
			require.NoError(t, err)
			require.Len(t, peers, tt.expectedCount)
		})
	}

}

func TestSqlStore_GetAccountPeersWithExpiration(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "testdata/store_with_expired_peers.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	tests := []struct {
		name          string
		accountID     string
		expectedCount int
	}{
		{
			name:          "retrieve peers with expiration by existing account ID",
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
			peers, err := store.GetAccountPeersWithExpiration(context.Background(), LockingStrengthShare, tt.accountID)
			require.NoError(t, err)
			require.Len(t, peers, tt.expectedCount)
		})
	}
}

func TestSqlStore_GetAccountPeersWithInactivity(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "testdata/store_with_expired_peers.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	tests := []struct {
		name          string
		accountID     string
		expectedCount int
	}{
		{
			name:          "retrieve peers with inactivity by existing account ID",
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
			peers, err := store.GetAccountPeersWithInactivity(context.Background(), LockingStrengthShare, tt.accountID)
			require.NoError(t, err)
			require.Len(t, peers, tt.expectedCount)
		})
	}
}

func TestSqlStore_GetAllEphemeralPeers(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "testdata/storev1.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	peers, err := store.GetAllEphemeralPeers(context.Background(), LockingStrengthShare)
	require.NoError(t, err)
	require.Len(t, peers, 1)
	require.True(t, peers[0].Ephemeral)
}

func TestSqlStore_DeletePeer(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "testdata/store_with_expired_peers.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"
	peerID := "csrnkiq7qv9d8aitqd50"

	err = store.DeletePeer(context.Background(), LockingStrengthUpdate, accountID, peerID)
	require.NoError(t, err)

	peer, err := store.GetPeerByID(context.Background(), LockingStrengthShare, accountID, peerID)
	require.Error(t, err)
	require.Nil(t, peer)
}

func TestSqlStore_GetAccountCreatedBy(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "testdata/store.sql", t.TempDir())
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
			createdBy, err := store.GetAccountCreatedBy(context.Background(), LockingStrengthShare, tt.accountID)
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
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "testdata/extended-store.sql", t.TempDir())
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
			user, err := store.GetUserByUserID(context.Background(), LockingStrengthShare, tt.userID)
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
	store, cleanUp, err := NewTestStoreFromSQL(context.Background(), "testdata/store.sql", t.TempDir())
	t.Cleanup(cleanUp)
	assert.NoError(t, err)

	id := "9dj38s35-63fb-11ec-90d6-0242ac120003"

	user, err := store.GetUserByPATID(context.Background(), LockingStrengthShare, id)
	require.NoError(t, err)
	require.Equal(t, "f4f6d672-63fb-11ec-90d6-0242ac120003", user.Id)
}

func TestSqlStore_SaveUser(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "testdata/extended-store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"

	user := &User{
		Id:            "user-id",
		AccountID:     accountID,
		Role:          UserRoleAdmin,
		IsServiceUser: false,
		AutoGroups:    []string{"groupA", "groupB"},
		Blocked:       false,
		LastLogin:     time.Now().UTC(),
		CreatedAt:     time.Now().UTC().Add(-time.Hour),
		Issued:        UserIssuedIntegration,
	}
	err = store.SaveUser(context.Background(), LockingStrengthUpdate, user)
	require.NoError(t, err)

	saveUser, err := store.GetUserByUserID(context.Background(), LockingStrengthShare, user.Id)
	require.NoError(t, err)
	require.Equal(t, user.Id, saveUser.Id)
	require.Equal(t, user.AccountID, saveUser.AccountID)
	require.Equal(t, user.Role, saveUser.Role)
	require.Equal(t, user.AutoGroups, saveUser.AutoGroups)
	require.WithinDurationf(t, user.LastLogin, saveUser.LastLogin.UTC(), time.Millisecond, "LastLogin should be equal")
	require.WithinDurationf(t, user.CreatedAt, saveUser.CreatedAt.UTC(), time.Millisecond, "CreatedAt should be equal")
	require.Equal(t, user.Issued, saveUser.Issued)
	require.Equal(t, user.Blocked, saveUser.Blocked)
	require.Equal(t, user.IsServiceUser, saveUser.IsServiceUser)
}

func TestSqlStore_SaveUsers(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "testdata/extended-store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"

	accountUsers, err := store.GetAccountUsers(context.Background(), LockingStrengthShare, accountID)
	require.NoError(t, err)
	require.Len(t, accountUsers, 2)

	users := []*User{
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
	err = store.SaveUsers(context.Background(), LockingStrengthUpdate, users)
	require.NoError(t, err)

	accountUsers, err = store.GetAccountUsers(context.Background(), LockingStrengthShare, accountID)
	require.NoError(t, err)
	require.Len(t, accountUsers, 4)
}

func TestSqlStore_DeleteUser(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "testdata/extended-store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"
	userID := "f4f6d672-63fb-11ec-90d6-0242ac120003"

	err = store.DeleteUser(context.Background(), LockingStrengthUpdate, accountID, userID)
	require.NoError(t, err)

	user, err := store.GetUserByUserID(context.Background(), LockingStrengthShare, userID)
	require.Error(t, err)
	require.Nil(t, user)

	userPATs, err := store.GetUserPATs(context.Background(), LockingStrengthShare, userID)
	require.NoError(t, err)
	require.Len(t, userPATs, 0)
}

func TestSqlStore_GetPATByID(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "testdata/extended-store.sql", t.TempDir())
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
			pat, err := store.GetPATByID(context.Background(), LockingStrengthShare, userID, tt.patID)
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
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "testdata/extended-store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	userPATs, err := store.GetUserPATs(context.Background(), LockingStrengthShare, "f4f6d672-63fb-11ec-90d6-0242ac120003")
	require.NoError(t, err)
	require.Len(t, userPATs, 1)
}

func TestSqlStore_GetPATByHashedToken(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "testdata/extended-store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	pat, err := store.GetPATByHashedToken(context.Background(), LockingStrengthShare, "SoMeHaShEdToKeN")
	require.NoError(t, err)
	require.Equal(t, "9dj38s35-63fb-11ec-90d6-0242ac120003", pat.ID)
}

func TestSqlStore_MarkPATUsed(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "testdata/extended-store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	userID := "f4f6d672-63fb-11ec-90d6-0242ac120003"
	patID := "9dj38s35-63fb-11ec-90d6-0242ac120003"

	err = store.MarkPATUsed(context.Background(), LockingStrengthUpdate, patID)
	require.NoError(t, err)

	pat, err := store.GetPATByID(context.Background(), LockingStrengthShare, userID, patID)
	require.NoError(t, err)
	now := time.Now().UTC()
	require.WithinRange(t, pat.LastUsed.UTC(), now.Add(-15*time.Second), now, "LastUsed should be within 1 second of now")
}

func TestSqlStore_SavePAT(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "testdata/extended-store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	userID := "edafee4e-63fb-11ec-90d6-0242ac120003"

	pat := &PersonalAccessToken{
		ID:             "pat-id",
		UserID:         userID,
		Name:           "token",
		HashedToken:    "SoMeHaShEdToKeN",
		ExpirationDate: time.Now().UTC().Add(12 * time.Hour),
		CreatedBy:      userID,
		CreatedAt:      time.Now().UTC().Add(time.Hour),
		LastUsed:       time.Now().UTC().Add(-15 * time.Minute),
	}
	err = store.SavePAT(context.Background(), LockingStrengthUpdate, pat)
	require.NoError(t, err)

	savePAT, err := store.GetPATByID(context.Background(), LockingStrengthShare, userID, pat.ID)
	require.NoError(t, err)
	require.Equal(t, pat.ID, savePAT.ID)
	require.Equal(t, pat.UserID, savePAT.UserID)
	require.Equal(t, pat.HashedToken, savePAT.HashedToken)
	require.Equal(t, pat.CreatedBy, savePAT.CreatedBy)
	require.WithinDurationf(t, pat.ExpirationDate, savePAT.ExpirationDate.UTC(), time.Millisecond, "ExpirationDate should be equal")
	require.WithinDurationf(t, pat.CreatedAt, savePAT.CreatedAt.UTC(), time.Millisecond, "CreatedAt should be equal")
	require.WithinDurationf(t, pat.LastUsed, savePAT.LastUsed.UTC(), time.Millisecond, "LastUsed should be equal")
}

func TestSqlStore_DeletePAT(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "testdata/extended-store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	userID := "f4f6d672-63fb-11ec-90d6-0242ac120003"
	patID := "9dj38s35-63fb-11ec-90d6-0242ac120003"

	err = store.DeletePAT(context.Background(), LockingStrengthUpdate, userID, patID)
	require.NoError(t, err)

	pat, err := store.GetPATByID(context.Background(), LockingStrengthShare, userID, patID)
	require.Error(t, err)
	require.Nil(t, pat)
}

func TestSqlStore_GetAccountRoutes(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "testdata/extended-store.sql", t.TempDir())
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
			routes, err := store.GetAccountRoutes(context.Background(), LockingStrengthShare, tt.accountID)
			require.NoError(t, err)
			require.Len(t, routes, tt.expectedCount)
		})
	}
}

func TestSqlStore_GetRouteByID(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "testdata/extended-store.sql", t.TempDir())
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
			route, err := store.GetRouteByID(context.Background(), LockingStrengthShare, accountID, tt.routeID)
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
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "testdata/extended-store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"

	route := &route2.Route{
		ID:                  "route-id",
		AccountID:           accountID,
		Network:             netip.MustParsePrefix("10.10.0.0/16"),
		NetID:               "netID",
		PeerGroups:          []string{"routeA"},
		NetworkType:         route2.IPv4Network,
		Masquerade:          true,
		Metric:              9999,
		Enabled:             true,
		Groups:              []string{"groupA"},
		AccessControlGroups: []string{},
	}
	err = store.SaveRoute(context.Background(), LockingStrengthUpdate, route)
	require.NoError(t, err)

	saveRoute, err := store.GetRouteByID(context.Background(), LockingStrengthShare, accountID, string(route.ID))
	require.NoError(t, err)
	require.Equal(t, route, saveRoute)

}

func TestSqlStore_DeleteRoute(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "testdata/extended-store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"
	routeID := "ct03t427qv97vmtmglog"

	err = store.DeleteRoute(context.Background(), LockingStrengthUpdate, accountID, routeID)
	require.NoError(t, err)

	route, err := store.GetRouteByID(context.Background(), LockingStrengthShare, accountID, routeID)
	require.Error(t, err)
	require.Nil(t, route)
}
