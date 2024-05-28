package server

import (
	"fmt"
	"math/rand"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	nbdns "github.com/netbirdio/netbird/dns"
	nbgroup "github.com/netbirdio/netbird/management/server/group"
	"github.com/netbirdio/netbird/management/server/testutil"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	route2 "github.com/netbirdio/netbird/route"

	"github.com/netbirdio/netbird/management/server/status"

	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/util"
)

func TestSqlite_NewStore(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("The SQLite store is not properly supported by Windows yet")
	}

	store := newSqliteStore(t)

	if len(store.GetAllAccounts()) != 0 {
		t.Errorf("expected to create a new empty Accounts map when creating a new FileStore")
	}
}

func TestSqlite_SaveAccount_Large(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("The SQLite store is not properly supported by Windows yet")
	}

	store := newSqliteStore(t)

	account := newAccountWithId("account_id", "testuser", "")
	groupALL, err := account.GetGroupAll()
	if err != nil {
		t.Fatal(err)
	}
	setupKey := GenerateDefaultSetupKey()
	account.SetupKeys[setupKey.Key] = setupKey
	const numPerAccount = 2000
	for n := 0; n < numPerAccount; n++ {
		netIP := randomIPv4()
		peerID := fmt.Sprintf("%s-peer-%d", account.Id, n)

		peer := &nbpeer.Peer{
			ID:         peerID,
			Key:        peerID,
			SetupKey:   "",
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

		setupKey := GenerateDefaultSetupKey()
		account.SetupKeys[setupKey.Key] = setupKey
	}

	err = store.SaveAccount(account)
	require.NoError(t, err)

	if len(store.GetAllAccounts()) != 1 {
		t.Errorf("expecting 1 Accounts to be stored after SaveAccount()")
	}

	a, err := store.GetAccount(account.Id)
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

	store := newSqliteStore(t)

	account := newAccountWithId("account_id", "testuser", "")
	setupKey := GenerateDefaultSetupKey()
	account.SetupKeys[setupKey.Key] = setupKey
	account.Peers["testpeer"] = &nbpeer.Peer{
		Key:      "peerkey",
		SetupKey: "peerkeysetupkey",
		IP:       net.IP{127, 0, 0, 1},
		Meta:     nbpeer.PeerSystemMeta{},
		Name:     "peer name",
		Status:   &nbpeer.PeerStatus{Connected: true, LastSeen: time.Now().UTC()},
	}

	err := store.SaveAccount(account)
	require.NoError(t, err)

	account2 := newAccountWithId("account_id2", "testuser2", "")
	setupKey = GenerateDefaultSetupKey()
	account2.SetupKeys[setupKey.Key] = setupKey
	account2.Peers["testpeer2"] = &nbpeer.Peer{
		Key:      "peerkey2",
		SetupKey: "peerkeysetupkey2",
		IP:       net.IP{127, 0, 0, 2},
		Meta:     nbpeer.PeerSystemMeta{},
		Name:     "peer name 2",
		Status:   &nbpeer.PeerStatus{Connected: true, LastSeen: time.Now().UTC()},
	}

	err = store.SaveAccount(account2)
	require.NoError(t, err)

	if len(store.GetAllAccounts()) != 2 {
		t.Errorf("expecting 2 Accounts to be stored after SaveAccount()")
	}

	a, err := store.GetAccount(account.Id)
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

	if a, err := store.GetAccountByPeerPubKey("peerkey"); a == nil {
		t.Errorf("expecting PeerKeyID2AccountID index updated after SaveAccount(): %v", err)
	}

	if a, err := store.GetAccountByUser("testuser"); a == nil {
		t.Errorf("expecting UserID2AccountID index updated after SaveAccount(): %v", err)
	}

	if a, err := store.GetAccountByPeerID("testpeer"); a == nil {
		t.Errorf("expecting PeerID2AccountID index updated after SaveAccount(): %v", err)
	}

	if a, err := store.GetAccountBySetupKey(setupKey.Key); a == nil {
		t.Errorf("expecting SetupKeyID2AccountID index updated after SaveAccount(): %v", err)
	}
}

func TestSqlite_DeleteAccount(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("The SQLite store is not properly supported by Windows yet")
	}

	store := newSqliteStore(t)

	testUserID := "testuser"
	user := NewAdminUser(testUserID)
	user.PATs = map[string]*PersonalAccessToken{"testtoken": {
		ID:   "testtoken",
		Name: "test token",
	}}

	account := newAccountWithId("account_id", testUserID, "")
	setupKey := GenerateDefaultSetupKey()
	account.SetupKeys[setupKey.Key] = setupKey
	account.Peers["testpeer"] = &nbpeer.Peer{
		Key:      "peerkey",
		SetupKey: "peerkeysetupkey",
		IP:       net.IP{127, 0, 0, 1},
		Meta:     nbpeer.PeerSystemMeta{},
		Name:     "peer name",
		Status:   &nbpeer.PeerStatus{Connected: true, LastSeen: time.Now().UTC()},
	}
	account.Users[testUserID] = user

	err := store.SaveAccount(account)
	require.NoError(t, err)

	if len(store.GetAllAccounts()) != 1 {
		t.Errorf("expecting 1 Accounts to be stored after SaveAccount()")
	}

	err = store.DeleteAccount(account)
	require.NoError(t, err)

	if len(store.GetAllAccounts()) != 0 {
		t.Errorf("expecting 0 Accounts to be stored after DeleteAccount()")
	}

	_, err = store.GetAccountByPeerPubKey("peerkey")
	require.Error(t, err, "expecting error after removing DeleteAccount when getting account by peer public key")

	_, err = store.GetAccountByUser("testuser")
	require.Error(t, err, "expecting error after removing DeleteAccount when getting account by user")

	_, err = store.GetAccountByPeerID("testpeer")
	require.Error(t, err, "expecting error after removing DeleteAccount when getting account by peer id")

	_, err = store.GetAccountBySetupKey(setupKey.Key)
	require.Error(t, err, "expecting error after removing DeleteAccount when getting account by setup key")

	_, err = store.GetAccount(account.Id)
	require.Error(t, err, "expecting error after removing DeleteAccount when getting account by id")

	for _, policy := range account.Policies {
		var rules []*PolicyRule
		err = store.db.Model(&PolicyRule{}).Find(&rules, "policy_id = ?", policy.ID).Error
		require.NoError(t, err, "expecting no error after removing DeleteAccount when searching for policy rules")
		require.Len(t, rules, 0, "expecting no policy rules to be found after removing DeleteAccount")

	}

	for _, accountUser := range account.Users {
		var pats []*PersonalAccessToken
		err = store.db.Model(&PersonalAccessToken{}).Find(&pats, "user_id = ?", accountUser.Id).Error
		require.NoError(t, err, "expecting no error after removing DeleteAccount when searching for personal access token")
		require.Len(t, pats, 0, "expecting no personal access token to be found after removing DeleteAccount")

	}

}

func TestSqlite_GetAccount(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("The SQLite store is not properly supported by Windows yet")
	}

	store := newSqliteStoreFromFile(t, "testdata/store.json")

	id := "bf1c8084-ba50-4ce7-9439-34653001fc3b"

	account, err := store.GetAccount(id)
	require.NoError(t, err)
	require.Equal(t, id, account.Id, "account id should match")

	_, err = store.GetAccount("non-existing-account")
	assert.Error(t, err)
	parsedErr, ok := status.FromError(err)
	require.True(t, ok)
	require.Equal(t, status.NotFound, parsedErr.Type(), "should return not found error")
}

func TestSqlite_SavePeerStatus(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("The SQLite store is not properly supported by Windows yet")
	}

	store := newSqliteStoreFromFile(t, "testdata/store.json")

	account, err := store.GetAccount("bf1c8084-ba50-4ce7-9439-34653001fc3b")
	require.NoError(t, err)

	// save status of non-existing peer
	newStatus := nbpeer.PeerStatus{Connected: true, LastSeen: time.Now().UTC()}
	err = store.SavePeerStatus(account.Id, "non-existing-peer", newStatus)
	assert.Error(t, err)
	parsedErr, ok := status.FromError(err)
	require.True(t, ok)
	require.Equal(t, status.NotFound, parsedErr.Type(), "should return not found error")

	// save new status of existing peer
	account.Peers["testpeer"] = &nbpeer.Peer{
		Key:      "peerkey",
		ID:       "testpeer",
		SetupKey: "peerkeysetupkey",
		IP:       net.IP{127, 0, 0, 1},
		Meta:     nbpeer.PeerSystemMeta{},
		Name:     "peer name",
		Status:   &nbpeer.PeerStatus{Connected: false, LastSeen: time.Now().UTC()},
	}

	err = store.SaveAccount(account)
	require.NoError(t, err)

	err = store.SavePeerStatus(account.Id, "testpeer", newStatus)
	require.NoError(t, err)

	account, err = store.GetAccount(account.Id)
	require.NoError(t, err)

	actual := account.Peers["testpeer"].Status
	assert.Equal(t, newStatus, *actual)
}
func TestSqlite_SavePeerLocation(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("The SQLite store is not properly supported by Windows yet")
	}

	store := newSqliteStoreFromFile(t, "testdata/store.json")

	account, err := store.GetAccount("bf1c8084-ba50-4ce7-9439-34653001fc3b")
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
	err = store.SaveAccount(account)
	require.NoError(t, err)

	peer.Location.ConnectionIP = net.ParseIP("35.1.1.1")
	peer.Location.CountryCode = "DE"
	peer.Location.CityName = "Berlin"
	peer.Location.GeoNameID = 2950159

	err = store.SavePeerLocation(account.Id, account.Peers[peer.ID])
	assert.NoError(t, err)

	account, err = store.GetAccount(account.Id)
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

	store := newSqliteStoreFromFile(t, "testdata/store.json")

	existingDomain := "test.com"

	account, err := store.GetAccountByPrivateDomain(existingDomain)
	require.NoError(t, err, "should found account")
	require.Equal(t, existingDomain, account.Domain, "domains should match")

	_, err = store.GetAccountByPrivateDomain("missing-domain.com")
	require.Error(t, err, "should return error on domain lookup")
	parsedErr, ok := status.FromError(err)
	require.True(t, ok)
	require.Equal(t, status.NotFound, parsedErr.Type(), "should return not found error")
}

func TestSqlite_GetTokenIDByHashedToken(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("The SQLite store is not properly supported by Windows yet")
	}

	store := newSqliteStoreFromFile(t, "testdata/store.json")

	hashed := "SoMeHaShEdToKeN"
	id := "9dj38s35-63fb-11ec-90d6-0242ac120003"

	token, err := store.GetTokenIDByHashedToken(hashed)
	require.NoError(t, err)
	require.Equal(t, id, token)

	_, err = store.GetTokenIDByHashedToken("non-existing-hash")
	require.Error(t, err)
	parsedErr, ok := status.FromError(err)
	require.True(t, ok)
	require.Equal(t, status.NotFound, parsedErr.Type(), "should return not found error")
}

func TestSqlite_GetUserByTokenID(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("The SQLite store is not properly supported by Windows yet")
	}

	store := newSqliteStoreFromFile(t, "testdata/store.json")

	id := "9dj38s35-63fb-11ec-90d6-0242ac120003"

	user, err := store.GetUserByTokenID(id)
	require.NoError(t, err)
	require.Equal(t, id, user.PATs[id].ID)

	_, err = store.GetUserByTokenID("non-existing-id")
	require.Error(t, err)
	parsedErr, ok := status.FromError(err)
	require.True(t, ok)
	require.Equal(t, status.NotFound, parsedErr.Type(), "should return not found error")
}

func TestMigrate(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("The SQLite store is not properly supported by Windows yet")
	}

	store := newSqliteStore(t)

	err := migrate(store.db)
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

	err = store.db.Save(act).Error
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
	}

	err = store.db.Save(rt).Error
	require.NoError(t, err, "Failed to insert Gob data")

	err = migrate(store.db)
	require.NoError(t, err, "Migration should not fail on gob populated db")

	err = migrate(store.db)
	require.NoError(t, err, "Migration should not fail on migrated db")
}

func newSqliteStore(t *testing.T) *SqlStore {
	t.Helper()

	store, err := NewSqliteStore(t.TempDir(), nil)
	require.NoError(t, err)
	require.NotNil(t, store)

	return store
}

func newSqliteStoreFromFile(t *testing.T, filename string) *SqlStore {
	t.Helper()

	storeDir := t.TempDir()

	err := util.CopyFileContents(filename, filepath.Join(storeDir, "store.json"))
	require.NoError(t, err)

	fStore, err := NewFileStore(storeDir, nil)
	require.NoError(t, err)

	store, err := NewSqliteStoreFromFileStore(fStore, storeDir, nil)
	require.NoError(t, err)
	require.NotNil(t, store)

	return store
}

func newAccount(store Store, id int) error {
	str := fmt.Sprintf("%s-%d", uuid.New().String(), id)
	account := newAccountWithId(str, str+"-testuser", "example.com")
	setupKey := GenerateDefaultSetupKey()
	account.SetupKeys[setupKey.Key] = setupKey
	account.Peers["p"+str] = &nbpeer.Peer{
		Key:      "peerkey" + str,
		SetupKey: "peerkeysetupkey",
		IP:       net.IP{127, 0, 0, 1},
		Meta:     nbpeer.PeerSystemMeta{},
		Name:     "peer name",
		Status:   &nbpeer.PeerStatus{Connected: true, LastSeen: time.Now().UTC()},
	}

	return store.SaveAccount(account)
}

func newPostgresqlStore(t *testing.T) *SqlStore {
	t.Helper()

	cleanUp, err := testutil.CreatePGDB()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cleanUp)

	postgresDsn, ok := os.LookupEnv(postgresDsnEnv)
	if !ok {
		t.Fatalf("could not initialize postgresql store: %s is not set", postgresDsnEnv)
	}

	store, err := NewPostgresqlStore(postgresDsn, nil)
	if err != nil {
		t.Fatalf("could not initialize postgresql store: %s", err)
	}
	require.NoError(t, err)
	require.NotNil(t, store)

	return store
}

func newPostgresqlStoreFromFile(t *testing.T, filename string) *SqlStore {
	t.Helper()

	storeDir := t.TempDir()
	err := util.CopyFileContents(filename, filepath.Join(storeDir, "store.json"))
	require.NoError(t, err)

	fStore, err := NewFileStore(storeDir, nil)
	require.NoError(t, err)

	cleanUp, err := testutil.CreatePGDB()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cleanUp)

	postgresDsn, ok := os.LookupEnv(postgresDsnEnv)
	if !ok {
		t.Fatalf("could not initialize postgresql store: %s is not set", postgresDsnEnv)
	}

	store, err := NewPostgresqlStoreFromFileStore(fStore, postgresDsn, nil)
	require.NoError(t, err)
	require.NotNil(t, store)

	return store
}

func TestPostgresql_NewStore(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skipf("The PostgreSQL store is not properly supported by %s yet", runtime.GOOS)
	}

	store := newPostgresqlStore(t)

	if len(store.GetAllAccounts()) != 0 {
		t.Errorf("expected to create a new empty Accounts map when creating a new FileStore")
	}
}

func TestPostgresql_SaveAccount(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skipf("The PostgreSQL store is not properly supported by %s yet", runtime.GOOS)
	}

	store := newPostgresqlStore(t)

	account := newAccountWithId("account_id", "testuser", "")
	setupKey := GenerateDefaultSetupKey()
	account.SetupKeys[setupKey.Key] = setupKey
	account.Peers["testpeer"] = &nbpeer.Peer{
		Key:      "peerkey",
		SetupKey: "peerkeysetupkey",
		IP:       net.IP{127, 0, 0, 1},
		Meta:     nbpeer.PeerSystemMeta{},
		Name:     "peer name",
		Status:   &nbpeer.PeerStatus{Connected: true, LastSeen: time.Now().UTC()},
	}

	err := store.SaveAccount(account)
	require.NoError(t, err)

	account2 := newAccountWithId("account_id2", "testuser2", "")
	setupKey = GenerateDefaultSetupKey()
	account2.SetupKeys[setupKey.Key] = setupKey
	account2.Peers["testpeer2"] = &nbpeer.Peer{
		Key:      "peerkey2",
		SetupKey: "peerkeysetupkey2",
		IP:       net.IP{127, 0, 0, 2},
		Meta:     nbpeer.PeerSystemMeta{},
		Name:     "peer name 2",
		Status:   &nbpeer.PeerStatus{Connected: true, LastSeen: time.Now().UTC()},
	}

	err = store.SaveAccount(account2)
	require.NoError(t, err)

	if len(store.GetAllAccounts()) != 2 {
		t.Errorf("expecting 2 Accounts to be stored after SaveAccount()")
	}

	a, err := store.GetAccount(account.Id)
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

	if a, err := store.GetAccountByPeerPubKey("peerkey"); a == nil {
		t.Errorf("expecting PeerKeyID2AccountID index updated after SaveAccount(): %v", err)
	}

	if a, err := store.GetAccountByUser("testuser"); a == nil {
		t.Errorf("expecting UserID2AccountID index updated after SaveAccount(): %v", err)
	}

	if a, err := store.GetAccountByPeerID("testpeer"); a == nil {
		t.Errorf("expecting PeerID2AccountID index updated after SaveAccount(): %v", err)
	}

	if a, err := store.GetAccountBySetupKey(setupKey.Key); a == nil {
		t.Errorf("expecting SetupKeyID2AccountID index updated after SaveAccount(): %v", err)
	}
}

func TestPostgresql_DeleteAccount(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skipf("The PostgreSQL store is not properly supported by %s yet", runtime.GOOS)
	}

	store := newPostgresqlStore(t)

	testUserID := "testuser"
	user := NewAdminUser(testUserID)
	user.PATs = map[string]*PersonalAccessToken{"testtoken": {
		ID:   "testtoken",
		Name: "test token",
	}}

	account := newAccountWithId("account_id", testUserID, "")
	setupKey := GenerateDefaultSetupKey()
	account.SetupKeys[setupKey.Key] = setupKey
	account.Peers["testpeer"] = &nbpeer.Peer{
		Key:      "peerkey",
		SetupKey: "peerkeysetupkey",
		IP:       net.IP{127, 0, 0, 1},
		Meta:     nbpeer.PeerSystemMeta{},
		Name:     "peer name",
		Status:   &nbpeer.PeerStatus{Connected: true, LastSeen: time.Now().UTC()},
	}
	account.Users[testUserID] = user

	err := store.SaveAccount(account)
	require.NoError(t, err)

	if len(store.GetAllAccounts()) != 1 {
		t.Errorf("expecting 1 Accounts to be stored after SaveAccount()")
	}

	err = store.DeleteAccount(account)
	require.NoError(t, err)

	if len(store.GetAllAccounts()) != 0 {
		t.Errorf("expecting 0 Accounts to be stored after DeleteAccount()")
	}

	_, err = store.GetAccountByPeerPubKey("peerkey")
	require.Error(t, err, "expecting error after removing DeleteAccount when getting account by peer public key")

	_, err = store.GetAccountByUser("testuser")
	require.Error(t, err, "expecting error after removing DeleteAccount when getting account by user")

	_, err = store.GetAccountByPeerID("testpeer")
	require.Error(t, err, "expecting error after removing DeleteAccount when getting account by peer id")

	_, err = store.GetAccountBySetupKey(setupKey.Key)
	require.Error(t, err, "expecting error after removing DeleteAccount when getting account by setup key")

	_, err = store.GetAccount(account.Id)
	require.Error(t, err, "expecting error after removing DeleteAccount when getting account by id")

	for _, policy := range account.Policies {
		var rules []*PolicyRule
		err = store.db.Model(&PolicyRule{}).Find(&rules, "policy_id = ?", policy.ID).Error
		require.NoError(t, err, "expecting no error after removing DeleteAccount when searching for policy rules")
		require.Len(t, rules, 0, "expecting no policy rules to be found after removing DeleteAccount")

	}

	for _, accountUser := range account.Users {
		var pats []*PersonalAccessToken
		err = store.db.Model(&PersonalAccessToken{}).Find(&pats, "user_id = ?", accountUser.Id).Error
		require.NoError(t, err, "expecting no error after removing DeleteAccount when searching for personal access token")
		require.Len(t, pats, 0, "expecting no personal access token to be found after removing DeleteAccount")

	}

}

func TestPostgresql_SavePeerStatus(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skipf("The PostgreSQL store is not properly supported by %s yet", runtime.GOOS)
	}

	store := newPostgresqlStoreFromFile(t, "testdata/store.json")

	account, err := store.GetAccount("bf1c8084-ba50-4ce7-9439-34653001fc3b")
	require.NoError(t, err)

	// save status of non-existing peer
	newStatus := nbpeer.PeerStatus{Connected: true, LastSeen: time.Now().UTC()}
	err = store.SavePeerStatus(account.Id, "non-existing-peer", newStatus)
	assert.Error(t, err)

	// save new status of existing peer
	account.Peers["testpeer"] = &nbpeer.Peer{
		Key:      "peerkey",
		ID:       "testpeer",
		SetupKey: "peerkeysetupkey",
		IP:       net.IP{127, 0, 0, 1},
		Meta:     nbpeer.PeerSystemMeta{},
		Name:     "peer name",
		Status:   &nbpeer.PeerStatus{Connected: false, LastSeen: time.Now().UTC()},
	}

	err = store.SaveAccount(account)
	require.NoError(t, err)

	err = store.SavePeerStatus(account.Id, "testpeer", newStatus)
	require.NoError(t, err)

	account, err = store.GetAccount(account.Id)
	require.NoError(t, err)

	actual := account.Peers["testpeer"].Status
	assert.Equal(t, newStatus.Connected, actual.Connected)
}

func TestPostgresql_TestGetAccountByPrivateDomain(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skipf("The PostgreSQL store is not properly supported by %s yet", runtime.GOOS)
	}

	store := newPostgresqlStoreFromFile(t, "testdata/store.json")

	existingDomain := "test.com"

	account, err := store.GetAccountByPrivateDomain(existingDomain)
	require.NoError(t, err, "should found account")
	require.Equal(t, existingDomain, account.Domain, "domains should match")

	_, err = store.GetAccountByPrivateDomain("missing-domain.com")
	require.Error(t, err, "should return error on domain lookup")
}

func TestPostgresql_GetTokenIDByHashedToken(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skipf("The PostgreSQL store is not properly supported by %s yet", runtime.GOOS)
	}

	store := newPostgresqlStoreFromFile(t, "testdata/store.json")

	hashed := "SoMeHaShEdToKeN"
	id := "9dj38s35-63fb-11ec-90d6-0242ac120003"

	token, err := store.GetTokenIDByHashedToken(hashed)
	require.NoError(t, err)
	require.Equal(t, id, token)
}

func TestPostgresql_GetUserByTokenID(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skipf("The PostgreSQL store is not properly supported by %s yet", runtime.GOOS)
	}

	store := newPostgresqlStoreFromFile(t, "testdata/store.json")

	id := "9dj38s35-63fb-11ec-90d6-0242ac120003"

	user, err := store.GetUserByTokenID(id)
	require.NoError(t, err)
	require.Equal(t, id, user.PATs[id].ID)
}
