package server

import (
	"crypto/sha256"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/server/group"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/util"
)

type accounts struct {
	Accounts map[string]*Account
}

func TestStalePeerIndices(t *testing.T) {
	storeDir := t.TempDir()

	err := util.CopyFileContents("testdata/store.json", filepath.Join(storeDir, "store.json"))
	if err != nil {
		t.Fatal(err)
	}

	store, err := NewFileStore(storeDir, nil)
	if err != nil {
		return
	}

	account, err := store.GetAccount("bf1c8084-ba50-4ce7-9439-34653001fc3b")
	require.NoError(t, err)

	peerID := "some_peer"
	peerKey := "some_peer_key"
	account.Peers[peerID] = &nbpeer.Peer{
		ID:  peerID,
		Key: peerKey,
	}

	err = store.SaveAccount(account)
	require.NoError(t, err)

	account.DeletePeer(peerID)

	err = store.SaveAccount(account)
	require.NoError(t, err)

	_, err = store.GetAccountByPeerID(peerID)
	require.Error(t, err, "expecting to get an error when found stale index")

	_, err = store.GetAccountByPeerPubKey(peerKey)
	require.Error(t, err, "expecting to get an error when found stale index")
}

func TestNewStore(t *testing.T) {
	store := newStore(t)
	defer store.Close()

	if store.Accounts == nil || len(store.Accounts) != 0 {
		t.Errorf("expected to create a new empty Accounts map when creating a new FileStore")
	}

	if store.SetupKeyID2AccountID == nil || len(store.SetupKeyID2AccountID) != 0 {
		t.Errorf("expected to create a new empty SetupKeyID2AccountID map when creating a new FileStore")
	}

	if store.PeerKeyID2AccountID == nil || len(store.PeerKeyID2AccountID) != 0 {
		t.Errorf("expected to create a new empty PeerKeyID2AccountID map when creating a new FileStore")
	}

	if store.UserID2AccountID == nil || len(store.UserID2AccountID) != 0 {
		t.Errorf("expected to create a new empty UserID2AccountID map when creating a new FileStore")
	}

	if store.HashedPAT2TokenID == nil || len(store.HashedPAT2TokenID) != 0 {
		t.Errorf("expected to create a new empty HashedPAT2TokenID map when creating a new FileStore")
	}

	if store.TokenID2UserID == nil || len(store.TokenID2UserID) != 0 {
		t.Errorf("expected to create a new empty TokenID2UserID map when creating a new FileStore")
	}
}

func TestSaveAccount(t *testing.T) {
	store := newStore(t)
	defer store.Close()

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

	// SaveAccount should trigger persist
	err := store.SaveAccount(account)
	if err != nil {
		return
	}

	if store.Accounts[account.Id] == nil {
		t.Errorf("expecting Account to be stored after SaveAccount()")
	}

	if store.PeerKeyID2AccountID["peerkey"] == "" {
		t.Errorf("expecting PeerKeyID2AccountID index updated after SaveAccount()")
	}

	if store.UserID2AccountID["testuser"] == "" {
		t.Errorf("expecting UserID2AccountID index updated after SaveAccount()")
	}

	if store.SetupKeyID2AccountID[setupKey.Key] == "" {
		t.Errorf("expecting SetupKeyID2AccountID index updated after SaveAccount()")
	}
}

func TestDeleteAccount(t *testing.T) {
	storeDir := t.TempDir()
	storeFile := filepath.Join(storeDir, "store.json")
	err := util.CopyFileContents("testdata/store.json", storeFile)
	if err != nil {
		t.Fatal(err)
	}

	store, err := NewFileStore(storeDir, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	var account *Account
	for _, a := range store.Accounts {
		account = a
		break
	}

	require.NotNil(t, account, "failed to restore a FileStore file and get at least one account")

	err = store.DeleteAccount(account)
	require.NoError(t, err, "failed to delete account, error: %v", err)

	_, ok := store.Accounts[account.Id]
	require.False(t, ok, "failed to delete account")

	for id := range account.Users {
		_, ok := store.UserID2AccountID[id]
		assert.False(t, ok, "failed to delete UserID2AccountID index")
		for _, pat := range account.Users[id].PATs {
			_, ok := store.HashedPAT2TokenID[pat.HashedToken]
			assert.False(t, ok, "failed to delete HashedPAT2TokenID index")
			_, ok = store.TokenID2UserID[pat.ID]
			assert.False(t, ok, "failed to delete TokenID2UserID index")
		}
	}

	for _, p := range account.Peers {
		_, ok := store.PeerKeyID2AccountID[p.Key]
		assert.False(t, ok, "failed to delete PeerKeyID2AccountID index")
		_, ok = store.PeerID2AccountID[p.ID]
		assert.False(t, ok, "failed to delete PeerID2AccountID index")
	}

	for id := range account.SetupKeys {
		_, ok := store.SetupKeyID2AccountID[id]
		assert.False(t, ok, "failed to delete SetupKeyID2AccountID index")
	}

	_, ok = store.PrivateDomain2AccountID[account.Domain]
	assert.False(t, ok, "failed to delete PrivateDomain2AccountID index")

}

func TestStore(t *testing.T) {
	store := newStore(t)
	defer store.Close()

	account := newAccountWithId("account_id", "testuser", "")
	account.Peers["testpeer"] = &nbpeer.Peer{
		Key:      "peerkey",
		SetupKey: "peerkeysetupkey",
		IP:       net.IP{127, 0, 0, 1},
		Meta:     nbpeer.PeerSystemMeta{},
		Name:     "peer name",
		Status:   &nbpeer.PeerStatus{Connected: true, LastSeen: time.Now().UTC()},
	}
	account.Groups["all"] = &group.Group{
		ID:    "all",
		Name:  "all",
		Peers: []string{"testpeer"},
	}
	account.Policies = append(account.Policies, &Policy{
		ID:      "all",
		Name:    "all",
		Enabled: true,
		Rules: []*PolicyRule{
			{
				ID:           "all",
				Name:         "all",
				Sources:      []string{"all"},
				Destinations: []string{"all"},
			},
		},
	})
	account.Policies = append(account.Policies, &Policy{
		ID:      "dmz",
		Name:    "dmz",
		Enabled: true,
		Rules: []*PolicyRule{
			{
				ID:           "dmz",
				Name:         "dmz",
				Enabled:      true,
				Sources:      []string{"all"},
				Destinations: []string{"all"},
			},
		},
	})

	// SaveAccount should trigger persist
	err := store.SaveAccount(account)
	if err != nil {
		return
	}

	restored, err := NewFileStore(store.storeFile, nil)
	if err != nil {
		return
	}

	restoredAccount := restored.Accounts[account.Id]
	if restoredAccount == nil {
		t.Errorf("failed to restore a FileStore file - missing Account %s", account.Id)
		return
	}

	if restoredAccount.Peers["testpeer"] == nil {
		t.Errorf("failed to restore a FileStore file - missing Peer testpeer")
	}

	if restoredAccount.CreatedBy != "testuser" {
		t.Errorf("failed to restore a FileStore file - missing Account CreatedBy")
	}

	if restoredAccount.Users["testuser"] == nil {
		t.Errorf("failed to restore a FileStore file - missing User testuser")
	}

	if restoredAccount.Network == nil {
		t.Errorf("failed to restore a FileStore file - missing Network")
	}

	if restoredAccount.Groups["all"] == nil {
		t.Errorf("failed to restore a FileStore file - missing Group all")
	}

	if len(restoredAccount.Policies) != 2 {
		t.Errorf("failed to restore a FileStore file - missing Policies")
		return
	}

	assert.Equal(t, account.Policies[0], restoredAccount.Policies[0], "failed to restore a FileStore file - missing Policy all")
	assert.Equal(t, account.Policies[1], restoredAccount.Policies[1], "failed to restore a FileStore file - missing Policy dmz")
}

func TestRestore(t *testing.T) {
	storeDir := t.TempDir()

	err := util.CopyFileContents("testdata/store.json", filepath.Join(storeDir, "store.json"))
	if err != nil {
		t.Fatal(err)
	}

	store, err := NewFileStore(storeDir, nil)
	if err != nil {
		return
	}

	account := store.Accounts["bf1c8084-ba50-4ce7-9439-34653001fc3b"]

	require.NotNil(t, account, "failed to restore a FileStore file - missing account bf1c8084-ba50-4ce7-9439-34653001fc3b")

	require.NotNil(t, account.Users["edafee4e-63fb-11ec-90d6-0242ac120003"], "failed to restore a FileStore file - missing Account User edafee4e-63fb-11ec-90d6-0242ac120003")

	require.NotNil(t, account.Users["f4f6d672-63fb-11ec-90d6-0242ac120003"], "failed to restore a FileStore file - missing Account User f4f6d672-63fb-11ec-90d6-0242ac120003")

	require.NotNil(t, account.Network, "failed to restore a FileStore file - missing Account Network")

	require.NotNil(t, account.SetupKeys["A2C8E62B-38F5-4553-B31E-DD66C696CEBB"], "failed to restore a FileStore file - missing Account SetupKey A2C8E62B-38F5-4553-B31E-DD66C696CEBB")

	require.NotNil(t, account.Users["f4f6d672-63fb-11ec-90d6-0242ac120003"].PATs["9dj38s35-63fb-11ec-90d6-0242ac120003"], "failed to restore a FileStore wrong PATs length")

	require.Len(t, store.UserID2AccountID, 2, "failed to restore a FileStore wrong UserID2AccountID mapping length")

	require.Len(t, store.SetupKeyID2AccountID, 1, "failed to restore a FileStore wrong SetupKeyID2AccountID mapping length")

	require.Len(t, store.PrivateDomain2AccountID, 1, "failed to restore a FileStore wrong PrivateDomain2AccountID mapping length")

	require.Len(t, store.HashedPAT2TokenID, 1, "failed to restore a FileStore wrong HashedPAT2TokenID mapping length")

	require.Len(t, store.TokenID2UserID, 1, "failed to restore a FileStore wrong TokenID2UserID mapping length")
}

func TestRestoreGroups_Migration(t *testing.T) {
	storeDir := t.TempDir()

	err := util.CopyFileContents("testdata/store.json", filepath.Join(storeDir, "store.json"))
	if err != nil {
		t.Fatal(err)
	}

	store, err := NewFileStore(storeDir, nil)
	if err != nil {
		return
	}

	// create default group
	account := store.Accounts["bf1c8084-ba50-4ce7-9439-34653001fc3b"]
	account.Groups = map[string]*group.Group{
		"cfefqs706sqkneg59g3g": {
			ID:   "cfefqs706sqkneg59g3g",
			Name: "All",
		},
	}
	err = store.SaveAccount(account)
	require.NoError(t, err, "failed to save account")

	// restore account with default group with empty Issue field
	if store, err = NewFileStore(storeDir, nil); err != nil {
		return
	}
	account = store.Accounts["bf1c8084-ba50-4ce7-9439-34653001fc3b"]

	require.Contains(t, account.Groups, "cfefqs706sqkneg59g3g", "failed to restore a FileStore file - missing Account Groups")
	require.Equal(t, group.GroupIssuedAPI, account.Groups["cfefqs706sqkneg59g3g"].Issued, "default group should has API issued mark")
}

func TestGetAccountByPrivateDomain(t *testing.T) {
	storeDir := t.TempDir()

	err := util.CopyFileContents("testdata/store.json", filepath.Join(storeDir, "store.json"))
	if err != nil {
		t.Fatal(err)
	}

	store, err := NewFileStore(storeDir, nil)
	if err != nil {
		return
	}

	existingDomain := "test.com"

	account, err := store.GetAccountByPrivateDomain(existingDomain)
	require.NoError(t, err, "should found account")
	require.Equal(t, existingDomain, account.Domain, "domains should match")

	_, err = store.GetAccountByPrivateDomain("missing-domain.com")
	require.Error(t, err, "should return error on domain lookup")
}

func TestFileStore_GetAccount(t *testing.T) {
	storeDir := t.TempDir()
	storeFile := filepath.Join(storeDir, "store.json")
	err := util.CopyFileContents("testdata/store.json", storeFile)
	if err != nil {
		t.Fatal(err)
	}

	accounts := &accounts{}
	_, err = util.ReadJson(storeFile, accounts)
	if err != nil {
		t.Fatal(err)
	}

	store, err := NewFileStore(storeDir, nil)
	if err != nil {
		t.Fatal(err)
	}

	expected := accounts.Accounts["bf1c8084-ba50-4ce7-9439-34653001fc3b"]
	if expected == nil {
		t.Fatalf("expected account doesn't exist")
		return
	}

	account, err := store.GetAccount(expected.Id)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, expected.IsDomainPrimaryAccount, account.IsDomainPrimaryAccount)
	assert.Equal(t, expected.DomainCategory, account.DomainCategory)
	assert.Equal(t, expected.Domain, account.Domain)
	assert.Equal(t, expected.CreatedBy, account.CreatedBy)
	assert.Equal(t, expected.Network.Identifier, account.Network.Identifier)
	assert.Len(t, account.Peers, len(expected.Peers))
	assert.Len(t, account.Users, len(expected.Users))
	assert.Len(t, account.SetupKeys, len(expected.SetupKeys))
	assert.Len(t, account.Routes, len(expected.Routes))
	assert.Len(t, account.NameServerGroups, len(expected.NameServerGroups))
}

func TestFileStore_GetTokenIDByHashedToken(t *testing.T) {
	storeDir := t.TempDir()
	storeFile := filepath.Join(storeDir, "store.json")
	err := util.CopyFileContents("testdata/store.json", storeFile)
	if err != nil {
		t.Fatal(err)
	}

	accounts := &accounts{}
	_, err = util.ReadJson(storeFile, accounts)
	if err != nil {
		t.Fatal(err)
	}

	store, err := NewFileStore(storeDir, nil)
	if err != nil {
		t.Fatal(err)
	}

	hashedToken := accounts.Accounts["bf1c8084-ba50-4ce7-9439-34653001fc3b"].Users["f4f6d672-63fb-11ec-90d6-0242ac120003"].PATs["9dj38s35-63fb-11ec-90d6-0242ac120003"].HashedToken
	tokenID, err := store.GetTokenIDByHashedToken(hashedToken)
	if err != nil {
		t.Fatal(err)
	}

	expectedTokenID := accounts.Accounts["bf1c8084-ba50-4ce7-9439-34653001fc3b"].Users["f4f6d672-63fb-11ec-90d6-0242ac120003"].PATs["9dj38s35-63fb-11ec-90d6-0242ac120003"].ID
	assert.Equal(t, expectedTokenID, tokenID)
}

func TestFileStore_DeleteHashedPAT2TokenIDIndex(t *testing.T) {
	store := newStore(t)
	defer store.Close()
	store.HashedPAT2TokenID["someHashedToken"] = "someTokenId"

	err := store.DeleteHashedPAT2TokenIDIndex("someHashedToken")
	if err != nil {
		t.Fatal(err)
	}

	assert.Empty(t, store.HashedPAT2TokenID["someHashedToken"])
}

func TestFileStore_DeleteTokenID2UserIDIndex(t *testing.T) {
	store := newStore(t)
	store.TokenID2UserID["someTokenId"] = "someUserId"

	err := store.DeleteTokenID2UserIDIndex("someTokenId")
	if err != nil {
		t.Fatal(err)
	}

	assert.Empty(t, store.TokenID2UserID["someTokenId"])
}

func TestFileStore_GetTokenIDByHashedToken_Failure(t *testing.T) {
	storeDir := t.TempDir()
	storeFile := filepath.Join(storeDir, "store.json")
	err := util.CopyFileContents("testdata/store.json", storeFile)
	if err != nil {
		t.Fatal(err)
	}

	accounts := &accounts{}
	_, err = util.ReadJson(storeFile, accounts)
	if err != nil {
		t.Fatal(err)
	}

	store, err := NewFileStore(storeDir, nil)
	if err != nil {
		t.Fatal(err)
	}

	wrongToken := sha256.Sum256([]byte("someNotValidTokenThatFails1234"))
	_, err = store.GetTokenIDByHashedToken(string(wrongToken[:]))

	assert.Error(t, err, "GetTokenIDByHashedToken should throw error if token invalid")
}

func TestFileStore_GetUserByTokenID(t *testing.T) {
	storeDir := t.TempDir()
	storeFile := filepath.Join(storeDir, "store.json")
	err := util.CopyFileContents("testdata/store.json", storeFile)
	if err != nil {
		t.Fatal(err)
	}

	accounts := &accounts{}
	_, err = util.ReadJson(storeFile, accounts)
	if err != nil {
		t.Fatal(err)
	}

	store, err := NewFileStore(storeDir, nil)
	if err != nil {
		t.Fatal(err)
	}

	tokenID := accounts.Accounts["bf1c8084-ba50-4ce7-9439-34653001fc3b"].Users["f4f6d672-63fb-11ec-90d6-0242ac120003"].PATs["9dj38s35-63fb-11ec-90d6-0242ac120003"].ID
	user, err := store.GetUserByTokenID(tokenID)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, "f4f6d672-63fb-11ec-90d6-0242ac120003", user.Id)
}

func TestFileStore_GetUserByTokenID_Failure(t *testing.T) {
	storeDir := t.TempDir()
	storeFile := filepath.Join(storeDir, "store.json")
	err := util.CopyFileContents("testdata/store.json", storeFile)
	if err != nil {
		t.Fatal(err)
	}

	accounts := &accounts{}
	_, err = util.ReadJson(storeFile, accounts)
	if err != nil {
		t.Fatal(err)
	}

	store, err := NewFileStore(storeDir, nil)
	if err != nil {
		t.Fatal(err)
	}

	wrongTokenID := "someNonExistingTokenID"
	_, err = store.GetUserByTokenID(wrongTokenID)

	assert.Error(t, err, "GetUserByTokenID should throw error if tokenID invalid")
}

func TestFileStore_SavePeerStatus(t *testing.T) {
	storeDir := t.TempDir()

	err := util.CopyFileContents("testdata/store.json", filepath.Join(storeDir, "store.json"))
	if err != nil {
		t.Fatal(err)
	}

	store, err := NewFileStore(storeDir, nil)
	if err != nil {
		return
	}

	account, err := store.getAccount("bf1c8084-ba50-4ce7-9439-34653001fc3b")
	if err != nil {
		t.Fatal(err)
	}

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
	if err != nil {
		t.Fatal(err)
	}

	err = store.SavePeerStatus(account.Id, "testpeer", newStatus)
	if err != nil {
		t.Fatal(err)
	}
	account, err = store.getAccount(account.Id)
	if err != nil {
		t.Fatal(err)
	}

	actual := account.Peers["testpeer"].Status
	assert.Equal(t, newStatus, *actual)
}

func TestFileStore_SavePeerLocation(t *testing.T) {
	storeDir := t.TempDir()

	err := util.CopyFileContents("testdata/store.json", filepath.Join(storeDir, "store.json"))
	if err != nil {
		t.Fatal(err)
	}

	store, err := NewFileStore(storeDir, nil)
	if err != nil {
		return
	}
	account, err := store.GetAccount("bf1c8084-ba50-4ce7-9439-34653001fc3b")
	require.NoError(t, err)

	peer := &nbpeer.Peer{
		AccountID: account.Id,
		ID:        "testpeer",
		Location: nbpeer.Location{
			ConnectionIP: net.ParseIP("10.0.0.0"),
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
}

func newStore(t *testing.T) *FileStore {
	t.Helper()
	store, err := NewFileStore(t.TempDir(), nil)
	if err != nil {
		t.Errorf("failed creating a new store")
	}

	return store
}
