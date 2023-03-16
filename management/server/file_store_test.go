package server

import (
	"crypto/sha256"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/netbirdio/netbird/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

	store, err := NewFileStore(storeDir)
	if err != nil {
		return
	}

	account, err := store.GetAccount("bf1c8084-ba50-4ce7-9439-34653001fc3b")
	require.NoError(t, err)

	peerID := "some_peer"
	peerKey := "some_peer_key"
	account.Peers[peerID] = &Peer{
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

	account := newAccountWithId("account_id", "testuser", "")
	setupKey := GenerateDefaultSetupKey()
	account.SetupKeys[setupKey.Key] = setupKey
	account.Peers["testpeer"] = &Peer{
		Key:      "peerkey",
		SetupKey: "peerkeysetupkey",
		IP:       net.IP{127, 0, 0, 1},
		Meta:     PeerSystemMeta{},
		Name:     "peer name",
		Status:   &PeerStatus{Connected: true, LastSeen: time.Now()},
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

func TestStore(t *testing.T) {
	store := newStore(t)

	account := newAccountWithId("account_id", "testuser", "")
	account.Peers["testpeer"] = &Peer{
		Key:      "peerkey",
		SetupKey: "peerkeysetupkey",
		IP:       net.IP{127, 0, 0, 1},
		Meta:     PeerSystemMeta{},
		Name:     "peer name",
		Status:   &PeerStatus{Connected: true, LastSeen: time.Now()},
	}
	account.Groups["all"] = &Group{
		ID:    "all",
		Name:  "all",
		Peers: []string{"testpeer"},
	}
	account.Rules["all"] = &Rule{
		ID:          "all",
		Name:        "all",
		Source:      []string{"all"},
		Destination: []string{"all"},
		Flow:        TrafficFlowBidirect,
	}
	account.Policies = append(account.Policies, &Policy{
		ID:      "all",
		Name:    "all",
		Enabled: true,
		Rules:   []*PolicyRule{account.Rules["all"].ToPolicyRule()},
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

	restored, err := NewFileStore(store.storeFile)
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

	if restoredAccount.Rules["all"] == nil {
		t.Errorf("failed to restore a FileStore file - missing Rule all")
		return
	}

	if restoredAccount.Rules["dmz"] == nil {
		t.Errorf("failed to restore a FileStore file - missing Rule dmz")
		return
	}
	assert.Equal(t, account.Rules["all"], restoredAccount.Rules["all"], "failed to restore a FileStore file - missing Rule all")
	assert.Equal(t, account.Rules["dmz"], restoredAccount.Rules["dmz"], "failed to restore a FileStore file - missing Rule dmz")

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

	store, err := NewFileStore(storeDir)
	if err != nil {
		return
	}

	account := store.Accounts["bf1c8084-ba50-4ce7-9439-34653001fc3b"]

	require.NotNil(t, account, "failed to restore a FileStore file - missing account bf1c8084-ba50-4ce7-9439-34653001fc3b")

	require.NotNil(t, account.Users["edafee4e-63fb-11ec-90d6-0242ac120003"], "failed to restore a FileStore file - missing Account User edafee4e-63fb-11ec-90d6-0242ac120003")

	require.NotNil(t, account.Users["f4f6d672-63fb-11ec-90d6-0242ac120003"], "failed to restore a FileStore file - missing Account User f4f6d672-63fb-11ec-90d6-0242ac120003")

	require.NotNil(t, account.Network, "failed to restore a FileStore file - missing Account Network")

	require.NotNil(t, account.SetupKeys["A2C8E62B-38F5-4553-B31E-DD66C696CEBB"], "failed to restore a FileStore file - missing Account SetupKey A2C8E62B-38F5-4553-B31E-DD66C696CEBB")

	require.Len(t, account.Users["f4f6d672-63fb-11ec-90d6-0242ac120003"].PATs, 1, "failed to restore a FileStore wrong PATs length")

	require.Len(t, store.UserID2AccountID, 2, "failed to restore a FileStore wrong UserID2AccountID mapping length")

	require.Len(t, store.SetupKeyID2AccountID, 1, "failed to restore a FileStore wrong SetupKeyID2AccountID mapping length")

	require.Len(t, store.PrivateDomain2AccountID, 1, "failed to restore a FileStore wrong PrivateDomain2AccountID mapping length")

	require.Len(t, store.HashedPAT2TokenID, 1, "failed to restore a FileStore wrong HashedPAT2TokenID mapping length")

	require.Len(t, store.TokenID2UserID, 1, "failed to restore a FileStore wrong TokenID2UserID mapping length")
}

func TestRestorePolicies_Migration(t *testing.T) {
	storeDir := t.TempDir()

	err := util.CopyFileContents("testdata/store_policy_migrate.json", filepath.Join(storeDir, "store.json"))
	if err != nil {
		t.Fatal(err)
	}

	store, err := NewFileStore(storeDir)
	if err != nil {
		return
	}

	account := store.Accounts["bf1c8084-ba50-4ce7-9439-34653001fc3b"]
	require.Len(t, account.Groups, 1, "failed to restore a FileStore file - missing Account Groups")
	require.Len(t, account.Rules, 1, "failed to restore a FileStore file - missing Account Rules")
	require.Len(t, account.Policies, 1, "failed to restore a FileStore file - missing Account Policies")

	policy := account.Policies[0]
	require.Equal(t, policy.Name, "Default", "failed to restore a FileStore file - missing Account Policies Name")
	require.Equal(t, policy.Description,
		"This is a default rule that allows connections between all the resources",
		"failed to restore a FileStore file - missing Account Policies Description")
	expectedPolicy := policy.Copy()
	err = expectedPolicy.UpdateQueryFromRules()
	require.NoError(t, err, "failed to upldate query")
	require.Equal(t, policy.Query, expectedPolicy.Query, "failed to restore a FileStore file - missing Account Policies Query")
	require.Len(t, policy.Rules, 1, "failed to restore a FileStore file - missing Account Policy Rules")
	require.Equal(t, policy.Rules[0].Action, PolicyTrafficActionAccept, "failed to restore a FileStore file - missing Account Policies Action")
	require.Equal(t, policy.Rules[0].Destinations,
		[]string{"cfefqs706sqkneg59g3g"},
		"failed to restore a FileStore file - missing Account Policies Destinations")
	require.Equal(t, policy.Rules[0].Sources,
		[]string{"cfefqs706sqkneg59g3g"},
		"failed to restore a FileStore file - missing Account Policies Sources")
}

func TestGetAccountByPrivateDomain(t *testing.T) {
	storeDir := t.TempDir()

	err := util.CopyFileContents("testdata/store.json", filepath.Join(storeDir, "store.json"))
	if err != nil {
		t.Fatal(err)
	}

	store, err := NewFileStore(storeDir)
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

	store, err := NewFileStore(storeDir)
	if err != nil {
		t.Fatal(err)
	}

	expected := accounts.Accounts["bf1c8084-ba50-4ce7-9439-34653001fc3b"]
	if expected == nil {
		t.Fatalf("expected account doesn't exist")
	}

	account, err := store.GetAccount(expected.Id)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, expected.IsDomainPrimaryAccount, account.IsDomainPrimaryAccount)
	assert.Equal(t, expected.DomainCategory, account.DomainCategory)
	assert.Equal(t, expected.Domain, account.Domain)
	assert.Equal(t, expected.CreatedBy, account.CreatedBy)
	assert.Equal(t, expected.Network.Id, account.Network.Id)
	assert.Len(t, account.Peers, len(expected.Peers))
	assert.Len(t, account.Users, len(expected.Users))
	assert.Len(t, account.SetupKeys, len(expected.SetupKeys))
	assert.Len(t, account.Rules, len(expected.Rules))
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

	store, err := NewFileStore(storeDir)
	if err != nil {
		t.Fatal(err)
	}

	hashedToken := accounts.Accounts["bf1c8084-ba50-4ce7-9439-34653001fc3b"].Users["f4f6d672-63fb-11ec-90d6-0242ac120003"].PATs[0].HashedToken
	tokenID, err := store.GetTokenIDByHashedToken(hashedToken)

	expectedTokenID := accounts.Accounts["bf1c8084-ba50-4ce7-9439-34653001fc3b"].Users["f4f6d672-63fb-11ec-90d6-0242ac120003"].PATs[0].ID
	assert.Equal(t, expectedTokenID, tokenID)
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

	store, err := NewFileStore(storeDir)
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

	store, err := NewFileStore(storeDir)
	if err != nil {
		t.Fatal(err)
	}

	tokenId := accounts.Accounts["bf1c8084-ba50-4ce7-9439-34653001fc3b"].Users["f4f6d672-63fb-11ec-90d6-0242ac120003"].PATs[0].ID
	user, err := store.GetUserByTokenID(tokenId)
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

	store, err := NewFileStore(storeDir)
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

	store, err := NewFileStore(storeDir)
	if err != nil {
		return
	}

	account, err := store.getAccount("bf1c8084-ba50-4ce7-9439-34653001fc3b")
	if err != nil {
		t.Fatal(err)
	}

	// save status of non-existing peer
	newStatus := PeerStatus{Connected: true, LastSeen: time.Now()}
	err = store.SavePeerStatus(account.Id, "non-existing-peer", newStatus)
	assert.Error(t, err)

	// save new status of existing peer
	account.Peers["testpeer"] = &Peer{
		Key:      "peerkey",
		ID:       "testpeer",
		SetupKey: "peerkeysetupkey",
		IP:       net.IP{127, 0, 0, 1},
		Meta:     PeerSystemMeta{},
		Name:     "peer name",
		Status:   &PeerStatus{Connected: false, LastSeen: time.Now()},
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

func newStore(t *testing.T) *FileStore {
	store, err := NewFileStore(t.TempDir())
	if err != nil {
		t.Errorf("failed creating a new store")
	}

	return store
}
