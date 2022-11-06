package server

import (
	"github.com/netbirdio/netbird/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"net"
	"path/filepath"
	"testing"
	"time"
)

type accounts struct {
	Accounts map[string]*Account
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

	// SaveAccount should trigger persist
	err := store.SaveAccount(account)
	if err != nil {
		return
	}

	restored, err := NewStore(store.storeFile)
	if err != nil {
		return
	}

	restoredAccount := restored.Accounts[account.Id]
	if restoredAccount == nil {
		t.Errorf("failed to restore a FileStore file - missing Account %s", account.Id)
	}

	if restoredAccount != nil && restoredAccount.Peers["testpeer"] == nil {
		t.Errorf("failed to restore a FileStore file - missing Peer testpeer")
	}

	if restoredAccount != nil && restoredAccount.CreatedBy != "testuser" {
		t.Errorf("failed to restore a FileStore file - missing Account CreatedBy")
	}

	if restoredAccount != nil && restoredAccount.Users["testuser"] == nil {
		t.Errorf("failed to restore a FileStore file - missing User testuser")
	}

	if restoredAccount != nil && restoredAccount.Network == nil {
		t.Errorf("failed to restore a FileStore file - missing Network")
	}

}

func TestRestore(t *testing.T) {
	storeDir := t.TempDir()

	err := util.CopyFileContents("testdata/store.json", filepath.Join(storeDir, "store.json"))
	if err != nil {
		t.Fatal(err)
	}

	store, err := NewStore(storeDir)
	if err != nil {
		return
	}

	account := store.Accounts["bf1c8084-ba50-4ce7-9439-34653001fc3b"]

	require.NotNil(t, account, "failed to restore a FileStore file - missing account bf1c8084-ba50-4ce7-9439-34653001fc3b")

	require.NotNil(t, account.Users["edafee4e-63fb-11ec-90d6-0242ac120003"], "failed to restore a FileStore file - missing Account User edafee4e-63fb-11ec-90d6-0242ac120003")

	require.NotNil(t, account.Users["f4f6d672-63fb-11ec-90d6-0242ac120003"], "failed to restore a FileStore file - missing Account User f4f6d672-63fb-11ec-90d6-0242ac120003")

	require.NotNil(t, account.Network, "failed to restore a FileStore file - missing Account Network")

	require.NotNil(t, account.SetupKeys["A2C8E62B-38F5-4553-B31E-DD66C696CEBB"], "failed to restore a FileStore file - missing Account SetupKey A2C8E62B-38F5-4553-B31E-DD66C696CEBB")

	require.Len(t, store.UserID2AccountID, 2, "failed to restore a FileStore wrong UserID2AccountID mapping length")

	require.Len(t, store.SetupKeyID2AccountID, 1, "failed to restore a FileStore wrong SetupKeyID2AccountID mapping length")

	require.Len(t, store.PrivateDomain2AccountID, 1, "failed to restore a FileStore wrong PrivateDomain2AccountID mapping length")
}

func TestGetAccountByPrivateDomain(t *testing.T) {
	storeDir := t.TempDir()

	err := util.CopyFileContents("testdata/store.json", filepath.Join(storeDir, "store.json"))
	if err != nil {
		t.Fatal(err)
	}

	store, err := NewStore(storeDir)
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

	store, err := NewStore(storeDir)
	if err != nil {
		t.Fatal(err)
	}

	expected := accounts.Accounts["bf1c8084-ba50-4ce7-9439-34653001fc3b"]
	if expected == nil {
		t.Errorf("expected account doesn't exist")
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

func newStore(t *testing.T) *FileStore {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Errorf("failed creating a new store")
	}

	return store
}
