package server

import (
	"github.com/stretchr/testify/require"
	"github.com/wiretrustee/wiretrustee/util"
	"net"
	"path/filepath"
	"testing"
	"time"
)

func TestNewStore(t *testing.T) {
	store := newStore(t)

	if store.Accounts == nil || len(store.Accounts) != 0 {
		t.Errorf("expected to create a new empty Accounts map when creating a new FileStore")
	}

	if store.SetupKeyId2AccountId == nil || len(store.SetupKeyId2AccountId) != 0 {
		t.Errorf("expected to create a new empty SetupKeyId2AccountId map when creating a new FileStore")
	}

	if store.PeerKeyId2AccountId == nil || len(store.PeerKeyId2AccountId) != 0 {
		t.Errorf("expected to create a new empty PeerKeyId2AccountId map when creating a new FileStore")
	}

	if store.UserId2AccountId == nil || len(store.UserId2AccountId) != 0 {
		t.Errorf("expected to create a new empty UserId2AccountId map when creating a new FileStore")
	}

}

func TestSaveAccount(t *testing.T) {
	store := newStore(t)

	account := NewAccount("testuser", "")
	account.Users["testuser"] = NewAdminUser("testuser")
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

	if store.PeerKeyId2AccountId["peerkey"] == "" {
		t.Errorf("expecting PeerKeyId2AccountId index updated after SaveAccount()")
	}

	if store.UserId2AccountId["testuser"] == "" {
		t.Errorf("expecting UserId2AccountId index updated after SaveAccount()")
	}

	if store.SetupKeyId2AccountId[setupKey.Key] == "" {
		t.Errorf("expecting SetupKeyId2AccountId index updated after SaveAccount()")
	}

}

func TestStore(t *testing.T) {
	store := newStore(t)

	account := NewAccount("testuser", "")
	account.Users["testuser"] = NewAdminUser("testuser")
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

	require.Len(t, store.UserId2AccountId, 2, "failed to restore a FileStore wrong UserId2AccountId mapping length")

	require.Len(t, store.SetupKeyId2AccountId, 1, "failed to restore a FileStore wrong SetupKeyId2AccountId mapping length")

	require.Len(t, store.PrivateDomain2AccountId, 1, "failed to restore a FileStore wrong PrivateDomain2AccountId mapping length")
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

func newStore(t *testing.T) *FileStore {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Errorf("failed creating a new store")
	}

	return store
}
