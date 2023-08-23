package server

import (
	"fmt"
	"net"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/netbirdio/netbird/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

func TestSqlite_SaveAccount(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("The SQLite store is not properly supported by Windows yet")
	}

	store := newSqliteStore(t)

	account := newAccountWithId("account_id", "testuser", "")
	setupKey := GenerateDefaultSetupKey()
	account.SetupKeys[setupKey.Key] = setupKey
	account.Peers["testpeer"] = &Peer{
		Key:      "peerkey",
		SetupKey: "peerkeysetupkey",
		IP:       net.IP{127, 0, 0, 1},
		Meta:     PeerSystemMeta{},
		Name:     "peer name",
		Status:   &PeerStatus{Connected: true, LastSeen: time.Now().UTC()},
	}

	err := store.SaveAccount(account)
	require.NoError(t, err)

	account2 := newAccountWithId("account_id2", "testuser2", "")
	setupKey = GenerateDefaultSetupKey()
	account2.SetupKeys[setupKey.Key] = setupKey
	account2.Peers["testpeer2"] = &Peer{
		Key:      "peerkey2",
		SetupKey: "peerkeysetupkey2",
		IP:       net.IP{127, 0, 0, 2},
		Meta:     PeerSystemMeta{},
		Name:     "peer name 2",
		Status:   &PeerStatus{Connected: true, LastSeen: time.Now().UTC()},
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

func TestSqlite_SavePeerStatus(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("The SQLite store is not properly supported by Windows yet")
	}

	store := newSqliteStoreFromFile(t, "testdata/store.json")

	account, err := store.GetAccount("bf1c8084-ba50-4ce7-9439-34653001fc3b")
	require.NoError(t, err)

	// save status of non-existing peer
	newStatus := PeerStatus{Connected: true, LastSeen: time.Now().UTC()}
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
		Status:   &PeerStatus{Connected: false, LastSeen: time.Now().UTC()},
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
}

func newSqliteStore(t *testing.T) *SqliteStore {
	t.Helper()

	store, err := NewSqliteStore(t.TempDir(), nil)
	require.NoError(t, err)
	require.NotNil(t, store)

	return store
}

func newSqliteStoreFromFile(t *testing.T, filename string) *SqliteStore {
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
	account.Peers["p"+str] = &Peer{
		Key:      "peerkey" + str,
		SetupKey: "peerkeysetupkey",
		IP:       net.IP{127, 0, 0, 1},
		Meta:     PeerSystemMeta{},
		Name:     "peer name",
		Status:   &PeerStatus{Connected: true, LastSeen: time.Now().UTC()},
	}

	return store.SaveAccount(account)
}
