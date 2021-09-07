package server

import (
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"net"
	"testing"
)

func TestAccountManager_AddAccount(t *testing.T) {
	manager, err := createManager(t)
	if err != nil {
		t.Fatal(err)
		return
	}

	expectedId := "test_account"
	expectedPeersSize := 0
	expectedSetupKeysSize := 2
	expectedNetwork := net.IPNet{
		IP:   net.IP{100, 64, 0, 0},
		Mask: net.IPMask{255, 192, 0, 0},
	}

	account, err := manager.AddAccount(expectedId)
	if err != nil {
		t.Fatal(err)
	}

	if account.Id != expectedId {
		t.Errorf("expected account to have Id = %s, got %s", expectedId, account.Id)
	}

	if len(account.Peers) != expectedPeersSize {
		t.Errorf("expected account to have len(Peers) = %v, got %v", expectedPeersSize, len(account.Peers))
	}

	if len(account.SetupKeys) != expectedSetupKeysSize {
		t.Errorf("expected account to have len(SetupKeys) = %v, got %v", expectedSetupKeysSize, len(account.SetupKeys))
	}

	if account.Network.Net.String() != expectedNetwork.String() {
		t.Errorf("expected account to have Network = %v, got %v", expectedNetwork.String(), account.Network.Net.String())
	}
}

func TestAccountManager_GetOrCreateAccount(t *testing.T) {
	manager, err := createManager(t)
	if err != nil {
		t.Fatal(err)
		return
	}

	expectedId := "test_account"

	//make sure account doesn't exist
	account, err := manager.GetAccount(expectedId)
	if err != nil {
		errStatus, ok := status.FromError(err)
		if !(ok && errStatus.Code() == codes.NotFound) {
			t.Fatal(err)
		}
	}
	if account != nil {
		t.Fatal("expecting empty account")
	}

	account, err = manager.GetOrCreateAccount(expectedId)
	if err != nil {
		t.Fatal(err)
	}

	if account.Id != expectedId {
		t.Fatalf("expected to create an account, got wrong account")
	}

	account, err = manager.GetOrCreateAccount(expectedId)
	if err != nil {
		t.Errorf("expected to get existing account after creation, failed")
	}

	if account.Id != expectedId {
		t.Fatalf("expected to create an account, got wrong account")
	}
}

func TestAccountManager_AccountExists(t *testing.T) {
	manager, err := createManager(t)
	if err != nil {
		t.Fatal(err)
		return
	}

	expectedId := "test_account"
	_, err = manager.AddAccount(expectedId)
	if err != nil {
		t.Fatal(err)
	}

	exists, err := manager.AccountExists(expectedId)
	if err != nil {
		t.Fatal(err)
	}

	if !*exists {
		t.Errorf("expected account to exist after creation, got false")
	}

}

func TestAccountManager_GetAccount(t *testing.T) {
	manager, err := createManager(t)
	if err != nil {
		t.Fatal(err)
		return
	}

	expectedId := "test_account"
	account, err := manager.AddAccount(expectedId)
	if err != nil {
		t.Fatal(err)
	}

	//AddAccount has been already tested so we can assume it is correct and compare results
	getAccount, err := manager.GetAccount(expectedId)
	if err != nil {
		t.Fatal(err)
		return
	}

	if account.Id != getAccount.Id {
		t.Errorf("expected account.Id %s, got %s", account.Id, getAccount.Id)
	}

	for _, peer := range account.Peers {
		if _, ok := getAccount.Peers[peer.Key]; !ok {
			t.Errorf("expected account to have peer %s, not found", peer.Key)
		}
	}

	for _, key := range account.SetupKeys {
		if _, ok := getAccount.SetupKeys[key.Key]; !ok {
			t.Errorf("expected account to have setup key %s, not found", key.Key)
		}
	}

}

func TestAccountManager_AddPeer(t *testing.T) {
	manager, err := createManager(t)
	if err != nil {
		t.Fatal(err)
		return
	}

	account, err := manager.AddAccount("test_account")
	if err != nil {
		t.Fatal(err)
	}

	var setupKey *SetupKey
	for _, key := range account.SetupKeys {
		setupKey = key
	}

	if setupKey == nil {
		t.Errorf("expecting account to have a default setup key")
		return
	}

	key, err := wgtypes.GenerateKey()
	if err != nil {
		t.Fatal(err)
		return
	}
	expectedPeerKey := key.PublicKey().String()
	expectedPeerIP := "100.64.0.1"

	peer, err := manager.AddPeer(setupKey.Key, Peer{
		Key:  expectedPeerKey,
		Meta: PeerSystemMeta{},
		Name: expectedPeerKey,
	})
	if err != nil {
		t.Errorf("expecting peer to be added, got failure %v", err)
		return
	}

	if peer.Key != expectedPeerKey {
		t.Errorf("expecting just added peer to have key = %s, got %s", expectedPeerKey, peer.Key)
	}

	if peer.Key != expectedPeerKey {
		t.Errorf("expecting just added peer to have IP = %s, got %s", expectedPeerIP, peer.IP.String())
	}

}
func createManager(t *testing.T) (*AccountManager, error) {
	store, err := createStore(t)
	if err != nil {
		return nil, err
	}
	return NewManager(store, NewPeersUpdateManager()), nil
}

func createStore(t *testing.T) (Store, error) {
	dataDir := t.TempDir()
	store, err := NewStore(dataDir)
	if err != nil {
		return nil, err
	}

	return store, nil
}
