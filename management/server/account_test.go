package server

import (
	"net"
	"testing"
)

func TestAccountManager_AddAccount(t *testing.T) {
	store, err := createStore(t)
	if err != nil {
		t.Fatal(err)
	}

	expectedId := "test_account"
	expectedPeersSize := 0
	expectedSetupKeysSize := 1
	expectedNetwork := net.IPNet{
		IP:   net.IP{100, 64, 0, 0},
		Mask: net.IPMask{255, 192, 0, 0},
	}

	manager := NewManager(store)
	account, err := manager.AddAccount(expectedId)
	if err != nil {
		t.Fatal(err)
	}

	if account.Id != expectedId {
		t.Errorf("expected account to have ID = %s, got %s", expectedId, account.Id)
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

func TestAccountManager_AddPeer(t *testing.T) {

	store, err := createStore(t)
	if err != nil {
		t.Fatal(err)
	}

	manager := NewManager(store)

	_, err = manager.AddAccount("test_account")
	if err != nil {
		t.Fatal(err)
	}

	//manager.AddPeer(account.SetupKeys[0].Key, "peer-key")
}

func createStore(t *testing.T) (Store, error) {
	dataDir := t.TempDir()
	store, err := NewStore(dataDir)
	if err != nil {
		return nil, err
	}

	return store, nil
}
