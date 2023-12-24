package server

import (
	"fmt"
	"testing"
	"time"

	nbpeer "github.com/netbirdio/netbird/management/server/peer"
)

type MockStore struct {
	Store
	account *Account
}

func (s *MockStore) GetAllAccounts() []*Account {
	return []*Account{s.account}
}

func (s *MockStore) GetAccountByPeerID(peerId string) (*Account, error) {
	_, ok := s.account.Peers[peerId]
	if ok {
		return s.account, nil
	}

	return nil, fmt.Errorf("account not found")
}

type MocAccountManager struct {
	AccountManager
	store *MockStore
}

func (a MocAccountManager) DeletePeer(accountID, peerID, userID string) error {
	delete(a.store.account.Peers, peerID)
	return nil //nolint:nil
}

func TestNewManager(t *testing.T) {
	startTime := time.Now()
	timeNow = func() time.Time {
		return startTime
	}

	store := &MockStore{}
	am := MocAccountManager{
		store: store,
	}

	numberOfPeers := 5
	numberOfEphemeralPeers := 3
	seedPeers(store, numberOfPeers, numberOfEphemeralPeers)

	mgr := NewEphemeralManager(store, am)
	mgr.loadEphemeralPeers()
	startTime = startTime.Add(ephemeralLifeTime + 1)
	mgr.cleanup()

	if len(store.account.Peers) != numberOfPeers {
		t.Errorf("failed to cleanup ephemeral peers, expected: %d, result: %d", numberOfPeers, len(store.account.Peers))
	}
}

func TestNewManagerPeerConnected(t *testing.T) {
	startTime := time.Now()
	timeNow = func() time.Time {
		return startTime
	}

	store := &MockStore{}
	am := MocAccountManager{
		store: store,
	}

	numberOfPeers := 5
	numberOfEphemeralPeers := 3
	seedPeers(store, numberOfPeers, numberOfEphemeralPeers)

	mgr := NewEphemeralManager(store, am)
	mgr.loadEphemeralPeers()
	mgr.OnPeerConnected(store.account.Peers["ephemeral_peer_0"])

	startTime = startTime.Add(ephemeralLifeTime + 1)
	mgr.cleanup()

	expected := numberOfPeers + 1
	if len(store.account.Peers) != expected {
		t.Errorf("failed to cleanup ephemeral peers, expected: %d, result: %d", expected, len(store.account.Peers))
	}
}

func TestNewManagerPeerDisconnected(t *testing.T) {
	startTime := time.Now()
	timeNow = func() time.Time {
		return startTime
	}

	store := &MockStore{}
	am := MocAccountManager{
		store: store,
	}

	numberOfPeers := 5
	numberOfEphemeralPeers := 3
	seedPeers(store, numberOfPeers, numberOfEphemeralPeers)

	mgr := NewEphemeralManager(store, am)
	mgr.loadEphemeralPeers()
	for _, v := range store.account.Peers {
		mgr.OnPeerConnected(v)

	}
	mgr.OnPeerDisconnected(store.account.Peers["ephemeral_peer_0"])

	startTime = startTime.Add(ephemeralLifeTime + 1)
	mgr.cleanup()

	expected := numberOfPeers + numberOfEphemeralPeers - 1
	if len(store.account.Peers) != expected {
		t.Errorf("failed to cleanup ephemeral peers, expected: %d, result: %d", expected, len(store.account.Peers))
	}
}

func seedPeers(store *MockStore, numberOfPeers int, numberOfEphemeralPeers int) {
	store.account = newAccountWithId("my account", "", "")

	for i := 0; i < numberOfPeers; i++ {
		peerId := fmt.Sprintf("peer_%d", i)
		p := &nbpeer.Peer{
			ID:        peerId,
			Ephemeral: false,
		}
		store.account.Peers[p.ID] = p
	}

	for i := 0; i < numberOfEphemeralPeers; i++ {
		peerId := fmt.Sprintf("ephemeral_peer_%d", i)
		p := &nbpeer.Peer{
			ID:        peerId,
			Ephemeral: true,
		}
		store.account.Peers[p.ID] = p
	}
}
