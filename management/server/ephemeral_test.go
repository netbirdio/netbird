package server

import (
	"context"
	"fmt"
	"testing"
	"time"

	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/stretchr/testify/require"
)

type MockStore struct {
	Store
	accountID string
}

type MocAccountManager struct {
	AccountManager
	store *MockStore
}

func (a MocAccountManager) DeletePeer(_ context.Context, accountID, peerID, _ string) error {
	return a.store.DeletePeer(context.Background(), LockingStrengthUpdate, accountID, peerID)
}

func TestNewManager(t *testing.T) {
	startTime := time.Now()
	timeNow = func() time.Time {
		return startTime
	}

	store := &MockStore{
		Store: newStore(t),
	}
	am := MocAccountManager{
		store: store,
	}

	numberOfPeers := 5
	numberOfEphemeralPeers := 3
	err := seedPeers(store, numberOfPeers, numberOfEphemeralPeers)
	require.NoError(t, err, "failed to seed peers")

	mgr := NewEphemeralManager(store, am)
	mgr.loadEphemeralPeers(context.Background())
	startTime = startTime.Add(ephemeralLifeTime + 1)
	mgr.cleanup(context.Background())

	peers, err := store.GetAccountPeers(context.Background(), LockingStrengthShare, store.accountID)
	require.NoError(t, err, "failed to get account peers")
	require.Equal(t, numberOfPeers, len(peers), "failed to cleanup ephemeral peers")
}

func TestNewManagerPeerConnected(t *testing.T) {
	startTime := time.Now()
	timeNow = func() time.Time {
		return startTime
	}

	store := &MockStore{
		Store: newStore(t),
	}
	am := MocAccountManager{
		store: store,
	}

	numberOfPeers := 5
	numberOfEphemeralPeers := 3
	err := seedPeers(store, numberOfPeers, numberOfEphemeralPeers)
	require.NoError(t, err, "failed to seed peers")

	mgr := NewEphemeralManager(store, am)
	mgr.loadEphemeralPeers(context.Background())

	peer, err := am.store.GetPeerByID(context.Background(), LockingStrengthShare, store.accountID, "ephemeral_peer_0")
	require.NoError(t, err, "failed to get peer")

	mgr.OnPeerConnected(context.Background(), peer)

	startTime = startTime.Add(ephemeralLifeTime + 1)
	mgr.cleanup(context.Background())

	peers, err := store.GetAccountPeers(context.Background(), LockingStrengthShare, store.accountID)
	require.NoError(t, err, "failed to get account peers")
	require.Equal(t, numberOfPeers+1, len(peers), "failed to cleanup ephemeral peers")
}

func TestNewManagerPeerDisconnected(t *testing.T) {
	startTime := time.Now()
	timeNow = func() time.Time {
		return startTime
	}

	store := &MockStore{
		Store: newStore(t),
	}
	am := MocAccountManager{
		store: store,
	}

	numberOfPeers := 5
	numberOfEphemeralPeers := 3
	err := seedPeers(store, numberOfPeers, numberOfEphemeralPeers)
	require.NoError(t, err, "failed to seed peers")

	mgr := NewEphemeralManager(store, am)
	mgr.loadEphemeralPeers(context.Background())

	peers, err := store.GetAccountPeers(context.Background(), LockingStrengthShare, store.accountID)
	require.NoError(t, err, "failed to get account peers")
	for _, v := range peers {
		mgr.OnPeerConnected(context.Background(), v)
	}

	peer, err := am.store.GetPeerByID(context.Background(), LockingStrengthShare, store.accountID, "ephemeral_peer_0")
	require.NoError(t, err, "failed to get peer")
	mgr.OnPeerDisconnected(context.Background(), peer)

	startTime = startTime.Add(ephemeralLifeTime + 1)
	mgr.cleanup(context.Background())

	peers, err = store.GetAccountPeers(context.Background(), LockingStrengthShare, store.accountID)
	require.NoError(t, err, "failed to get account peers")
	expected := numberOfPeers + numberOfEphemeralPeers - 1
	require.Equal(t, expected, len(peers), "failed to cleanup ephemeral peers")
}

func seedPeers(store *MockStore, numberOfPeers int, numberOfEphemeralPeers int) error {
	accountID := "my account"
	err := newAccountWithId(context.Background(), store, accountID, "", "")
	if err != nil {
		return err
	}
	store.accountID = accountID

	for i := 0; i < numberOfPeers; i++ {
		peerId := fmt.Sprintf("peer_%d", i)
		p := &nbpeer.Peer{
			ID:        peerId,
			AccountID: accountID,
			Ephemeral: false,
		}
		err = store.AddPeerToAccount(context.Background(), p)
		if err != nil {
			return err
		}
	}

	for i := 0; i < numberOfEphemeralPeers; i++ {
		peerId := fmt.Sprintf("ephemeral_peer_%d", i)
		p := &nbpeer.Peer{
			ID:        peerId,
			AccountID: accountID,
			Ephemeral: true,
		}
		err = store.AddPeerToAccount(context.Background(), p)
		if err != nil {
			return err
		}
	}

	return nil
}
