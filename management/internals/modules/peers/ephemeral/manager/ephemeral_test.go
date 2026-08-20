package manager

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"

	nbdns "github.com/netbirdio/netbird/dns"
	"github.com/netbirdio/netbird/management/internals/modules/peers"
	"github.com/netbirdio/netbird/management/internals/modules/peers/ephemeral"
	nbAccount "github.com/netbirdio/netbird/management/server/account"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/route"
)

type MockStore struct {
	store.Store
	account *types.Account
}

func (s *MockStore) GetAllEphemeralPeers(_ context.Context, _ store.LockingStrength) ([]*nbpeer.Peer, error) {
	var peers []*nbpeer.Peer
	for _, v := range s.account.Peers {
		if v.Ephemeral {
			peers = append(peers, v)
		}
	}
	return peers, nil
}

type MockAccountManager struct {
	mu sync.Mutex
	nbAccount.Manager
	store             *MockStore
	deletePeerCalls   int
	bufferUpdateCalls map[string]int
	wg                *sync.WaitGroup
}

func (a *MockAccountManager) DeletePeer(_ context.Context, accountID, peerID, userID string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.deletePeerCalls++
	delete(a.store.account.Peers, peerID)
	if a.wg != nil {
		a.wg.Done()
	}
	return nil
}

func (a *MockAccountManager) GetDeletePeerCalls() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.deletePeerCalls
}

func (a *MockAccountManager) BufferUpdateAccountPeers(ctx context.Context, accountID string, reason types.UpdateReason) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.bufferUpdateCalls == nil {
		a.bufferUpdateCalls = make(map[string]int)
	}
	a.bufferUpdateCalls[accountID]++
}

func (a *MockAccountManager) GetBufferUpdateCalls(accountID string) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.bufferUpdateCalls == nil {
		return 0
	}
	return a.bufferUpdateCalls[accountID]
}

func (a *MockAccountManager) GetStore() store.Store {
	return a.store
}

func TestNewManager(t *testing.T) {
	t.Cleanup(func() {
		timeNow = time.Now
	})
	startTime := time.Now()
	timeNow = func() time.Time {
		return startTime
	}

	store := &MockStore{}
	ctrl := gomock.NewController(t)
	peersManager := peers.NewMockManager(ctrl)

	numberOfPeers := 5
	numberOfEphemeralPeers := 3
	seedPeers(store, numberOfPeers, numberOfEphemeralPeers)

	// Expect DeletePeers to be called for ephemeral peers
	peersManager.EXPECT().
		DeletePeers(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), true).
		DoAndReturn(func(ctx context.Context, accountID string, peerIDs []string, userID string, checkConnected bool) ([]string, error) {
			for _, peerID := range peerIDs {
				delete(store.account.Peers, peerID)
			}
			return nil, nil
		}).
		AnyTimes()

	mgr := NewEphemeralManager(store, peersManager)
	mgr.loadEphemeralPeers(context.Background())
	startTime = startTime.Add(ephemeral.EphemeralLifeTime + 1)
	mgr.cleanup(context.Background())

	if len(store.account.Peers) != numberOfPeers {
		t.Errorf("failed to cleanup ephemeral peers, expected: %d, result: %d", numberOfPeers, len(store.account.Peers))
	}
}

func TestNewManagerPeerConnected(t *testing.T) {
	t.Cleanup(func() {
		timeNow = time.Now
	})
	startTime := time.Now()
	timeNow = func() time.Time {
		return startTime
	}

	store := &MockStore{}
	ctrl := gomock.NewController(t)
	peersManager := peers.NewMockManager(ctrl)

	numberOfPeers := 5
	numberOfEphemeralPeers := 3
	seedPeers(store, numberOfPeers, numberOfEphemeralPeers)

	// Expect DeletePeers to be called for ephemeral peers (except the connected one)
	peersManager.EXPECT().
		DeletePeers(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), true).
		DoAndReturn(func(ctx context.Context, accountID string, peerIDs []string, userID string, checkConnected bool) ([]string, error) {
			for _, peerID := range peerIDs {
				delete(store.account.Peers, peerID)
			}
			return nil, nil
		}).
		AnyTimes()

	mgr := NewEphemeralManager(store, peersManager)
	mgr.loadEphemeralPeers(context.Background())
	mgr.OnPeerConnected(context.Background(), store.account.Peers["ephemeral_peer_0"])

	startTime = startTime.Add(ephemeral.EphemeralLifeTime + 1)
	mgr.cleanup(context.Background())

	expected := numberOfPeers + 1
	if len(store.account.Peers) != expected {
		t.Errorf("failed to cleanup ephemeral peers, expected: %d, result: %d", expected, len(store.account.Peers))
	}
}

func TestNewManagerPeerDisconnected(t *testing.T) {
	t.Cleanup(func() {
		timeNow = time.Now
	})
	startTime := time.Now()
	timeNow = func() time.Time {
		return startTime
	}

	store := &MockStore{}
	ctrl := gomock.NewController(t)
	peersManager := peers.NewMockManager(ctrl)

	numberOfPeers := 5
	numberOfEphemeralPeers := 3
	seedPeers(store, numberOfPeers, numberOfEphemeralPeers)

	// Expect DeletePeers to be called for the one disconnected peer
	peersManager.EXPECT().
		DeletePeers(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), true).
		DoAndReturn(func(ctx context.Context, accountID string, peerIDs []string, userID string, checkConnected bool) ([]string, error) {
			for _, peerID := range peerIDs {
				delete(store.account.Peers, peerID)
			}
			return nil, nil
		}).
		AnyTimes()

	mgr := NewEphemeralManager(store, peersManager)
	mgr.loadEphemeralPeers(context.Background())
	for _, v := range store.account.Peers {
		mgr.OnPeerConnected(context.Background(), v)

	}
	mgr.OnPeerDisconnected(context.Background(), store.account.Peers["ephemeral_peer_0"])

	startTime = startTime.Add(ephemeral.EphemeralLifeTime + 1)
	mgr.cleanup(context.Background())

	expected := numberOfPeers + numberOfEphemeralPeers - 1
	if len(store.account.Peers) != expected {
		t.Errorf("failed to cleanup ephemeral peers, expected: %d, result: %d", expected, len(store.account.Peers))
	}
}

func TestCleanupSchedulingBehaviorIsBatched(t *testing.T) {
	const (
		ephemeralPeers    = 10
		testLifeTime      = 1 * time.Second
		testCleanupWindow = 100 * time.Millisecond
	)

	t.Cleanup(func() {
		timeNow = time.Now
	})
	startTime := time.Now()
	timeNow = func() time.Time {
		return startTime
	}

	mockStore := &MockStore{}
	account := newAccountWithId(context.Background(), "account", "", "", false)
	mockStore.account = account

	wg := &sync.WaitGroup{}
	wg.Add(ephemeralPeers)
	mockAM := &MockAccountManager{
		store: mockStore,
		wg:    wg,
	}

	ctrl := gomock.NewController(t)
	peersManager := peers.NewMockManager(ctrl)

	// Set up expectation that DeletePeers will be called once with all peer IDs
	peersManager.EXPECT().
		DeletePeers(gomock.Any(), account.Id, gomock.Any(), gomock.Any(), true).
		DoAndReturn(func(ctx context.Context, accountID string, peerIDs []string, userID string, checkConnected bool) ([]string, error) {
			// Simulate the actual deletion behavior
			for _, peerID := range peerIDs {
				err := mockAM.DeletePeer(ctx, accountID, peerID, userID)
				if err != nil {
					return nil, err
				}
			}
			mockAM.BufferUpdateAccountPeers(ctx, accountID, types.UpdateReason{})
			return nil, nil
		}).
		Times(1)

	mgr := NewEphemeralManager(mockStore, peersManager)
	mgr.lifeTime = testLifeTime
	mgr.cleanupWindow = testCleanupWindow

	// Add peers and disconnect them at slightly different times (within cleanup window)
	for i := range ephemeralPeers {
		p := &nbpeer.Peer{ID: fmt.Sprintf("peer-%d", i), AccountID: account.Id, Ephemeral: true}
		mockStore.account.Peers[p.ID] = p
		mgr.OnPeerDisconnected(context.Background(), p)
		startTime = startTime.Add(testCleanupWindow / (ephemeralPeers * 2))
	}

	// Advance time past the lifetime to trigger cleanup
	startTime = startTime.Add(testLifeTime + testCleanupWindow)

	// Wait for all deletions to complete
	wg.Wait()

	assert.Len(t, mockStore.account.Peers, 0, "all ephemeral peers should be cleaned up after the lifetime")
	assert.Equal(t, 1, mockAM.GetBufferUpdateCalls(account.Id), "buffer update should be called once")
	assert.Equal(t, ephemeralPeers, mockAM.GetDeletePeerCalls(), "should have deleted all peers")
}

// TestCleanupRequeuesVetoedPeers covers a peer whose deletion is vetoed (the
// store still reports it connected, or it was seen too recently): it must be
// scheduled for another attempt rather than dropped from the list, or it is
// never collected once the veto clears.
func TestCleanupRequeuesVetoedPeers(t *testing.T) {
	t.Cleanup(func() {
		timeNow = time.Now
	})
	startTime := time.Now()
	timeNow = func() time.Time {
		return startTime
	}

	mockStore := &MockStore{}
	seedPeers(mockStore, 0, 1)
	ctrl := gomock.NewController(t)
	peersManager := peers.NewMockManager(ctrl)

	// The first attempt vetoes the peer, the second deletes it.
	first := peersManager.EXPECT().
		DeletePeers(gomock.Any(), gomock.Any(), []string{"ephemeral_peer_0"}, gomock.Any(), true).
		Return([]string{"ephemeral_peer_0"}, nil)
	peersManager.EXPECT().
		DeletePeers(gomock.Any(), gomock.Any(), []string{"ephemeral_peer_0"}, gomock.Any(), true).
		After(first).
		DoAndReturn(func(_ context.Context, _ string, peerIDs []string, _ string, _ bool) ([]string, error) {
			for _, peerID := range peerIDs {
				delete(mockStore.account.Peers, peerID)
			}
			return nil, nil
		})

	mgr := NewEphemeralManager(mockStore, peersManager)
	mgr.loadEphemeralPeers(context.Background())

	startTime = startTime.Add(ephemeral.EphemeralLifeTime + time.Second)
	mgr.cleanup(context.Background())
	assert.Len(t, mockStore.account.Peers, 1, "vetoed peer must not be deleted yet")

	startTime = startTime.Add(ephemeral.EphemeralLifeTime + time.Second)
	mgr.cleanup(context.Background())
	assert.Len(t, mockStore.account.Peers, 0, "vetoed peer should be retried and deleted once the veto clears")
}

// TestCleanupRequeuesFailedDeletes covers a peer whose deletion attempt errors
// (DeletePeers reports it as skipped alongside the aggregate error): it must be
// scheduled for another attempt rather than dropped from the list, or a
// transient store failure leaks it forever.
func TestCleanupRequeuesFailedDeletes(t *testing.T) {
	t.Cleanup(func() {
		timeNow = time.Now
	})
	startTime := time.Now()
	timeNow = func() time.Time {
		return startTime
	}

	mockStore := &MockStore{}
	seedPeers(mockStore, 0, 1)
	ctrl := gomock.NewController(t)
	peersManager := peers.NewMockManager(ctrl)

	// The first attempt fails, the second deletes the peer.
	first := peersManager.EXPECT().
		DeletePeers(gomock.Any(), gomock.Any(), []string{"ephemeral_peer_0"}, gomock.Any(), true).
		Return([]string{"ephemeral_peer_0"}, errors.New("transient store failure"))
	peersManager.EXPECT().
		DeletePeers(gomock.Any(), gomock.Any(), []string{"ephemeral_peer_0"}, gomock.Any(), true).
		After(first).
		DoAndReturn(func(_ context.Context, _ string, peerIDs []string, _ string, _ bool) ([]string, error) {
			for _, peerID := range peerIDs {
				delete(mockStore.account.Peers, peerID)
			}
			return nil, nil
		})

	mgr := NewEphemeralManager(mockStore, peersManager)
	mgr.loadEphemeralPeers(context.Background())

	startTime = startTime.Add(ephemeral.EphemeralLifeTime + time.Second)
	mgr.cleanup(context.Background())
	assert.Len(t, mockStore.account.Peers, 1, "peer whose deletion failed must still exist")

	startTime = startTime.Add(ephemeral.EphemeralLifeTime + time.Second)
	mgr.cleanup(context.Background())
	assert.Len(t, mockStore.account.Peers, 0, "peer whose deletion failed should be retried and deleted")
}

func seedPeers(store *MockStore, numberOfPeers int, numberOfEphemeralPeers int) {
	store.account = newAccountWithId(context.Background(), "my account", "", "", false)

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

// newAccountWithId creates a new Account with a default SetupKey (doesn't store in a Store) and provided id
func newAccountWithId(ctx context.Context, accountID, userID, domain string, disableDefaultPolicy bool) *types.Account {
	log.WithContext(ctx).Debugf("creating new account")

	network := types.NewNetwork()
	peers := make(map[string]*nbpeer.Peer)
	users := make(map[string]*types.User)
	routes := make(map[route.ID]*route.Route)
	setupKeys := map[string]*types.SetupKey{}
	nameServersGroups := make(map[string]*nbdns.NameServerGroup)

	owner := types.NewOwnerUser(userID, "", "")
	owner.AccountID = accountID
	users[userID] = owner

	dnsSettings := types.DNSSettings{
		DisabledManagementGroups: make([]string, 0),
	}
	log.WithContext(ctx).Debugf("created new account %s", accountID)

	acc := &types.Account{
		Id:               accountID,
		CreatedAt:        time.Now().UTC(),
		SetupKeys:        setupKeys,
		Network:          network,
		Peers:            peers,
		Users:            users,
		CreatedBy:        userID,
		Domain:           domain,
		Routes:           routes,
		NameServerGroups: nameServersGroups,
		DNSSettings:      dnsSettings,
		Settings: &types.Settings{
			PeerLoginExpirationEnabled: true,
			PeerLoginExpiration:        types.DefaultPeerLoginExpiration,
			GroupsPropagationEnabled:   true,
			RegularUsersViewBlocked:    true,

			PeerInactivityExpirationEnabled: false,
			PeerInactivityExpiration:        types.DefaultPeerInactivityExpiration,
			RoutingPeerDNSResolutionEnabled: true,
		},
		Onboarding: types.AccountOnboarding{
			OnboardingFlowPending: true,
			SignupFormPending:     true,
		},
	}

	if err := acc.AddAllGroup(disableDefaultPolicy); err != nil {
		log.WithContext(ctx).Errorf("error adding all group to account %s: %v", acc.Id, err)
	}
	return acc
}
