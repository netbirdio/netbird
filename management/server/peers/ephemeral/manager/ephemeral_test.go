package manager

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"

	nbdns "github.com/netbirdio/netbird/dns"
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

func (a *MockAccountManager) BufferUpdateAccountPeers(ctx context.Context, accountID string) {
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
	am := MockAccountManager{
		store: store,
	}

	numberOfPeers := 5
	numberOfEphemeralPeers := 3
	seedPeers(store, numberOfPeers, numberOfEphemeralPeers)

	mgr := NewEphemeralManager(store, &am)
	mgr.loadEphemeralPeers(context.Background())
	startTime = startTime.Add(EphemeralLifeTime + 1)
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
	am := MockAccountManager{
		store: store,
	}

	numberOfPeers := 5
	numberOfEphemeralPeers := 3
	seedPeers(store, numberOfPeers, numberOfEphemeralPeers)

	mgr := NewEphemeralManager(store, &am)
	mgr.loadEphemeralPeers(context.Background())
	mgr.OnPeerConnected(context.Background(), store.account.Peers["ephemeral_peer_0"])

	startTime = startTime.Add(EphemeralLifeTime + 1)
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
	am := MockAccountManager{
		store: store,
	}

	numberOfPeers := 5
	numberOfEphemeralPeers := 3
	seedPeers(store, numberOfPeers, numberOfEphemeralPeers)

	mgr := NewEphemeralManager(store, &am)
	mgr.loadEphemeralPeers(context.Background())
	for _, v := range store.account.Peers {
		mgr.OnPeerConnected(context.Background(), v)

	}
	mgr.OnPeerDisconnected(context.Background(), store.account.Peers["ephemeral_peer_0"])

	startTime = startTime.Add(EphemeralLifeTime + 1)
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
	mockStore := &MockStore{}
	mockAM := &MockAccountManager{
		store: mockStore,
	}
	mockAM.wg = &sync.WaitGroup{}
	mockAM.wg.Add(ephemeralPeers)
	mgr := NewEphemeralManager(mockStore, mockAM)
	mgr.lifeTime = testLifeTime
	mgr.cleanupWindow = testCleanupWindow

	account := newAccountWithId(context.Background(), "account", "", "", false)
	mockStore.account = account
	for i := range ephemeralPeers {
		p := &nbpeer.Peer{ID: fmt.Sprintf("peer-%d", i), AccountID: account.Id, Ephemeral: true}
		mockStore.account.Peers[p.ID] = p
		time.Sleep(testCleanupWindow / ephemeralPeers)
		mgr.OnPeerDisconnected(context.Background(), p)
	}
	mockAM.wg.Wait()
	assert.Len(t, mockStore.account.Peers, 0, "all ephemeral peers should be cleaned up after the lifetime")
	assert.Equal(t, 1, mockAM.GetBufferUpdateCalls(account.Id), "buffer update should be called once")
	assert.Equal(t, ephemeralPeers, mockAM.GetDeletePeerCalls(), "should have deleted all peers")
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

	owner := types.NewOwnerUser(userID)
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
