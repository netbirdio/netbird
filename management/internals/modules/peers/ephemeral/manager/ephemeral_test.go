package manager

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	nbdns "github.com/netbirdio/netbird/dns"
	"github.com/netbirdio/netbird/management/internals/modules/peers"
	"github.com/netbirdio/netbird/management/internals/modules/peers/ephemeral"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/route"
)

// MockStore is a thin in-memory stand-in that implements only the two
// methods the EphemeralManager uses. It honors the account / ephemeral
// / connected / lastSeen attributes of each peer so the cleanup logic
// can be exercised end-to-end without bringing up sqlite or Postgres.
type MockStore struct {
	store.Store
	mu      sync.Mutex
	account *types.Account
}

func (s *MockStore) GetStaleEphemeralPeerIDsForAccount(_ context.Context, accountID string, olderThan time.Time) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.account == nil || s.account.Id != accountID {
		return nil, nil
	}
	var ids []string
	for _, p := range s.account.Peers {
		if !p.Ephemeral {
			continue
		}
		if p.Status == nil || p.Status.Connected {
			continue
		}
		if p.Status.LastSeen.Before(olderThan) {
			ids = append(ids, p.ID)
		}
	}
	return ids, nil
}

func (s *MockStore) GetEphemeralAccountsLastDisconnect(_ context.Context) (map[string]time.Time, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string]time.Time{}
	if s.account == nil {
		return out, nil
	}
	var latest time.Time
	hasAny := false
	for _, p := range s.account.Peers {
		if !p.Ephemeral || p.Status == nil || p.Status.Connected {
			continue
		}
		if !hasAny || p.Status.LastSeen.After(latest) {
			latest = p.Status.LastSeen
			hasAny = true
		}
	}
	if hasAny {
		out[s.account.Id] = latest
	}
	return out, nil
}

// withFakeClock pins timeNow to a settable value for the duration of t.
// Returns a getter and a setter so subtests can advance virtual time.
func withFakeClock(t *testing.T, start time.Time) (get func() time.Time, set func(time.Time)) {
	t.Helper()
	var mu sync.Mutex
	now := start
	timeNow = func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return now
	}
	t.Cleanup(func() { timeNow = time.Now })

	return func() time.Time {
			mu.Lock()
			defer mu.Unlock()
			return now
		}, func(v time.Time) {
			mu.Lock()
			defer mu.Unlock()
			now = v
		}
}

// newManagerForTest builds a manager with short timers and no random
// initial-load delay so tests run instantly.
func newManagerForTest(t *testing.T, st store.Store, peersMgr peers.Manager) *EphemeralManager {
	t.Helper()
	mgr := NewEphemeralManager(st, peersMgr)
	mgr.lifeTime = 100 * time.Millisecond
	mgr.cleanupWindow = 10 * time.Millisecond
	mgr.initialLoadDelay = func() time.Duration { return 0 }
	t.Cleanup(mgr.Stop)
	return mgr
}

// TestOnPeerDisconnected_RegistersAndSweeps drives the OnPeerDisconnected
// path with a fake clock: a single ephemeral peer disconnects, we
// advance past the staleness window, and the sweep deletes it.
func TestOnPeerDisconnected_RegistersAndSweeps(t *testing.T) {
	mockStore := &MockStore{account: newAccountWithId(context.Background(), "acc-1", "", "", false)}

	getNow, setNow := withFakeClock(t, time.Now())

	ctrl := gomock.NewController(t)
	peersMgr := peers.NewMockManager(ctrl)

	var deletedMu sync.Mutex
	var deleted []string
	var deleteCalls atomic.Int32
	peersMgr.EXPECT().
		DeletePeers(gomock.Any(), "acc-1", gomock.Any(), gomock.Any(), true).
		DoAndReturn(func(_ context.Context, accountID string, peerIDs []string, _ string, _ bool) error {
			deleteCalls.Add(1)
			mockStore.mu.Lock()
			for _, id := range peerIDs {
				delete(mockStore.account.Peers, id)
			}
			mockStore.mu.Unlock()
			deletedMu.Lock()
			deleted = append(deleted, peerIDs...)
			deletedMu.Unlock()
			return nil
		}).AnyTimes()

	mgr := newManagerForTest(t, mockStore, peersMgr)

	// One ephemeral peer that disconnected "now".
	now := getNow()
	p := &nbpeer.Peer{
		ID:        "p1",
		AccountID: "acc-1",
		Ephemeral: true,
		Status:    &nbpeer.PeerStatus{Connected: false, LastSeen: now},
	}
	mockStore.account.Peers[p.ID] = p
	mgr.OnPeerDisconnected(context.Background(), p)

	// Advance past lifeTime + cleanupWindow so the timer-driven sweep fires.
	setNow(now.Add(mgr.lifeTime + 5*mgr.cleanupWindow))
	require.Eventually(t, func() bool { return deleteCalls.Load() >= 1 }, 2*time.Second, 5*time.Millisecond,
		"sweep should fire and delete the stale peer")

	deletedMu.Lock()
	deletedCopy := append([]string(nil), deleted...)
	deletedMu.Unlock()
	require.Equal(t, []string{"p1"}, deletedCopy, "only the one ephemeral peer should be deleted")
}

// TestOnPeerDisconnected_NonEphemeralIgnored: a non-ephemeral disconnect
// must not register the account or arm any timer.
func TestOnPeerDisconnected_NonEphemeralIgnored(t *testing.T) {
	mockStore := &MockStore{account: newAccountWithId(context.Background(), "acc-1", "", "", false)}
	withFakeClock(t, time.Now())

	ctrl := gomock.NewController(t)
	peersMgr := peers.NewMockManager(ctrl)
	// No DeletePeers expectation — must not be called.

	mgr := newManagerForTest(t, mockStore, peersMgr)
	mgr.OnPeerDisconnected(context.Background(), &nbpeer.Peer{
		ID:        "p1",
		AccountID: "acc-1",
		Ephemeral: false,
		Status:    &nbpeer.PeerStatus{Connected: false, LastSeen: timeNow()},
	})

	mgr.accountsLock.Lock()
	require.Empty(t, mgr.accounts, "non-ephemeral disconnect must not register an account")
	mgr.accountsLock.Unlock()
}

// TestSweep_DropsAccountWhenIdle: after a sweep cleans the stale peers,
// if no more disconnects have arrived the account must be dropped from
// the in-memory tracker.
func TestSweep_DropsAccountWhenIdle(t *testing.T) {
	mockStore := &MockStore{account: newAccountWithId(context.Background(), "acc-1", "", "", false)}
	getNow, setNow := withFakeClock(t, time.Now())

	ctrl := gomock.NewController(t)
	peersMgr := peers.NewMockManager(ctrl)
	peersMgr.EXPECT().
		DeletePeers(gomock.Any(), "acc-1", gomock.Any(), gomock.Any(), true).
		DoAndReturn(func(_ context.Context, _ string, peerIDs []string, _ string, _ bool) error {
			mockStore.mu.Lock()
			for _, id := range peerIDs {
				delete(mockStore.account.Peers, id)
			}
			mockStore.mu.Unlock()
			return nil
		}).AnyTimes()

	mgr := newManagerForTest(t, mockStore, peersMgr)

	now := getNow()
	p := &nbpeer.Peer{ID: "p1", AccountID: "acc-1", Ephemeral: true,
		Status: &nbpeer.PeerStatus{Connected: false, LastSeen: now}}
	mockStore.account.Peers[p.ID] = p
	mgr.OnPeerDisconnected(context.Background(), p)

	setNow(now.Add(mgr.lifeTime + 5*mgr.cleanupWindow))

	require.Eventually(t, func() bool {
		mgr.accountsLock.Lock()
		defer mgr.accountsLock.Unlock()
		return len(mgr.accounts) == 0
	}, 2*time.Second, 5*time.Millisecond, "account should be dropped after sweep with no new disconnects")
}

// TestSweep_ReArmsWhenNewDisconnectArrived: simulate the race where a
// fresh disconnect arrives just before the sweep fires. The sweep must
// observe the updated lastDisc and re-arm rather than drop.
func TestSweep_ReArmsWhenNewDisconnectArrived(t *testing.T) {
	mockStore := &MockStore{account: newAccountWithId(context.Background(), "acc-1", "", "", false)}
	getNow, setNow := withFakeClock(t, time.Now())

	ctrl := gomock.NewController(t)
	peersMgr := peers.NewMockManager(ctrl)
	peersMgr.EXPECT().
		DeletePeers(gomock.Any(), "acc-1", gomock.Any(), gomock.Any(), true).
		DoAndReturn(func(_ context.Context, _ string, peerIDs []string, _ string, _ bool) error {
			mockStore.mu.Lock()
			for _, id := range peerIDs {
				delete(mockStore.account.Peers, id)
			}
			mockStore.mu.Unlock()
			return nil
		}).AnyTimes()

	mgr := newManagerForTest(t, mockStore, peersMgr)

	now := getNow()
	p1 := &nbpeer.Peer{ID: "p1", AccountID: "acc-1", Ephemeral: true,
		Status: &nbpeer.PeerStatus{Connected: false, LastSeen: now}}
	mockStore.account.Peers[p1.ID] = p1
	mgr.OnPeerDisconnected(context.Background(), p1)

	// Advance most of the way toward the first sweep, then introduce
	// a fresh disconnect that resets lastDisc.
	setNow(now.Add(mgr.lifeTime - 10*time.Millisecond))
	p2 := &nbpeer.Peer{ID: "p2", AccountID: "acc-1", Ephemeral: true,
		Status: &nbpeer.PeerStatus{Connected: false, LastSeen: getNow()}}
	mockStore.account.Peers[p2.ID] = p2
	mgr.OnPeerDisconnected(context.Background(), p2)

	// Push past p1's staleness so the first sweep runs and cleans p1
	// but observes p2 already on the account entry. It must re-arm.
	setNow(now.Add(mgr.lifeTime + 5*mgr.cleanupWindow))

	require.Eventually(t, func() bool {
		mockStore.mu.Lock()
		defer mockStore.mu.Unlock()
		_, gone := mockStore.account.Peers["p1"]
		return !gone
	}, 2*time.Second, 5*time.Millisecond, "p1 should be cleaned at the first sweep")

	// The account should still be tracked because p2 is younger than lifeTime
	// from the sweep's vantage point at this moment.
	mgr.accountsLock.Lock()
	_, stillTracked := mgr.accounts["acc-1"]
	mgr.accountsLock.Unlock()
	require.True(t, stillTracked, "account should remain tracked because p2's disconnect kept it active")

	// Push past p2's staleness; second sweep cleans p2 and drops the account.
	setNow(getNow().Add(mgr.lifeTime + 5*mgr.cleanupWindow))
	require.Eventually(t, func() bool {
		mgr.accountsLock.Lock()
		defer mgr.accountsLock.Unlock()
		return len(mgr.accounts) == 0
	}, 2*time.Second, 5*time.Millisecond, "account should drop after the final sweep")
}

// TestSweep_BatchesPeersPerAccount: many ephemeral peers disconnect on
// the same account; a single sweep must delete them all in one
// DeletePeers call.
func TestSweep_BatchesPeersPerAccount(t *testing.T) {
	const ephemeralPeers = 8

	mockStore := &MockStore{account: newAccountWithId(context.Background(), "acc-1", "", "", false)}
	getNow, setNow := withFakeClock(t, time.Now())

	ctrl := gomock.NewController(t)
	peersMgr := peers.NewMockManager(ctrl)

	deleteBatches := make(chan []string, 4)
	peersMgr.EXPECT().
		DeletePeers(gomock.Any(), "acc-1", gomock.Any(), gomock.Any(), true).
		DoAndReturn(func(_ context.Context, _ string, peerIDs []string, _ string, _ bool) error {
			cp := append([]string(nil), peerIDs...)
			mockStore.mu.Lock()
			for _, id := range peerIDs {
				delete(mockStore.account.Peers, id)
			}
			mockStore.mu.Unlock()
			deleteBatches <- cp
			return nil
		}).Times(1)

	mgr := newManagerForTest(t, mockStore, peersMgr)

	now := getNow()
	for i := 0; i < ephemeralPeers; i++ {
		id := fmt.Sprintf("p-%d", i)
		// Stagger by a fraction of cleanupWindow so they all fall on
		// the same sweep tick.
		when := now.Add(time.Duration(i) * time.Millisecond)
		p := &nbpeer.Peer{ID: id, AccountID: "acc-1", Ephemeral: true,
			Status: &nbpeer.PeerStatus{Connected: false, LastSeen: when}}
		mockStore.account.Peers[id] = p
		mgr.OnPeerDisconnected(context.Background(), p)
	}

	setNow(now.Add(mgr.lifeTime + 5*mgr.cleanupWindow))

	select {
	case batch := <-deleteBatches:
		require.Len(t, batch, ephemeralPeers, "all peers should be deleted in a single batch")
	case <-time.After(2 * time.Second):
		t.Fatal("expected one batched DeletePeers call")
	}
}

// TestLoadInitialAccounts_SeedsFromStore exercises the post-restart
// catch-up path: pre-populate the store, point the manager at it, and
// confirm both already-stale and not-yet-stale peers get cleaned at
// their proper times.
func TestLoadInitialAccounts_SeedsFromStore(t *testing.T) {
	mockStore := &MockStore{account: newAccountWithId(context.Background(), "acc-1", "", "", false)}
	getNow, setNow := withFakeClock(t, time.Now())

	now := getNow()
	// p-stale: already past the staleness window when load runs.
	mockStore.account.Peers["p-stale"] = &nbpeer.Peer{
		ID: "p-stale", AccountID: "acc-1", Ephemeral: true,
		Status: &nbpeer.PeerStatus{Connected: false, LastSeen: now.Add(-time.Hour)},
	}
	// p-fresh: disconnected but not yet stale.
	mockStore.account.Peers["p-fresh"] = &nbpeer.Peer{
		ID: "p-fresh", AccountID: "acc-1", Ephemeral: true,
		Status: &nbpeer.PeerStatus{Connected: false, LastSeen: now},
	}

	ctrl := gomock.NewController(t)
	peersMgr := peers.NewMockManager(ctrl)
	peersMgr.EXPECT().
		DeletePeers(gomock.Any(), "acc-1", gomock.Any(), gomock.Any(), true).
		DoAndReturn(func(_ context.Context, _ string, peerIDs []string, _ string, _ bool) error {
			mockStore.mu.Lock()
			for _, id := range peerIDs {
				delete(mockStore.account.Peers, id)
			}
			mockStore.mu.Unlock()
			return nil
		}).AnyTimes()

	mgr := newManagerForTest(t, mockStore, peersMgr)
	// Drive loadInitialAccounts directly with the fake-clock-aware now.
	mgr.loadInitialAccounts(context.Background())

	// First sweep should fire shortly (cleanupWindow) for the stale peer.
	setNow(now.Add(5 * mgr.cleanupWindow))
	require.Eventually(t, func() bool {
		mockStore.mu.Lock()
		defer mockStore.mu.Unlock()
		_, gone := mockStore.account.Peers["p-stale"]
		return !gone
	}, 2*time.Second, 5*time.Millisecond, "p-stale should be deleted on the first sweep")

	// p-fresh is not yet stale; advance past its window.
	setNow(now.Add(mgr.lifeTime + 5*mgr.cleanupWindow))
	require.Eventually(t, func() bool {
		mockStore.mu.Lock()
		defer mockStore.mu.Unlock()
		_, gone := mockStore.account.Peers["p-fresh"]
		return !gone
	}, 2*time.Second, 5*time.Millisecond, "p-fresh should be deleted once it crosses the staleness window")
}

// TestStop_CancelsPendingWork verifies that Stop() cancels both the
// deferred initial load and per-account sweep timers and that
// subsequent OnPeerDisconnected calls are ignored.
func TestStop_CancelsPendingWork(t *testing.T) {
	mockStore := &MockStore{account: newAccountWithId(context.Background(), "acc-1", "", "", false)}
	withFakeClock(t, time.Now())

	ctrl := gomock.NewController(t)
	peersMgr := peers.NewMockManager(ctrl)
	// DeletePeers must NOT be called after Stop.

	mgr := NewEphemeralManager(mockStore, peersMgr)
	mgr.lifeTime = 100 * time.Millisecond
	mgr.cleanupWindow = 10 * time.Millisecond
	// Use a long delay so the initial-load timer is still pending.
	mgr.initialLoadDelay = func() time.Duration { return time.Hour }

	mgr.LoadInitialPeers(context.Background())
	mgr.OnPeerDisconnected(context.Background(), &nbpeer.Peer{
		ID: "p1", AccountID: "acc-1", Ephemeral: true,
		Status: &nbpeer.PeerStatus{Connected: false, LastSeen: timeNow()},
	})

	mgr.accountsLock.Lock()
	require.NotNil(t, mgr.initialLoadTimer, "initial-load timer should be armed")
	require.Len(t, mgr.accounts, 1, "account should be tracked after disconnect")
	mgr.accountsLock.Unlock()

	mgr.Stop()

	mgr.accountsLock.Lock()
	require.Empty(t, mgr.accounts, "Stop should clear tracked accounts")
	require.True(t, mgr.stopped, "stopped flag must be set")
	mgr.accountsLock.Unlock()

	// Post-stop disconnect must be ignored.
	mgr.OnPeerDisconnected(context.Background(), &nbpeer.Peer{
		ID: "p2", AccountID: "acc-1", Ephemeral: true,
		Status: &nbpeer.PeerStatus{Connected: false, LastSeen: timeNow()},
	})
	mgr.accountsLock.Lock()
	require.Empty(t, mgr.accounts, "disconnects after Stop must be ignored")
	mgr.accountsLock.Unlock()
}

// TestOnPeerConnected_IsNoop: the OnPeerConnected hook is preserved on
// the interface but does nothing in the per-account model — the sweep
// query filters connected peers at the DB level.
func TestOnPeerConnected_IsNoop(t *testing.T) {
	mockStore := &MockStore{account: newAccountWithId(context.Background(), "acc-1", "", "", false)}
	withFakeClock(t, time.Now())

	ctrl := gomock.NewController(t)
	peersMgr := peers.NewMockManager(ctrl)

	mgr := newManagerForTest(t, mockStore, peersMgr)
	mgr.OnPeerDisconnected(context.Background(), &nbpeer.Peer{
		ID: "p1", AccountID: "acc-1", Ephemeral: true,
		Status: &nbpeer.PeerStatus{Connected: false, LastSeen: timeNow()},
	})
	mgr.accountsLock.Lock()
	require.Len(t, mgr.accounts, 1, "disconnect should track the account")
	mgr.accountsLock.Unlock()

	mgr.OnPeerConnected(context.Background(), &nbpeer.Peer{ID: "p1", AccountID: "acc-1", Ephemeral: true})
	mgr.accountsLock.Lock()
	require.Len(t, mgr.accounts, 1, "OnPeerConnected must be a no-op")
	mgr.accountsLock.Unlock()
}

// TestSweep_StoreErrorReArms: if the stale-peer query fails, the
// account must remain tracked and a follow-up sweep gets scheduled.
func TestSweep_StoreErrorReArms(t *testing.T) {
	mockStore := &erroringStore{
		MockStore: MockStore{account: newAccountWithId(context.Background(), "acc-1", "", "", false)},
	}
	getNow, setNow := withFakeClock(t, time.Now())

	ctrl := gomock.NewController(t)
	peersMgr := peers.NewMockManager(ctrl)

	mgr := newManagerForTest(t, mockStore, peersMgr)

	p := &nbpeer.Peer{ID: "p1", AccountID: "acc-1", Ephemeral: true,
		Status: &nbpeer.PeerStatus{Connected: false, LastSeen: getNow()}}
	mockStore.account.Peers[p.ID] = p
	mgr.OnPeerDisconnected(context.Background(), p)

	mockStore.fail.Store(true)
	setNow(getNow().Add(mgr.lifeTime + 5*mgr.cleanupWindow))

	// Wait until the failing sweep has run at least once.
	require.Eventually(t, func() bool { return mockStore.failedCalls.Load() >= 1 },
		2*time.Second, 5*time.Millisecond, "expected at least one failing sweep")

	mgr.accountsLock.Lock()
	_, stillTracked := mgr.accounts["acc-1"]
	mgr.accountsLock.Unlock()
	require.True(t, stillTracked, "account must remain tracked after a sweep error")

	// Recover and ensure the rearmed sweep cleans up.
	peersMgr.EXPECT().
		DeletePeers(gomock.Any(), "acc-1", gomock.Any(), gomock.Any(), true).
		DoAndReturn(func(_ context.Context, _ string, peerIDs []string, _ string, _ bool) error {
			mockStore.mu.Lock()
			for _, id := range peerIDs {
				delete(mockStore.account.Peers, id)
			}
			mockStore.mu.Unlock()
			return nil
		}).AnyTimes()
	mockStore.fail.Store(false)

	require.Eventually(t, func() bool {
		mockStore.mu.Lock()
		defer mockStore.mu.Unlock()
		_, gone := mockStore.account.Peers["p1"]
		return !gone
	}, 2*time.Second, 5*time.Millisecond, "rearmed sweep should clean up after the store recovers")
}

// erroringStore is a MockStore that can be flipped into a failing mode
// to exercise the sweep's error-rearm path.
type erroringStore struct {
	MockStore
	fail        atomic.Bool
	failedCalls atomic.Int32
}

func (s *erroringStore) GetStaleEphemeralPeerIDsForAccount(ctx context.Context, accountID string, olderThan time.Time) ([]string, error) {
	if s.fail.Load() {
		s.failedCalls.Add(1)
		return nil, errors.New("synthetic store error")
	}
	return s.MockStore.GetStaleEphemeralPeerIDsForAccount(ctx, accountID, olderThan)
}

// TestDefaultInitialLoadDelay confirms the jitter falls inside the
// documented [8m, 10m) range — sanity check for the production timer.
func TestDefaultInitialLoadDelay(t *testing.T) {
	for i := 0; i < 1000; i++ {
		d := defaultInitialLoadDelay()
		assert.GreaterOrEqual(t, d, initialLoadMinDelay)
		assert.Less(t, d, initialLoadMaxDelay)
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

// silence the import "github.com/netbirdio/netbird/management/internals/modules/peers/ephemeral"
// (still needed indirectly for ephemeral.EphemeralLifeTime in production paths).
var _ = ephemeral.EphemeralLifeTime
