package inactivity

import (
	"context"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"

	"github.com/netbirdio/netbird/client/internal/lazyconn"
	"github.com/netbirdio/netbird/monotime"
)

type mockWgInterface struct {
	lastActivities map[string]monotime.Time
}

func (m *mockWgInterface) LastActivities() map[string]monotime.Time {
	return m.lastActivities
}

func TestPeerTriggersInactivity(t *testing.T) {
	peerID := "peer1"

	wgMock := &mockWgInterface{
		lastActivities: map[string]monotime.Time{
			peerID: monotime.Time(int64(monotime.Now()) - int64(20*time.Minute)),
		},
	}

	fakeTick := make(chan time.Time, 1)
	newTicker = func(d time.Duration) Ticker {
		return &fakeTickerMock{CChan: fakeTick}
	}

	peerLog := log.WithField("peer", peerID)
	peerCfg := &lazyconn.PeerConfig{
		PublicKey: peerID,
		Log:       peerLog,
	}

	manager := NewManager(wgMock, nil)
	manager.AddPeer(peerCfg)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start the manager in a goroutine
	go manager.Start(ctx)

	// Send a tick to simulate time passage
	fakeTick <- time.Now()

	// Check if peer appears on inactivePeersChan
	select {
	case inactivePeers := <-manager.inactivePeersChan:
		assert.Contains(t, inactivePeers, peerID, "expected peer to be marked inactive")
	case <-time.After(1 * time.Second):
		t.Fatal("expected inactivity event, but none received")
	}
}

func TestPeerTriggersActivity(t *testing.T) {
	peerID := "peer1"

	wgMock := &mockWgInterface{
		lastActivities: map[string]monotime.Time{
			peerID: monotime.Time(int64(monotime.Now()) - int64(5*time.Minute)),
		},
	}

	fakeTick := make(chan time.Time, 1)
	newTicker = func(d time.Duration) Ticker {
		return &fakeTickerMock{CChan: fakeTick}
	}

	peerLog := log.WithField("peer", peerID)
	peerCfg := &lazyconn.PeerConfig{
		PublicKey: peerID,
		Log:       peerLog,
	}

	manager := NewManager(wgMock, nil)
	manager.AddPeer(peerCfg)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start the manager in a goroutine
	go manager.Start(ctx)

	// Send a tick to simulate time passage
	fakeTick <- time.Now()

	// Check if peer appears on inactivePeersChan
	select {
	case <-manager.inactivePeersChan:
		t.Fatal("expected inactive peer to be marked inactive")
	case <-time.After(1 * time.Second):
		// No inactivity event should be received
	}
}

// fakeTickerMock implements Ticker interface for testing
type fakeTickerMock struct {
	CChan chan time.Time
}

func (f *fakeTickerMock) C() <-chan time.Time {
	return f.CChan
}

func (f *fakeTickerMock) Stop() {}

// --- Phase 2 (#5989) two-timer tests ---

// makePeerCfg is a test helper for building a minimal PeerConfig with logger.
func makePeerCfg(peerID string) *lazyconn.PeerConfig {
	return &lazyconn.PeerConfig{
		PublicKey: peerID,
		Log:       log.WithField("peer", peerID),
	}
}

// pastActivity returns a monotime.Time corresponding to (now - d).
func pastActivity(d time.Duration) monotime.Time {
	return monotime.Time(int64(monotime.Now()) - int64(d))
}

func TestTwoTimers_OnlyICEFires(t *testing.T) {
	peerID := "peer1"

	// Peer idle for 6 minutes: above iceTimeout (5m), below relayTimeout (24h).
	wgMock := &mockWgInterface{
		lastActivities: map[string]monotime.Time{
			peerID: pastActivity(6 * time.Minute),
		},
	}

	fakeTick := make(chan time.Time, 1)
	newTicker = func(d time.Duration) Ticker {
		return &fakeTickerMock{CChan: fakeTick}
	}

	manager := NewManagerWithTwoTimers(wgMock, 5*time.Minute, 24*time.Hour)
	manager.AddPeer(makePeerCfg(peerID))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go manager.Start(ctx)

	fakeTick <- time.Now()

	select {
	case peers := <-manager.ICEInactiveChan():
		assert.Contains(t, peers, peerID, "expected peerID on ICE channel")
	case <-time.After(1 * time.Second):
		t.Fatal("expected ICE-inactive event, none received")
	}

	// Relay channel must NOT fire.
	select {
	case <-manager.RelayInactiveChan():
		t.Fatal("Relay channel should not fire when only iceTimeout exceeded")
	case <-time.After(200 * time.Millisecond):
		// expected
	}
}

func TestTwoTimers_BothFire(t *testing.T) {
	peerID := "peer1"

	// Peer idle for 25h: above both iceTimeout (5m) and relayTimeout (24h).
	wgMock := &mockWgInterface{
		lastActivities: map[string]monotime.Time{
			peerID: pastActivity(25 * time.Hour),
		},
	}

	fakeTick := make(chan time.Time, 1)
	newTicker = func(d time.Duration) Ticker {
		return &fakeTickerMock{CChan: fakeTick}
	}

	manager := NewManagerWithTwoTimers(wgMock, 5*time.Minute, 24*time.Hour)
	manager.AddPeer(makePeerCfg(peerID))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go manager.Start(ctx)

	fakeTick <- time.Now()

	gotICE := false
	gotRelay := false
	deadline := time.After(1 * time.Second)
	for !gotICE || !gotRelay {
		select {
		case peers := <-manager.ICEInactiveChan():
			if _, ok := peers[peerID]; ok {
				gotICE = true
			}
		case peers := <-manager.RelayInactiveChan():
			if _, ok := peers[peerID]; ok {
				gotRelay = true
			}
		case <-deadline:
			t.Fatalf("timeout waiting for both channels (gotICE=%v, gotRelay=%v)", gotICE, gotRelay)
		}
	}
}

func TestTwoTimers_ICEDisabled(t *testing.T) {
	peerID := "peer1"

	// iceTimeout=0 (disabled) + relayTimeout=10m, peer idle 11m -> only relay fires.
	wgMock := &mockWgInterface{
		lastActivities: map[string]monotime.Time{
			peerID: pastActivity(11 * time.Minute),
		},
	}

	fakeTick := make(chan time.Time, 1)
	newTicker = func(d time.Duration) Ticker {
		return &fakeTickerMock{CChan: fakeTick}
	}

	manager := NewManagerWithTwoTimers(wgMock, 0, 10*time.Minute)
	manager.AddPeer(makePeerCfg(peerID))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go manager.Start(ctx)

	fakeTick <- time.Now()

	select {
	case peers := <-manager.RelayInactiveChan():
		assert.Contains(t, peers, peerID)
	case <-time.After(1 * time.Second):
		t.Fatal("relay channel should fire when relayTimeout exceeded")
	}

	// ICE channel must never fire because iceTimeout=0.
	select {
	case <-manager.ICEInactiveChan():
		t.Fatal("ICE channel should NEVER fire when iceTimeout=0")
	case <-time.After(200 * time.Millisecond):
		// expected
	}
}

func TestTwoTimers_RelayDisabled(t *testing.T) {
	peerID := "peer1"

	// iceTimeout=5m + relayTimeout=0, peer idle 6m -> only ICE fires.
	wgMock := &mockWgInterface{
		lastActivities: map[string]monotime.Time{
			peerID: pastActivity(6 * time.Minute),
		},
	}

	fakeTick := make(chan time.Time, 1)
	newTicker = func(d time.Duration) Ticker {
		return &fakeTickerMock{CChan: fakeTick}
	}

	manager := NewManagerWithTwoTimers(wgMock, 5*time.Minute, 0)
	manager.AddPeer(makePeerCfg(peerID))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go manager.Start(ctx)

	fakeTick <- time.Now()

	select {
	case peers := <-manager.ICEInactiveChan():
		assert.Contains(t, peers, peerID)
	case <-time.After(1 * time.Second):
		t.Fatal("ICE channel should fire when iceTimeout exceeded")
	}

	// Relay channel must never fire because relayTimeout=0.
	select {
	case <-manager.RelayInactiveChan():
		t.Fatal("Relay channel should NEVER fire when relayTimeout=0")
	case <-time.After(200 * time.Millisecond):
		// expected
	}
}

func TestTwoTimers_BothDisabled(t *testing.T) {
	peerID := "peer1"

	wgMock := &mockWgInterface{
		lastActivities: map[string]monotime.Time{
			peerID: pastActivity(99 * time.Hour),
		},
	}

	fakeTick := make(chan time.Time, 1)
	newTicker = func(d time.Duration) Ticker {
		return &fakeTickerMock{CChan: fakeTick}
	}

	manager := NewManagerWithTwoTimers(wgMock, 0, 0)
	manager.AddPeer(makePeerCfg(peerID))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go manager.Start(ctx)

	fakeTick <- time.Now()

	// Neither channel should fire.
	select {
	case <-manager.ICEInactiveChan():
		t.Fatal("ICE channel must not fire when both disabled")
	case <-manager.RelayInactiveChan():
		t.Fatal("Relay channel must not fire when both disabled")
	case <-time.After(300 * time.Millisecond):
		// expected
	}
}

// TestPhase1_LazyEquivalence verifies that the legacy NewManager constructor
// behaves identically to the Phase-1 single-timer code: peers cross the
// (single) inactivityThreshold and appear on InactivePeersChan, ICE
// channel never fires.
func TestPhase1_LazyEquivalence(t *testing.T) {
	peerID := "peer1"

	wgMock := &mockWgInterface{
		lastActivities: map[string]monotime.Time{
			peerID: pastActivity(20 * time.Minute),
		},
	}

	fakeTick := make(chan time.Time, 1)
	newTicker = func(d time.Duration) Ticker {
		return &fakeTickerMock{CChan: fakeTick}
	}

	// Phase-1 entry point with default threshold (15m).
	manager := NewManager(wgMock, nil)
	manager.AddPeer(makePeerCfg(peerID))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go manager.Start(ctx)

	fakeTick <- time.Now()

	// InactivePeersChan (Phase-1 alias of RelayInactiveChan) must fire.
	select {
	case peers := <-manager.InactivePeersChan():
		assert.Contains(t, peers, peerID)
	case <-time.After(1 * time.Second):
		t.Fatal("Phase-1 InactivePeersChan must fire (= RelayInactiveChan in Phase 2)")
	}

	// ICE channel must NEVER fire from Phase-1 entry point (iceTimeout=0).
	select {
	case <-manager.ICEInactiveChan():
		t.Fatal("ICE channel must not fire in Phase-1 NewManager mode")
	case <-time.After(200 * time.Millisecond):
		// expected
	}
}
