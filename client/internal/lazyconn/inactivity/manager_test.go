package inactivity

import (
	"context"
	"fmt"
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
	addAt(manager, peerCfg, wgMock.lastActivities[peerID])

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
	addAt(manager, peerCfg, wgMock.lastActivities[peerID])

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

// addAt adds the peer as if it had been added at the time of its last
// activity, so the idle time in the test is measured from that activity
// alone.
func addAt(m *Manager, peerCfg *lazyconn.PeerConfig, at monotime.Time) {
	m.now = func() monotime.Time { return at }
	m.AddPeer(peerCfg)
	m.now = monotime.Now
}

// fakeClock is a manual monotonic clock for the manager.
type fakeClock struct {
	t int64
}

func newFakeClock() *fakeClock {
	return &fakeClock{t: int64(monotime.Now())}
}

func (c *fakeClock) now() monotime.Time { return monotime.Time(c.t) }

func (c *fakeClock) advance(d time.Duration) { c.t += int64(d) }

func clockedManager(clock *fakeClock, lastActive monotime.Time) *Manager {
	wgMock := &mockWgInterface{lastActivities: map[string]monotime.Time{"peer1": lastActive}}
	manager := NewManager(wgMock, nil)
	manager.now = clock.now
	return manager
}

func addPeer1(m *Manager) {
	m.AddPeer(&lazyconn.PeerConfig{PublicKey: "peer1", Log: log.WithField("peer", "peer1")})
}

// The interface still reports the last traffic of the previous session when
// a link reopens. A check right after the open must not close the link, and
// the link closes once it is idle past the threshold since the open.
func TestFirstCheckAfterOpenKeepsLink(t *testing.T) {
	clock := newFakeClock()
	manager := clockedManager(clock, clock.now()-monotime.Time(time.Hour))

	addPeer1(manager)
	clock.advance(time.Minute)
	idle, err := manager.checkStats()
	assert.NoError(t, err)
	assert.NotContains(t, idle, "peer1", "check right after the open must not close the link")

	clock.advance(DefaultInactivityThreshold)
	idle, err = manager.checkStats()
	assert.NoError(t, err)
	assert.Contains(t, idle, "peer1", "link idle past the threshold since the open is reported")
}

// A close removes the peer, the reopen adds it again. The add time of the
// new session counts, not the one of the first.
func TestReaddedPeerGetsNewAddTime(t *testing.T) {
	clock := newFakeClock()
	manager := clockedManager(clock, clock.now()-monotime.Time(time.Hour))

	addPeer1(manager)
	clock.advance(DefaultInactivityThreshold + time.Minute)
	idle, err := manager.checkStats()
	assert.NoError(t, err)
	assert.Contains(t, idle, "peer1", "peer idle past the threshold after the add is reported")

	manager.RemovePeer("peer1")
	addPeer1(manager)
	clock.advance(time.Minute)
	idle, err = manager.checkStats()
	assert.NoError(t, err)
	assert.NotContains(t, idle, "peer1", "check right after the re-add must not close the link")
}

// Traffic after the add moves the idle start past the add time.
func TestActivityAfterAddCounts(t *testing.T) {
	clock := newFakeClock()
	addTime := clock.now()
	manager := clockedManager(clock, addTime+monotime.Time(20*time.Second))

	addPeer1(manager)
	clock.advance(25 * time.Second)
	idle, err := manager.checkStats()
	assert.NoError(t, err)
	assert.NotContains(t, idle, "peer1", "peer active 5 s ago must stay open")

	clock.advance(DefaultInactivityThreshold)
	idle, err = manager.checkStats()
	assert.NoError(t, err)
	assert.Contains(t, idle, "peer1", "peer idle past the threshold since its last traffic is reported")
}

// The engine adds and removes peers while the Start loop checks them. Run
// with -race: an unguarded peer map shows up as a data race or a concurrent
// map crash.
func TestConcurrentPeerChangesDuringCheck(t *testing.T) {
	wgMock := &mockWgInterface{lastActivities: map[string]monotime.Time{}}

	fakeTick := make(chan time.Time)
	newTicker = func(d time.Duration) Ticker {
		return &fakeTickerMock{CChan: fakeTick}
	}

	manager := NewManager(wgMock, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go manager.Start(ctx)

	done := make(chan struct{})
	go func() {
		defer close(done)
		peerLog := log.WithField("peer", "churn")
		for i := 0; i < 200; i++ {
			key := fmt.Sprintf("peer%d", i%10)
			manager.AddPeer(&lazyconn.PeerConfig{PublicKey: key, Log: peerLog})
			manager.RemovePeer(key)
		}
	}()

	for {
		select {
		case <-done:
			return
		case fakeTick <- time.Now():
		case <-time.After(5 * time.Second):
			t.Fatal("peer changes did not finish")
		}
	}
}
