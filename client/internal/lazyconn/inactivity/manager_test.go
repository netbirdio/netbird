package inactivity

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
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

	manager := NewManager(wgMock, nil, nil)
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

	manager := NewManager(wgMock, nil, nil)
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

// addAt adds the peer as if it had been added at the time of its last activity,
// so the idle time in the test is measured from that activity alone.
func addAt(m *Manager, peerCfg *lazyconn.PeerConfig, at monotime.Time) {
	m.now = func() monotime.Time { return at }
	m.AddPeer(peerCfg)
	m.now = monotime.Now
}

// fakeTickerMock implements Ticker interface for testing
type fakeTickerMock struct {
	CChan chan time.Time

	mu     sync.Mutex
	resets []time.Duration
}

func (f *fakeTickerMock) C() <-chan time.Time {
	return f.CChan
}

func (f *fakeTickerMock) Reset(d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.resets = append(f.resets, d)
}

func (f *fakeTickerMock) getResets() []time.Duration {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]time.Duration(nil), f.resets...)
}

func (f *fakeTickerMock) Stop() {}

// fakeTickSource stands in for the aligned heartbeat tick.
type fakeTickSource struct {
	subscribed   chan func(time.Duration)
	unsubscribed chan struct{}
}

func newFakeTickSource() *fakeTickSource {
	return &fakeTickSource{
		subscribed:   make(chan func(time.Duration), 1),
		unsubscribed: make(chan struct{}),
	}
}

func (s *fakeTickSource) subscribe(f func(period time.Duration)) func() {
	s.subscribed <- f
	return func() { close(s.unsubscribed) }
}

// startTickManager starts a manager with one peer idle for idle, the configured
// threshold and the fake tick source. The fallback timer never fires on its own.
func startTickManager(t *testing.T, idle time.Duration, threshold *time.Duration) (*Manager, *fakeTickerMock, *fakeTickSource, context.CancelFunc) {
	t.Helper()
	peerID := "peer1"
	wgMock := &mockWgInterface{
		lastActivities: map[string]monotime.Time{
			peerID: monotime.Time(int64(monotime.Now()) - int64(idle)),
		},
	}

	ticker := &fakeTickerMock{CChan: make(chan time.Time, 1)}
	prev := newTicker
	newTicker = func(time.Duration) Ticker { return ticker }
	t.Cleanup(func() { newTicker = prev })

	src := newFakeTickSource()
	manager := NewManager(wgMock, threshold, src.subscribe)
	addAt(manager, &lazyconn.PeerConfig{PublicKey: peerID, Log: log.WithField("peer", peerID)},
		wgMock.lastActivities[peerID])

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go manager.Start(ctx)
	return manager, ticker, src, cancel
}

func waitSubscribed(t *testing.T, src *fakeTickSource) func(time.Duration) {
	t.Helper()
	select {
	case f := <-src.subscribed:
		return f
	case <-time.After(time.Second):
		t.Fatal("manager did not subscribe to the aligned tick")
		return nil
	}
}

func TestAlignedTickRunsCheck(t *testing.T) {
	manager, ticker, src, _ := startTickManager(t, 20*time.Minute, nil)
	tick := waitSubscribed(t, src)

	tick(time.Minute)

	select {
	case inactivePeers := <-manager.inactivePeersChan:
		assert.Contains(t, inactivePeers, "peer1", "idle peer reported on the aligned tick")
	case <-time.After(time.Second):
		t.Fatal("expected inactivity event on the aligned tick")
	}
	assert.Equal(t, []time.Duration{time.Minute + tickSlack}, ticker.getResets(),
		"fallback timer pushed past the next expected tick")
}

func TestAlignedTickActivePeerNotReported(t *testing.T) {
	manager, _, src, _ := startTickManager(t, 5*time.Second, nil)
	tick := waitSubscribed(t, src)

	tick(time.Minute)

	select {
	case <-manager.inactivePeersChan:
		t.Fatal("active peer must not be reported")
	case <-time.After(200 * time.Millisecond):
	}
}

func TestAlignedTickWithoutPeriodIgnored(t *testing.T) {
	manager, ticker, src, _ := startTickManager(t, 20*time.Minute, nil)
	tick := waitSubscribed(t, src)

	tick(0)

	select {
	case <-manager.inactivePeersChan:
		t.Fatal("a tick without a period must not run the check")
	case <-time.After(200 * time.Millisecond):
	}
	assert.Empty(t, ticker.getResets(), "fallback timer untouched")
}

// While no aligned tick arrives, the fallback timer still runs the check.
func TestFallbackTimerWithoutTicks(t *testing.T) {
	manager, ticker, src, _ := startTickManager(t, 20*time.Minute, nil)
	waitSubscribed(t, src)

	ticker.CChan <- time.Now()

	select {
	case inactivePeers := <-manager.inactivePeersChan:
		assert.Contains(t, inactivePeers, "peer1", "idle peer reported by the fallback timer")
	case <-time.After(time.Second):
		t.Fatal("expected inactivity event from the fallback timer")
	}
}

func TestAlignedTickUnsubscribeOnStop(t *testing.T) {
	_, _, src, cancel := startTickManager(t, 20*time.Minute, nil)
	waitSubscribed(t, src)

	cancel()

	select {
	case <-src.unsubscribed:
	case <-time.After(time.Second):
		t.Fatal("manager did not unsubscribe from the aligned tick on stop")
	}
}

// A peer idle for 30 s is past the short threshold of the aligned tick check.
func TestAlignedTickUsesShortThreshold(t *testing.T) {
	manager, _, src, _ := startTickManager(t, 30*time.Second, nil)
	tick := waitSubscribed(t, src)

	tick(time.Minute)

	select {
	case inactivePeers := <-manager.inactivePeersChan:
		assert.Contains(t, inactivePeers, "peer1", "peer idle past the aligned threshold reported on the tick")
	case <-time.After(time.Second):
		t.Fatal("expected inactivity event on the aligned tick")
	}
}

// Without aligned ticks (old server, aligned heartbeat off) the timer check keeps
// the stock threshold, so a peer idle for 30 s stays open.
func TestFallbackTimerKeepsStockThreshold(t *testing.T) {
	manager, ticker, src, _ := startTickManager(t, 30*time.Second, nil)
	waitSubscribed(t, src)

	ticker.CChan <- time.Now()

	select {
	case <-manager.inactivePeersChan:
		t.Fatal("timer check must use the stock threshold")
	case <-time.After(200 * time.Millisecond):
	}
}

func TestNewManagerThresholds(t *testing.T) {
	d := func(v time.Duration) *time.Duration { return &v }
	subscribe := func(func(time.Duration)) func() { return func() {} }
	tests := []struct {
		name      string
		in        *time.Duration
		tick      TickSubscriber
		wantStock time.Duration
		wantTick  time.Duration
	}{
		{name: "no tick, default", wantStock: DefaultInactivityThreshold},
		{name: "no tick, too low", in: d(30 * time.Second), wantStock: DefaultInactivityThreshold},
		{name: "no tick, configured", in: d(5 * time.Minute), wantStock: 5 * time.Minute},
		{name: "tick, default", tick: subscribe,
			wantStock: DefaultInactivityThreshold, wantTick: DefaultAlignedInactivityThreshold},
		{name: "tick, short value only on tick", in: d(30 * time.Second), tick: subscribe,
			wantStock: DefaultInactivityThreshold, wantTick: 30 * time.Second},
		{name: "tick, at aligned minimum", in: d(MinimumAlignedInactivityThreshold), tick: subscribe,
			wantStock: DefaultInactivityThreshold, wantTick: MinimumAlignedInactivityThreshold},
		{name: "tick, below aligned minimum", in: d(MinimumAlignedInactivityThreshold - time.Second), tick: subscribe,
			wantStock: DefaultInactivityThreshold, wantTick: DefaultAlignedInactivityThreshold},
		{name: "tick, long value on both", in: d(30 * time.Minute), tick: subscribe,
			wantStock: 30 * time.Minute, wantTick: 30 * time.Minute},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := NewManager(&mockWgInterface{}, tt.in, tt.tick)
			assert.Equal(t, tt.wantStock, m.inactivityThreshold, "timer check threshold")
			assert.Equal(t, tt.wantTick, m.tickThreshold, "aligned tick check threshold")
		})
	}
}

// The engine adds and removes peers while the Start loop checks them. Run with
// -race: an unguarded peer map shows up as a data race or a concurrent map crash.
func TestConcurrentPeerChangesDuringCheck(t *testing.T) {
	wgMock := &mockWgInterface{lastActivities: map[string]monotime.Time{}}

	ticker := &fakeTickerMock{CChan: make(chan time.Time)}
	prev := newTicker
	newTicker = func(time.Duration) Ticker { return ticker }
	t.Cleanup(func() { newTicker = prev })

	manager := NewManager(wgMock, nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
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
		case ticker.CChan <- time.Now():
		case <-time.After(5 * time.Second):
			t.Fatal("peer changes did not finish")
		}
	}
}

// fakeClock is a manual monotonic clock for the manager.
type fakeClock struct {
	t atomic.Int64
}

func newFakeClock() *fakeClock {
	c := &fakeClock{}
	c.t.Store(int64(monotime.Now()))
	return c
}

func (c *fakeClock) now() monotime.Time { return monotime.Time(c.t.Load()) }

func (c *fakeClock) advance(d time.Duration) { c.t.Add(int64(d)) }

// startClockedTickManager starts a manager on a fake clock with the fake tick
// source and no peers. lastActive is what the interface reports for peer1.
func startClockedTickManager(t *testing.T, clock *fakeClock, lastActive monotime.Time) (*Manager, func(time.Duration)) {
	t.Helper()
	ticker := &fakeTickerMock{CChan: make(chan time.Time, 1)}
	prev := newTicker
	newTicker = func(time.Duration) Ticker { return ticker }
	t.Cleanup(func() { newTicker = prev })

	src := newFakeTickSource()
	wgMock := &mockWgInterface{lastActivities: map[string]monotime.Time{"peer1": lastActive}}
	manager := NewManager(wgMock, nil, src.subscribe)
	manager.now = clock.now

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go manager.Start(ctx)
	return manager, waitSubscribed(t, src)
}

func addPeer1(m *Manager) {
	m.AddPeer(&lazyconn.PeerConfig{PublicKey: "peer1", Log: log.WithField("peer", "peer1")})
}

func expectReported(t *testing.T, m *Manager, msg string) {
	t.Helper()
	select {
	case inactivePeers := <-m.inactivePeersChan:
		assert.Contains(t, inactivePeers, "peer1", msg)
	case <-time.After(time.Second):
		t.Fatal(msg)
	}
}

func expectNotReported(t *testing.T, m *Manager, msg string) {
	t.Helper()
	select {
	case inactivePeers := <-m.inactivePeersChan:
		t.Fatalf("%s: reported %v", msg, inactivePeers)
	case <-time.After(200 * time.Millisecond):
	}
}

// The interface still reports the last traffic of the previous session when a
// link reopens. The aligned tick 0.3 s after the open must not close the link,
// and the link closes on the first tick after 10 s without traffic.
func TestFirstTickAfterOpenKeepsLink(t *testing.T) {
	clock := newFakeClock()
	staleActivity := clock.now() - monotime.Time(time.Hour)
	manager, tick := startClockedTickManager(t, clock, staleActivity)

	addPeer1(manager)
	clock.advance(300 * time.Millisecond)
	tick(time.Minute)
	expectNotReported(t, manager, "tick 0.3 s after the open must not close the link")

	clock.advance(10 * time.Second)
	tick(time.Minute)
	expectReported(t, manager, "link idle for 10 s since the open must close on the next tick")
}

// A close removes the peer, the reopen adds it again. The add time of the new
// session counts, not the one of the first.
func TestReaddedPeerGetsNewAddTime(t *testing.T) {
	clock := newFakeClock()
	manager, tick := startClockedTickManager(t, clock, clock.now()-monotime.Time(time.Hour))

	addPeer1(manager)
	clock.advance(time.Minute)
	tick(time.Minute)
	expectReported(t, manager, "peer idle for a minute after the add is reported")

	manager.RemovePeer("peer1")
	addPeer1(manager)
	clock.advance(300 * time.Millisecond)
	tick(time.Minute)
	expectNotReported(t, manager, "tick right after the re-add must not close the link")
}

// Traffic after the add moves the idle start past the add time.
func TestActivityAfterAddCounts(t *testing.T) {
	clock := newFakeClock()
	addTime := clock.now()
	manager, tick := startClockedTickManager(t, clock, addTime+monotime.Time(20*time.Second))

	addPeer1(manager)
	clock.advance(25 * time.Second)
	tick(time.Minute)
	expectNotReported(t, manager, "peer active 5 s ago must stay open")

	clock.advance(6 * time.Second)
	tick(time.Minute)
	expectReported(t, manager, "peer idle 11 s since its last traffic is reported")
}
