package hbwatch

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeTimer struct {
	due time.Time
	f   func()
}

type fakeClock struct {
	mu     sync.Mutex
	now    time.Time
	timers []fakeTimer
}

func newFakeClock(start time.Time) *fakeClock { return &fakeClock{now: start} }

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) AfterFunc(d time.Duration, f func()) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.timers = append(c.timers, fakeTimer{due: c.now.Add(d), f: f})
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	var due []func()
	var keep []fakeTimer
	for _, t := range c.timers {
		if t.due.After(c.now) {
			keep = append(keep, t)
		} else {
			due = append(due, t.f)
		}
	}
	c.timers = keep
	c.mu.Unlock()
	for _, f := range due {
		f()
	}
}

var testStart = time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)

func staleCounter() (func(), *int) {
	n := 0
	return func() { n++ }, &n
}

// TestTickStaleReconnectsAtSecondMissedTick checks that a stream two or more
// ticks behind is reconnected and one tick behind is not.
func TestTickStaleReconnectsAtSecondMissedTick(t *testing.T) {
	clk := newFakeClock(testStart)
	w := New(clk, time.Minute)
	mgmtStale, mgmtN := staleCounter()
	sigStale, sigN := staleCounter()
	w.Register(Management, Registration{Kind: ActionReconnect, Stale: mgmtStale, AlignedPeriod: time.Minute})
	w.Register(Signal, Registration{Kind: ActionReconnect, Stale: sigStale, AlignedPeriod: time.Minute})

	w.Seen(Management, time.Minute)
	clk.Advance(time.Second)
	w.Seen(Signal, time.Minute)

	clk.Advance(59 * time.Second)
	w.Seen(Management, time.Minute) // tick 2
	assert.Zero(t, *sigN, "one tick behind is live")

	clk.Advance(time.Minute)
	w.Seen(Management, time.Minute) // tick 3
	assert.Equal(t, 1, *sigN, "two ticks behind reconnects")
	assert.Zero(t, *mgmtN)

	clk.Advance(time.Minute)
	w.Seen(Management, time.Minute) // tick 4
	assert.Equal(t, 1, *sigN, "not again on the very next tick")
	clk.Advance(time.Minute)
	w.Seen(Management, time.Minute) // tick 5
	assert.Equal(t, 2, *sigN, "again after two more ticks while still dead")
}

// TestLateArrivalsDoNotReconnectLiveStreams checks that heartbeats arriving
// late, one stream on time and two held 20 s and 80 s, give no reconnect.
func TestLateArrivalsDoNotReconnectLiveStreams(t *testing.T) {
	clk := newFakeClock(testStart)
	w := New(clk, time.Minute)
	counts := map[Service]*int{}
	for _, svc := range services {
		stale, n := staleCounter()
		counts[svc] = n
		w.Register(svc, Registration{Kind: ActionReconnect, Stale: stale, AlignedPeriod: time.Minute})
		w.Seen(svc, time.Minute)
	}

	clk.Advance(time.Minute)
	w.Seen(Management, time.Minute) // tick 2 on time
	clk.Advance(20 * time.Second)
	w.Seen(Signal, time.Minute) // held 20 s: joins tick 2
	clk.Advance(60 * time.Second)
	w.Seen(Relay, time.Minute) // held 80 s in total: opens tick 3
	clk.Advance(time.Second)
	w.Seen(Management, time.Minute) // joins tick 3
	w.Seen(Signal, time.Minute)

	for svc, n := range counts {
		assert.Zero(t, *n, "live stream %s must not reconnect", svc)
	}
}

// TestHalfPeriodLateHeartbeatKeepsLiveStreams covers one heartbeat late by
// half a period: Signal at 30 s opens tick 2, so Management on time at 60 s
// opens tick 3 while Relay, on time too, is still on tick 1. Relay was heard
// 60 s ago, inside its receive timeout, and must not be reconnected.
func TestHalfPeriodLateHeartbeatKeepsLiveStreams(t *testing.T) {
	clk := newFakeClock(testStart)
	w := New(clk, time.Minute)
	counts := map[Service]*int{}
	for _, svc := range services {
		stale, n := staleCounter()
		counts[svc] = n
		w.Register(svc, Registration{Kind: ActionReconnect, Stale: stale, AlignedPeriod: time.Minute})
		w.Seen(svc, time.Minute) // tick 1
	}

	clk.Advance(30 * time.Second)
	w.Seen(Signal, time.Minute) // half a period late: opens tick 2
	clk.Advance(30 * time.Second)
	w.Seen(Management, time.Minute) // on time: opens tick 3, Relay is 2 ticks behind
	clk.Advance(time.Second)
	w.Seen(Relay, time.Minute) // on time: joins tick 3
	w.Seen(Signal, time.Minute)

	for svc, n := range counts {
		assert.Zero(t, *n, "live stream %s must not reconnect", svc)
	}
}

// TestStaleStreamHeardWithinTimeoutIsCheckedAgain covers a dead Relay in the
// tick pattern of a half-period-late heartbeat: at tick 3 it is 2 ticks
// behind but silent only 60 s, so it is skipped and keeps its tick. At tick 4
// it is silent past its receive timeout and is reconnected, then again only
// after two more ticks while it stays dead.
func TestStaleStreamHeardWithinTimeoutIsCheckedAgain(t *testing.T) {
	clk := newFakeClock(testStart)
	w := New(clk, time.Minute)
	relayStale, relayN := staleCounter()
	w.Register(Management, Registration{Kind: ActionReconnect, Stale: func() {}, AlignedPeriod: time.Minute})
	w.Register(Signal, Registration{Kind: ActionReconnect, Stale: func() {}, AlignedPeriod: time.Minute})
	w.Register(Relay, Registration{Kind: ActionReconnect, Stale: relayStale, AlignedPeriod: time.Minute})
	for _, svc := range services {
		w.Seen(svc, time.Minute) // tick 1, Relay's last heartbeat
	}

	clk.Advance(30 * time.Second)
	w.Seen(Signal, time.Minute) // tick 2
	clk.Advance(30 * time.Second)
	w.Seen(Management, time.Minute) // tick 3
	w.Seen(Signal, time.Minute)
	assert.Zero(t, *relayN, "2 ticks behind but silent 60 s, inside the receive timeout")

	clk.Advance(time.Minute)
	w.Seen(Management, time.Minute) // tick 4
	assert.Equal(t, 1, *relayN, "the skipped stream kept its tick and is silent 120 s now")

	clk.Advance(time.Minute)
	w.Seen(Management, time.Minute) // tick 5
	assert.Equal(t, 1, *relayN, "not again on the very next tick")
	clk.Advance(time.Minute)
	w.Seen(Management, time.Minute) // tick 6
	assert.Equal(t, 2, *relayN, "again after two more ticks while still dead")
}

// TestWakeCheckReconnectsSilentStream covers the all-streams-dead case: no
// ticks form, and the wake check reconnects after the grace.
func TestWakeCheckReconnectsSilentStream(t *testing.T) {
	clk := newFakeClock(testStart)
	w := New(clk, time.Minute)
	stale, n := staleCounter()
	w.Register(Signal, Registration{Kind: ActionReconnect, Stale: stale, AlignedPeriod: time.Minute})
	w.Seen(Signal, time.Minute)

	clk.Advance(30 * time.Second)
	w.CheckNow()
	clk.Advance(Grace)
	assert.Zero(t, *n, "silent 30 s is inside the receive timeout")

	clk.Advance(50 * time.Second) // silent 80 s in total
	w.CheckNow()
	assert.Zero(t, *n, "the check runs only after the grace")
	clk.Advance(Grace)
	assert.Equal(t, 1, *n, "silent over period+10 s at the wake reconnects")

	w.CheckNow()
	clk.Advance(Grace)
	assert.Equal(t, 1, *n, "the same wake does not fire twice")
}

// TestWakeCheckReconnectsConfirmedStreamBeforeFirstHeartbeat covers a stream
// that registers before its aligned answer, as Management and relay do: the
// confirmed period alone must make a stream that dies before its first
// heartbeat count for the wake check. A stream never confirmed stays stock.
func TestWakeCheckReconnectsConfirmedStreamBeforeFirstHeartbeat(t *testing.T) {
	clk := newFakeClock(testStart)
	w := New(clk, time.Minute)
	confirmedStale, confirmed := staleCounter()
	stockStale, stock := staleCounter()
	w.Register(Management, Registration{Kind: ActionReconnect, Stale: confirmedStale})
	w.Register(Relay, Registration{Kind: ActionReconnect, Stale: stockStale})
	w.Confirm(Management, time.Minute)

	clk.Advance(80 * time.Second)
	w.CheckNow()
	clk.Advance(Grace)
	assert.Equal(t, 1, *confirmed, "a confirmed stream silent over period+10 s reconnects at the wake")
	assert.Zero(t, *stock, "a stream never confirmed aligned is not judged")

	snap := w.Snapshot()
	require.Len(t, snap.Streams, 2)
	assert.Equal(t, time.Minute, snap.Streams[0].Period, "the confirmed period shows before the first heartbeat")
	assert.False(t, snap.Streams[0].Aligned, "no heartbeat came yet")
}

func TestOnTickRunsOncePerTick(t *testing.T) {
	clk := newFakeClock(testStart)
	w := New(clk, time.Minute)
	w.Register(Management, Registration{AlignedPeriod: time.Minute})

	var periods []time.Duration
	unsubscribe := w.OnTick(func(p time.Duration) { periods = append(periods, p) })

	w.Seen(Management, time.Minute)
	clk.Advance(10 * time.Second)
	w.Seen(Management, time.Minute)
	assert.Len(t, periods, 1, "a heartbeat inside half a period joins the tick")

	clk.Advance(50 * time.Second)
	w.Seen(Management, time.Minute)
	require.Len(t, periods, 2, "a heartbeat half a period after the tick opens the next one")
	assert.Equal(t, time.Minute, periods[0])

	unsubscribe()
	clk.Advance(time.Minute)
	w.Seen(Management, time.Minute)
	assert.Len(t, periods, 2, "an unsubscribed func no longer runs")
}

func TestWaitRetryDelayEndsAtWakePastDeadline(t *testing.T) {
	clk := newFakeClock(testStart)
	w := New(clk, time.Minute)

	done := make(chan error, 1)
	go func() { done <- w.WaitRetryDelay(context.Background(), time.Minute, nil) }()
	// Let the wait subscribe before the wake fires.
	require.Eventually(t, func() bool {
		w.mu.Lock()
		defer w.mu.Unlock()
		return len(w.wakeSubs) > 0
	}, 5*time.Second, time.Millisecond)

	clk.Advance(30 * time.Second)
	w.CheckNow() // a wake before the deadline must not end the wait
	select {
	case err := <-done:
		t.Fatalf("wait ended early: %v", err)
	case <-time.After(100 * time.Millisecond):
	}

	clk.Advance(40 * time.Second) // past the wall deadline
	w.CheckNow()
	select {
	case err := <-done:
		assert.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("wake past the deadline did not end the wait")
	}
}

// TestUnreadWakeIsReplacedByNewer covers a retry waiter that did not read
// an early wake: a later wake past its deadline must replace it, not be
// dropped, or the wait sleeps until its timer after the device woke.
func TestUnreadWakeIsReplacedByNewer(t *testing.T) {
	clk := newFakeClock(testStart)
	w := New(clk, time.Minute)
	wakes, unsubscribe := w.subscribeWake()
	defer unsubscribe()

	w.fireWake(wakeEvent{at: testStart.Add(10 * time.Second)})
	w.fireWake(wakeEvent{at: testStart.Add(2 * time.Minute)})
	w.fireWake(wakeEvent{at: testStart.Add(time.Minute)})

	select {
	case wake := <-wakes:
		assert.Equal(t, testStart.Add(2*time.Minute), wake.at, "the waiter must see the newest wake")
	default:
		t.Fatal("a wake must wait for the waiter")
	}
	select {
	case wake := <-wakes:
		t.Fatalf("only one wake must wait, got another at %s", wake.at)
	default:
	}
}

func TestWaitRetryDelayTimerAndCancel(t *testing.T) {
	clk := newFakeClock(testStart)
	w := New(clk, time.Minute)

	assert.NoError(t, w.WaitRetryDelay(context.Background(), 20*time.Millisecond, nil), "the timer ends the wait")

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	assert.ErrorIs(t, w.WaitRetryDelay(ctx, time.Minute, nil), context.Canceled)

	changed := make(chan struct{})
	close(changed)
	assert.NoError(t, w.WaitRetryDelay(context.Background(), time.Minute, changed), "a network change ends the wait")
}

func TestRegisterReplaceAndSnapshot(t *testing.T) {
	clk := newFakeClock(testStart)
	w := New(clk, time.Minute)

	stale, n := staleCounter()
	unregister := w.Register(Relay, Registration{Kind: ActionReconnect, Stale: stale, Addr: "rels://a:443", AlignedPeriod: time.Minute})
	w.Seen(Relay, time.Minute)

	snap := w.Snapshot()
	require.Len(t, snap.Streams, 1)
	assert.Equal(t, Relay, snap.Streams[0].Service)
	assert.True(t, snap.Streams[0].Aligned)
	assert.Equal(t, time.Minute, snap.Streams[0].Period)
	assert.Equal(t, "rels://a:443", snap.Streams[0].Addr)

	// A newer registration owns the slot; the old unregister is a no-op.
	w.Register(Relay, Registration{Addr: "rels://b:443"})
	unregister()
	snap = w.Snapshot()
	require.Len(t, snap.Streams, 1)
	assert.Equal(t, "rels://b:443", snap.Streams[0].Addr)
	assert.False(t, snap.Streams[0].Aligned, "a fresh stream starts unaligned")
	assert.Zero(t, *n)
}

func TestSeenConcurrent(t *testing.T) {
	clk := newFakeClock(testStart)
	w := New(clk, time.Minute)
	for _, svc := range services {
		w.Register(svc, Registration{Kind: ActionReconnect, Stale: func() {}, AlignedPeriod: time.Minute})
	}
	var wg sync.WaitGroup
	for i := 0; i < 30; i++ {
		for _, svc := range services {
			wg.Add(1)
			go func() {
				defer wg.Done()
				w.Seen(svc, time.Minute)
				_ = w.Snapshot()
			}()
		}
	}
	wg.Wait()

	snap := w.Snapshot()
	require.Len(t, snap.Streams, len(services), "every registered stream is reported")
	for _, st := range snap.Streams {
		assert.True(t, st.Aligned, "stream %s must be aligned after its heartbeats", st.Service)
		assert.Equal(t, time.Minute, st.Period, "stream %s period", st.Service)
	}
}

// TestDefaultWatcherPublishedAfterCreate covers the first lookups of the
// default Watcher at engine start: nothing may be published while the
// Watcher is still being built, or a concurrent caller on the fast path
// would get a decided state without its Watcher.
func TestDefaultWatcherPublishedAfterCreate(t *testing.T) {
	prev := defaultEntry.Swap(nil)
	t.Cleanup(func() { defaultEntry.Store(prev) })

	built := New(newFakeClock(time.Unix(0, 0)), time.Minute)
	got := loadDefault(func() *Watcher {
		assert.Nil(t, defaultEntry.Load(), "nothing is published while create runs")
		return built
	})
	assert.Same(t, built, got, "the first caller gets the Watcher it built")

	got = loadDefault(func() *Watcher {
		t.Error("create must run only once")
		return nil
	})
	assert.Same(t, built, got, "a later caller gets the published Watcher")
}

// TestDefaultWatcherKeepsNil covers builds without the aligned heartbeat:
// the missing Watcher is decided once and kept.
func TestDefaultWatcherKeepsNil(t *testing.T) {
	prev := defaultEntry.Swap(nil)
	t.Cleanup(func() { defaultEntry.Store(prev) })

	calls := 0
	create := func() *Watcher {
		calls++
		return nil
	}
	assert.Nil(t, loadDefault(create), "a build without the aligned heartbeat has no Watcher")
	assert.Nil(t, loadDefault(create), "the missing Watcher is kept")
	assert.Equal(t, 1, calls, "create runs once")
}

func TestSetDefaultRestore(t *testing.T) {
	prev := defaultEntry.Swap(nil)
	t.Cleanup(func() { defaultEntry.Store(prev) })

	first := New(newFakeClock(time.Unix(0, 0)), time.Minute)
	restoreFirst := SetDefault(first)
	second := New(newFakeClock(time.Unix(0, 0)), time.Minute)
	restoreSecond := SetDefault(second)
	assert.Same(t, second, def(), "SetDefault replaces the default Watcher")

	restoreSecond()
	assert.Same(t, first, def(), "restore brings back the previous Watcher")
	restoreFirst()
	assert.Nil(t, defaultEntry.Load(), "restore brings back the undecided state")
}
