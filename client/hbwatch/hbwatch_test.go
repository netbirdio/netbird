package hbwatch

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeClock is a wall clock moved by hand. A jump models the phone sleeping:
// no timer fires during the jump, but Now moves on.
type fakeClock struct {
	mu        sync.Mutex
	now       time.Time
	timers    []fakeTimer
	scheduled int
}

type fakeTimer struct {
	at time.Time
	f  func()
}

func newFakeClock() *fakeClock {
	return &fakeClock{now: time.Unix(1_800_000_000, 0)}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) AfterFunc(d time.Duration, f func()) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.scheduled++
	c.timers = append(c.timers, fakeTimer{at: c.now.Add(d), f: f})
}

// advance moves the clock and runs the timers that came due, in order.
func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	var due []func()
	kept := c.timers[:0]
	for _, t := range c.timers {
		if !t.at.After(c.now) {
			due = append(due, t.f)
			continue
		}
		kept = append(kept, t)
	}
	c.timers = kept
	c.mu.Unlock()
	for _, f := range due {
		f()
	}
}

// jump moves the clock without running any timer, like a sleeping phone.
func (c *fakeClock) jump(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func (c *fakeClock) scheduledCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.scheduled
}

type counter struct {
	mu sync.Mutex
	n  map[Service]int
}

func (c *counter) action(svc Service) func() {
	return func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.n == nil {
			c.n = map[Service]int{}
		}
		c.n[svc]++
	}
}

func (c *counter) get(svc Service) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.n[svc]
}

func registerAll(w *Watcher, c *counter) {
	w.Register(Management, ActionReconnect, c.action(Management))
	w.Register(Signal, ActionProbe, c.action(Signal))
	w.Register(Relay, ActionReconnect, c.action(Relay))
}

// After a sleep the monotonic timers have not run, but the first trigger must
// see the real wall gap and act on the streams that stayed silent.
func TestWallGapSeenAtOnceAfterSleep(t *testing.T) {
	clk := newFakeClock()
	w := New(clk, 30*time.Second)
	var c counter
	registerAll(w, &c)

	clk.jump(100 * time.Second)
	w.Seen(Management)
	clk.advance(Grace)

	assert.Equal(t, 0, c.get(Management), "management just sent a heartbeat")
	assert.Equal(t, 1, c.get(Signal), "signal silent for 102 s must fire its action")
	assert.Equal(t, 1, c.get(Relay), "relay silent for 102 s must fire its action")
}

// Heartbeats of one tick arrive a few hundred ms apart. They must collapse
// into one check, and none of them is stale.
func TestGraceCollapsesOneTick(t *testing.T) {
	clk := newFakeClock()
	w := New(clk, 30*time.Second)
	var c counter
	registerAll(w, &c)

	clk.advance(30 * time.Second)
	w.Seen(Relay)
	clk.advance(300 * time.Millisecond)
	w.Seen(Management)
	clk.advance(300 * time.Millisecond)
	w.Seen(Signal)
	clk.advance(Grace)

	assert.Equal(t, 1, clk.scheduledCount(), "three heartbeats within the grace must schedule one check")
	for _, svc := range services {
		assert.Equal(t, 0, c.get(svc), "no service is stale: %s", svc)
	}
}

// One silent service fires once, not again within the same period, and a
// reconnect (Register) resets its timestamp.
func TestStaleFiresOncePerPeriodAndResetsOnReconnect(t *testing.T) {
	clk := newFakeClock()
	w := New(clk, 30*time.Second)
	var c counter
	registerAll(w, &c)

	beat := func() {
		w.Seen(Management)
		w.Seen(Relay)
		clk.advance(Grace)
	}

	// Exactly period + tolerance at the trigger is still fine: the grace
	// before the check does not count toward the gap.
	clk.advance(30*time.Second + Tolerance)
	beat()
	assert.Equal(t, 0, c.get(Signal), "gap of period + tolerance is not stale")

	clk.advance(5 * time.Second)
	beat()
	require.Equal(t, 1, c.get(Signal), "signal past period + tolerance must fire")

	// Wake within the same period: no second action.
	w.CheckNow()
	clk.advance(Grace)
	clk.advance(10 * time.Second)
	beat()
	assert.Equal(t, 1, c.get(Signal), "no second action within one period")

	// The stream reconnects: the fresh stream is not stale.
	w.Register(Signal, ActionProbe, c.action(Signal))
	clk.advance(25 * time.Second)
	beat()
	assert.Equal(t, 1, c.get(Signal), "a fresh stream must not be stale")

	// It stays silent for a full period again: the next action may fire.
	clk.advance(10 * time.Second)
	beat()
	assert.Equal(t, 2, c.get(Signal), "silent again past period + tolerance must fire again")
	assert.Equal(t, 0, c.get(Management), "management kept sending")
	assert.Equal(t, 0, c.get(Relay), "relay kept sending")
}

// Only connected services are checked. A stale unregister from an old stream
// must not drop the registration of the new stream.
func TestUnregisterOnlyRemovesOwnRegistration(t *testing.T) {
	clk := newFakeClock()
	w := New(clk, 30*time.Second)
	var c counter

	oldUnregister := w.Register(Relay, ActionReconnect, c.action(Relay))
	newUnregister := w.Register(Relay, ActionReconnect, c.action(Relay))
	oldUnregister()

	clk.jump(60 * time.Second)
	w.CheckNow()
	clk.advance(Grace)
	assert.Equal(t, 1, c.get(Relay), "the newer registration must stay active")

	newUnregister()
	clk.jump(60 * time.Second)
	w.CheckNow()
	clk.advance(Grace)
	assert.Equal(t, 1, c.get(Relay), "an unregistered service is not checked")
}

// The Swift wake can call CheckNow before the engine runs and after it stops.
func TestCheckNowWithoutServicesIsNoop(t *testing.T) {
	clk := newFakeClock()
	w := New(clk, 30*time.Second)
	w.CheckNow()
	clk.advance(Grace)
	assert.Equal(t, 1, clk.scheduledCount(), "CheckNow schedules one check")
}

func TestPeriodFromEnv(t *testing.T) {
	t.Setenv(envPeriod, "60")
	assert.Equal(t, 60*time.Second, PeriodFromEnv(), "period from env")
	t.Setenv(envPeriod, "")
	assert.Equal(t, 30*time.Second, PeriodFromEnv(), "default period")
	t.Setenv(envPeriod, "x")
	assert.Equal(t, 30*time.Second, PeriodFromEnv(), "unparsable keeps default")
}
