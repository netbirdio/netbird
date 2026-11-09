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
	r  map[Service]int
}

// reconnect counts the off-phase reconnects of svc apart from its stale action.
func (c *counter) reconnect(svc Service) func() {
	return func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.r == nil {
			c.r = map[Service]int{}
		}
		c.r[svc]++
	}
}

func (c *counter) reconnects(svc Service) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.r[svc]
}

// register registers svc with the counter's stale action and reconnect.
func register(w *Watcher, c *counter, svc Service, kind string) (unregister func()) {
	return w.Register(svc, kind, c.action(svc), c.reconnect(svc))
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

// newTickWatcher returns a Watcher whose client phase is 0, so the fake clock
// start and every whole 30 s after it are ticks.
func newTickWatcher(clk *fakeClock) *Watcher {
	w := New(clk, 30*time.Second)
	w.phaseFn = func() (time.Duration, time.Duration, bool) { return 0, 30 * time.Second, true }
	return w
}

func registerAll(w *Watcher, c *counter) {
	register(w, c, Management, ActionReconnect)
	register(w, c, Signal, ActionProbe)
	register(w, c, Relay, ActionReconnect)
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
// reconnect (Register) resets its timestamp. Other frames (not heartbeats)
// trigger the checks, so the period plus tolerance rule applies.
func TestStaleFiresOncePerPeriodAndResetsOnReconnect(t *testing.T) {
	clk := newFakeClock()
	w := New(clk, 30*time.Second)
	var c counter
	registerAll(w, &c)

	beat := func() {
		w.Touch(Management)
		w.Touch(Relay)
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
	register(w, &c, Signal, ActionProbe)
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

// tick delivers the heartbeats of the given services as one server tick: a
// few hundred ms apart, then the grace runs out.
func tick(clk *fakeClock, w *Watcher, svcs ...Service) {
	for _, svc := range svcs {
		w.Seen(svc)
		clk.advance(300 * time.Millisecond)
	}
	clk.advance(Grace)
}

// untilNextTick moves the clock to the next tick after tick() ran for n
// services.
func untilNextTick(clk *fakeClock, n int) {
	clk.advance(30*time.Second - Grace - time.Duration(n)*300*time.Millisecond)
}

// A service that misses one tick is flagged at that tick, not one tick or a
// random wake later. A muted service is flagged at every tick it misses.
func TestTickFlagsFirstMissedHeartbeat(t *testing.T) {
	clk := newFakeClock()
	w := newTickWatcher(clk)
	var c counter
	registerAll(w, &c)

	clk.advance(30 * time.Second)
	tick(clk, w, Relay, Management, Signal)
	require.Equal(t, 0, c.get(Signal), "all three sent their heartbeat")

	untilNextTick(clk, 3)
	tick(clk, w, Relay, Management)
	assert.Equal(t, 1, c.get(Signal), "signal missed this tick and must fire at it")

	untilNextTick(clk, 2)
	tick(clk, w, Relay, Management)
	assert.Equal(t, 2, c.get(Signal), "signal missed the next tick too and must fire again")

	untilNextTick(clk, 2)
	tick(clk, w, Relay, Management, Signal)
	assert.Equal(t, 2, c.get(Signal), "signal is back and must not fire")
	assert.Equal(t, 0, c.get(Management), "management sent every heartbeat")
	assert.Equal(t, 0, c.get(Relay), "relay sent every heartbeat")
}

// A frame that lands inside the grace after the tick still counts for that
// tick.
func TestTickFrameInsideGraceNotStale(t *testing.T) {
	clk := newFakeClock()
	w := newTickWatcher(clk)
	var c counter
	registerAll(w, &c)

	clk.advance(30 * time.Second)
	tick(clk, w, Relay, Management, Signal)

	untilNextTick(clk, 3)
	w.Seen(Relay)
	clk.advance(300 * time.Millisecond)
	w.Seen(Management)
	clk.advance(Grace - 500*time.Millisecond)
	w.Touch(Signal)
	clk.advance(200 * time.Millisecond)
	require.Equal(t, 2, clk.scheduledCount(), "one check per tick")
	assert.Equal(t, 0, c.get(Signal), "signal frame inside the grace counts")
}

// Wakes and other frames between ticks keep the period plus tolerance rule:
// a steady service is not stale half a period after its heartbeat.
func TestWakeBetweenTicksNotStale(t *testing.T) {
	clk := newFakeClock()
	w := newTickWatcher(clk)
	var c counter
	registerAll(w, &c)

	clk.advance(30 * time.Second)
	tick(clk, w, Relay, Management, Signal)

	clk.advance(18 * time.Second)
	w.CheckNow()
	clk.advance(Grace)
	clk.advance(3 * time.Second)
	w.Touch(Relay)
	clk.advance(Grace)
	for _, svc := range services {
		assert.Equal(t, 0, c.get(svc), "wake or frame between ticks must not flag %s", svc)
	}
}

// After a stalled connect one stream keeps a wrong server skew and its
// heartbeat arrives about 11 s before the phase. That heartbeat is not a
// tick: it must not flag the streams that are on phase, and at their tick the
// early stream is not stale either. The early stream gets one off-phase
// reconnect; here the reconnect does nothing, so the same connection stays.
func TestOffPhaseHeartbeatIsNotATick(t *testing.T) {
	clk := newFakeClock()
	w := newTickWatcher(clk)
	var c counter
	registerAll(w, &c)

	clk.advance(19 * time.Second)
	for i := 0; i < 4; i++ {
		// Signal at phase - 11 s.
		w.Seen(Signal)
		clk.advance(11 * time.Second)
		// Management and relay at the phase.
		tick(clk, w, Management, Relay)
		clk.advance(19*time.Second - Grace - 600*time.Millisecond)
	}
	for _, svc := range services {
		assert.Equal(t, 0, c.get(svc), "steady streams must not be flagged: %s", svc)
	}
	assert.Equal(t, 1, c.reconnects(Signal), "one off-phase reconnect per connection")
	assert.Equal(t, 0, c.reconnects(Management), "management is on phase")
	assert.Equal(t, 0, c.reconnects(Relay), "relay is on phase")
}

// An off-phase heartbeat reconnects only its own service, at once, not after
// the grace. Here signal turns 4 s late: the tick flags it first and probes
// it, and the probe does not hold back the reconnect, which fixes the skew.
func TestOffPhaseHeartbeatReconnectsOwnService(t *testing.T) {
	clk := newFakeClock()
	w := newTickWatcher(clk)
	var c counter
	registerAll(w, &c)

	clk.advance(30 * time.Second)
	tick(clk, w, Relay, Management, Signal)
	untilNextTick(clk, 3)
	tick(clk, w, Relay, Management)
	require.Equal(t, 1, c.get(Signal), "the tick probes the late signal")

	clk.advance(4*time.Second - Grace - 600*time.Millisecond)
	w.Seen(Signal)
	assert.Equal(t, 1, c.reconnects(Signal), "off-phase signal heartbeat must reconnect signal at once")
	assert.Equal(t, 0, c.reconnects(Management), "management not touched")
	assert.Equal(t, 0, c.reconnects(Relay), "relay not touched")
	assert.Equal(t, 0, c.get(Management), "no stale action on management")
	assert.Equal(t, 0, c.get(Relay), "no stale action on relay")
}

// Heartbeats at the window edges are on phase and reconnect nothing.
func TestHeartbeatInsideWindowNoReconnect(t *testing.T) {
	clk := newFakeClock()
	w := newTickWatcher(clk)
	var c counter
	register(w, &c, Relay, ActionReconnect)

	clk.advance(30*time.Second - tickWindow)
	w.Seen(Relay)
	clk.advance(30 * time.Second)
	w.Seen(Relay)
	clk.advance(30*time.Second + 2*tickWindow)
	w.Seen(Relay)
	clk.advance(Grace)
	assert.Equal(t, 0, c.reconnects(Relay), "heartbeat within the window must not reconnect")
	assert.Equal(t, 0, c.get(Relay), "no stale action")
}

// At most one action per period: a new connection that is still off phase
// and sends its first heartbeat under one period after the reconnect is left
// until its next one. A reconnect that does not open a new connection leaves
// the old stream, and its off-phase heartbeats are not reconnected again. A
// new connection on phase is left alone.
func TestOffPhaseReconnectOncePerConnectionAndPeriod(t *testing.T) {
	clk := newFakeClock()
	w := newTickWatcher(clk)
	var c counter
	register(w, &c, Relay, ActionReconnect)
	// Management is not registered; its heartbeats only mark a test mode.
	relay := func() {
		w.Seen(Management)
		w.Seen(Relay)
	}

	// Relay heartbeat 10 s before the phase.
	clk.advance(20 * time.Second)
	relay()
	require.Equal(t, 1, c.reconnects(Relay), "first off-phase heartbeat reconnects")

	// New connection 1 s later, its server skew is wrong again: heartbeats
	// at phase + 10 s.
	clk.advance(time.Second)
	register(w, &c, Relay, ActionReconnect)
	clk.advance(19 * time.Second)
	relay()
	assert.Equal(t, 1, c.reconnects(Relay), "20 s after the last action: at most one action per period")
	clk.advance(30 * time.Second)
	relay()
	assert.Equal(t, 2, c.reconnects(Relay), "still off phase one period later: reconnect")

	// The reconnect did not open a new connection.
	clk.advance(30 * time.Second)
	relay()
	assert.Equal(t, 2, c.reconnects(Relay), "same connection must not be reconnected again")

	// The next connection is on phase.
	clk.advance(time.Second)
	register(w, &c, Relay, ActionReconnect)
	clk.advance(19 * time.Second)
	for i := 0; i < 4; i++ {
		tick(clk, w, Relay)
		untilNextTick(clk, 1)
	}
	assert.Equal(t, 2, c.reconnects(Relay), "connection on phase must not be reconnected")
	assert.Equal(t, 0, c.get(Relay), "no stale action")
}

// In mode off only the stock relay health check arrives, at any phase. It
// must not reconnect relay. Once Management or Signal heartbeats come (a test
// mode), an off-phase relay heartbeat reconnects; 2 periods after the last
// one it does not any more.
func TestOffPhaseRelayNeedsTestHeartbeats(t *testing.T) {
	clk := newFakeClock()
	w := newTickWatcher(clk)
	var c counter
	register(w, &c, Relay, ActionReconnect)

	clk.advance(10 * time.Second)
	for i := 0; i < 4; i++ {
		w.Seen(Relay)
		clk.advance(25 * time.Second)
	}
	require.Equal(t, 0, c.reconnects(Relay), "mode off: relay health checks must not reconnect")

	// A test mode starts: a Management heartbeat (here off phase too, so no
	// tick flags relay), then relay 10 s before the phase.
	w.Seen(Management)
	w.Seen(Relay)
	require.Equal(t, 1, c.reconnects(Relay), "test mode: off-phase relay heartbeat reconnects")

	// New relay connection, no test heartbeat for more than 2 periods.
	register(w, &c, Relay, ActionReconnect)
	clk.advance(61 * time.Second)
	w.Seen(Relay)
	assert.Equal(t, 1, c.reconnects(Relay), "2 periods without a test heartbeat: no reconnect")
}

// Without a known phase nothing is off phase.
func TestUnknownPhaseNoOffPhaseReconnect(t *testing.T) {
	clk := newFakeClock()
	w := New(clk, 30*time.Second)
	var c counter
	registerAll(w, &c)

	clk.advance(11 * time.Second)
	w.Seen(Signal)
	assert.Equal(t, 0, c.reconnects(Signal), "unknown phase must not reconnect")
}

// Without a known phase no heartbeat is a tick, so the period plus
// tolerance rule applies.
func TestUnknownPhaseKeepsPeriodRule(t *testing.T) {
	clk := newFakeClock()
	w := New(clk, 30*time.Second)
	var c counter
	registerAll(w, &c)

	clk.advance(30 * time.Second)
	tick(clk, w, Relay, Management, Signal)
	untilNextTick(clk, 3)
	tick(clk, w, Relay, Management)
	assert.Equal(t, 0, c.get(Signal), "one missed heartbeat is under period plus tolerance")
	untilNextTick(clk, 2)
	tick(clk, w, Relay, Management)
	assert.Equal(t, 1, c.get(Signal), "two missed heartbeats are over period plus tolerance")
}

func TestPhaseOffset(t *testing.T) {
	w := New(newFakeClock(), 30*time.Second)
	w.phaseFn = func() (time.Duration, time.Duration, bool) {
		return 21723 * time.Millisecond, 30 * time.Second, true
	}
	base := time.Unix(1_800_000_000, 0)
	for _, tc := range []struct {
		at   time.Duration
		want time.Duration
	}{
		{21723 * time.Millisecond, 0},
		{22223 * time.Millisecond, 500 * time.Millisecond},
		{10723 * time.Millisecond, -11 * time.Second},
		{6723 * time.Millisecond, 15 * time.Second},
		{51223 * time.Millisecond, -500 * time.Millisecond},
	} {
		off, ok := w.phaseOffset(base.Add(tc.at))
		require.True(t, ok)
		assert.Equal(t, tc.want, off, "offset at %s", tc.at)
	}
}

// Only connected services are checked. A stale unregister from an old stream
// must not drop the registration of the new stream.
func TestUnregisterOnlyRemovesOwnRegistration(t *testing.T) {
	clk := newFakeClock()
	w := New(clk, 30*time.Second)
	var c counter

	oldUnregister := register(w, &c, Relay, ActionReconnect)
	newUnregister := register(w, &c, Relay, ActionReconnect)
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

// The extension can call CheckNow before the engine exports the env. That
// early call must not keep the watcher disabled.
func TestDefaultEnabledAfterEarlyDisabledCall(t *testing.T) {
	defaultMu.Lock()
	prev, prevSet := defaultWatcher.Swap(nil), defaultSet.Swap(false)
	defaultMu.Unlock()
	t.Cleanup(func() {
		defaultMu.Lock()
		defaultWatcher.Store(prev)
		defaultSet.Store(prevSet)
		defaultMu.Unlock()
	})

	t.Setenv(envEnabled, "")
	CheckNow()
	require.Nil(t, def())

	t.Setenv(envEnabled, "1")
	w := def()
	require.NotNil(t, w)
	require.Same(t, w, def())

	restore := SetDefault(nil)
	require.Nil(t, def(), "SetDefault(nil) keeps the default off")
	restore()
	require.Same(t, w, def())
}

func checkPending(w *Watcher) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.pending
}

// toNextPhase moves the clock from a whole tick plus d to the next tick plus
// to, running timers on the way.
func toNextPhase(clk *fakeClock, from, to time.Duration) {
	clk.advance(30*time.Second - from + to)
}

// assertCheckAt asserts that the pending check runs at the current time plus
// d, not earlier.
func assertCheckAt(t *testing.T, clk *fakeClock, w *Watcher, d time.Duration) {
	t.Helper()
	clk.advance(d - time.Millisecond)
	assert.True(t, checkPending(w), "check must not run before the expected time")
	clk.advance(time.Millisecond)
	assert.False(t, checkPending(w), "check must run at the expected time")
}

// A wake (here a path update) just before the tick starts the check. The
// heartbeats of the tick join it, and relay, due 0.6 s after the phase, must
// still land before the check. Night 23 had the wake 1.95 s before the
// first heartbeat, inside the grace of the wake.
func TestWakeBeforeTickWaitsForTick(t *testing.T) {
	for _, wake := range []time.Duration{-2 * time.Second, -1800 * time.Millisecond} {
		t.Run(wake.String(), func(t *testing.T) {
			clk := newFakeClock()
			w := newTickWatcher(clk)
			var c counter
			registerAll(w, &c)

			clk.advance(30 * time.Second)
			tick(clk, w, Relay, Management, Signal)

			toNextPhase(clk, Grace+900*time.Millisecond, wake)
			w.CheckNow()
			clk.advance(100*time.Millisecond - wake)
			w.Seen(Management)
			w.Seen(Signal)
			clk.advance(500 * time.Millisecond)
			w.Seen(Relay)
			// Now at P + 0.6 s; the check runs at P + 2 s.
			assertCheckAt(t, clk, w, 1400*time.Millisecond)
			for _, svc := range services {
				assert.Equal(t, 0, c.get(svc), "no stale action: %s", svc)
			}
		})
	}
}

// A heartbeat 1.8 s early starts the tick check. Relay arrives 2.3 s later,
// after the grace from the early heartbeat, and must still count (22c Part D).
func TestEarlyHeartbeatWaitsForTick(t *testing.T) {
	clk := newFakeClock()
	w := newTickWatcher(clk)
	var c counter
	registerAll(w, &c)

	clk.advance(30 * time.Second)
	tick(clk, w, Relay, Management, Signal)

	toNextPhase(clk, Grace+900*time.Millisecond, -1800*time.Millisecond)
	w.Seen(Management)
	clk.advance(1900 * time.Millisecond)
	w.Seen(Signal)
	clk.advance(400 * time.Millisecond)
	w.Seen(Relay)
	assertCheckAt(t, clk, w, 1500*time.Millisecond)
	for _, svc := range services {
		assert.Equal(t, 0, c.get(svc), "no stale action: %s", svc)
	}
}

// A wake 3.5 s before the phase is no tick and schedules its check at T +
// grace. An early heartbeat joins it and moves the check to the tick.
func TestJoinMovesCheckLater(t *testing.T) {
	clk := newFakeClock()
	w := newTickWatcher(clk)
	var c counter
	registerAll(w, &c)

	clk.advance(30 * time.Second)
	tick(clk, w, Relay, Management, Signal)

	toNextPhase(clk, Grace+900*time.Millisecond, -3500*time.Millisecond)
	w.CheckNow()
	clk.advance(1700 * time.Millisecond)
	w.Seen(Management)
	clk.advance(1900 * time.Millisecond)
	w.Seen(Signal)
	clk.advance(400 * time.Millisecond)
	w.Seen(Relay)
	assertCheckAt(t, clk, w, 1500*time.Millisecond)
	for _, svc := range services {
		assert.Equal(t, 0, c.get(svc), "no stale action: %s", svc)
	}
}

// A real missed tick still gives exactly one action, within 3 s of the phase.
func TestMissedTickStillActsAfterTickGrace(t *testing.T) {
	clk := newFakeClock()
	w := newTickWatcher(clk)
	var c counter
	registerAll(w, &c)

	clk.advance(30 * time.Second)
	tick(clk, w, Relay, Management, Signal)

	toNextPhase(clk, Grace+900*time.Millisecond, 100*time.Millisecond)
	w.Seen(Management)
	clk.advance(200 * time.Millisecond)
	w.Seen(Signal)
	// Now at P + 0.3 s.
	clk.advance(Grace - 300*time.Millisecond - time.Millisecond)
	require.Equal(t, 0, c.get(Relay), "no action before P + grace")
	clk.advance(time.Millisecond)
	assert.Equal(t, 1, c.get(Relay), "missed relay tick acts at P + grace")
	clk.advance(5 * time.Second)
	assert.Equal(t, 1, c.get(Relay), "exactly one action")
	assert.Equal(t, 0, c.get(Management), "management sent its heartbeat")
	assert.Equal(t, 0, c.get(Signal), "signal sent its heartbeat")
}

// A wake far from the phase checks at T + grace with tick=false.
func TestWakeFarFromPhaseKeepsGrace(t *testing.T) {
	clk := newFakeClock()
	w := newTickWatcher(clk)
	var c counter
	registerAll(w, &c)

	clk.advance(30 * time.Second)
	tick(clk, w, Relay, Management, Signal)

	clk.advance(10*time.Second - Grace - 900*time.Millisecond)
	w.CheckNow()
	w.mu.Lock()
	tickSet := w.tick
	w.mu.Unlock()
	assert.False(t, tickSet, "a wake at P + 10 s is no tick")
	assertCheckAt(t, clk, w, Grace)
	for _, svc := range services {
		assert.Equal(t, 0, c.get(svc), "no stale action: %s", svc)
	}
}
