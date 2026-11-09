package hbwatch

import (
	"strings"
	"sync"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	logtest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeClock is a wall clock moved by hand. advance runs the timers that come
// due, each at its own time. A jump models the phone sleeping: no timer fires
// during the jump, so a timer that came due runs late at the next advance.
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

var t0 = time.Unix(1_800_000_000, 0)

func newFakeClock() *fakeClock {
	return &fakeClock{now: t0}
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

// advanceTo moves the clock to target and runs the timers due by then in
// time order. A timer due in the past (after a jump) runs at the current time.
func (c *fakeClock) advanceTo(target time.Time) {
	for {
		c.mu.Lock()
		idx := -1
		for i, t := range c.timers {
			if t.at.After(target) {
				continue
			}
			if idx < 0 || t.at.Before(c.timers[idx].at) {
				idx = i
			}
		}
		if idx < 0 {
			if target.After(c.now) {
				c.now = target
			}
			c.mu.Unlock()
			return
		}
		t := c.timers[idx]
		c.timers = append(c.timers[:idx], c.timers[idx+1:]...)
		if t.at.After(c.now) {
			c.now = t.at
		}
		c.mu.Unlock()
		t.f()
	}
}

func (c *fakeClock) advance(d time.Duration) {
	c.advanceTo(c.Now().Add(d))
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

// counter counts stale actions (n) and off-burst reconnects (r) per service.
type counter struct {
	mu sync.Mutex
	n  map[Service]int
	r  map[Service]int
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

func (c *counter) get(svc Service) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.n[svc]
}

func (c *counter) reconnects(svc Service) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.r[svc]
}

// total counts every stale action and off-burst reconnect.
func (c *counter) total() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for _, svc := range services {
		n += c.n[svc] + c.r[svc]
	}
	return n
}

func register(w *Watcher, c *counter, svc Service) (unregister func()) {
	return w.Register(svc, ActionReconnect, c.action(svc), c.reconnect(svc))
}

func registerAll(w *Watcher, c *counter) {
	register(w, c, Management)
	register(w, c, Signal)
	register(w, c, Relay)
}

func newTestWatcher(clk *fakeClock) *Watcher {
	return New(clk, 30*time.Second)
}

// captureLogs collects the standard logger entries of one test.
func captureLogs(t *testing.T) *logtest.Hook {
	t.Helper()
	hook := &logtest.Hook{}
	old := log.StandardLogger().ReplaceHooks(log.LevelHooks{})
	log.AddHook(hook)
	t.Cleanup(func() { log.StandardLogger().ReplaceHooks(old) })
	return hook
}

// lines returns the logged messages that start with prefix and contain every
// part.
func lines(h *logtest.Hook, prefix string, parts ...string) []string {
	var out []string
	for _, e := range h.AllEntries() {
		if !strings.HasPrefix(e.Message, prefix) {
			continue
		}
		ok := true
		for _, p := range parts {
			ok = ok && strings.Contains(e.Message, p)
		}
		if ok {
			out = append(out, e.Message)
		}
	}
	return out
}

func setup(t *testing.T) (*fakeClock, *Watcher, *counter, *logtest.Hook) {
	t.Helper()
	h := captureLogs(t)
	clk := newFakeClock()
	w := newTestWatcher(clk)
	c := &counter{}
	registerAll(w, c)
	return clk, w, c, h
}

// tickAt returns the server tick n periods after the start. The client phase
// of the old watcher is 0, so these are its ticks too.
func tickAt(n int) time.Time {
	return t0.Add(time.Duration(n) * 30 * time.Second)
}

type hb struct {
	svc Service
	at  time.Duration
}

// heartbeats delivers each heartbeat at p plus its offset. Offsets must
// ascend.
func heartbeats(clk *fakeClock, w *Watcher, p time.Time, hbs ...hb) {
	for _, h := range hbs {
		clk.advanceTo(p.Add(h.at))
		w.Seen(h.svc)
	}
}

const ms = time.Millisecond

var onTime = []hb{{Management, 0}, {Signal, 300 * ms}, {Relay, 600 * ms}}

// All three heartbeats within 1 s: one check at B + 5 s, no action.
func TestBurstOnTimeOneCheck(t *testing.T) {
	clk, w, c, h := setup(t)
	p := tickAt(1)
	heartbeats(clk, w, p, hb{Management, 0}, hb{Signal, 400 * ms}, hb{Relay, 900 * ms})
	clk.advanceTo(p.Add(BurstDelay - ms))
	assert.Empty(t, lines(h, "hbwatch: check "), "no check before B + 5 s")
	clk.advanceTo(p.Add(BurstDelay))
	assert.Len(t, lines(h, "hbwatch: check ", "trigger=burst", "members=management,signal,relay"), 1,
		"one burst check at B + 5 s")
	clk.advance(20 * time.Second)
	assert.Len(t, lines(h, "hbwatch: check "), 1, "one check for the burst")
	assert.Equal(t, 0, c.total(), "no action")
}

// Relay 4 s after Management and Signal (radio paging, a TCP resend) is
// jitter: it joins the burst.
func TestBurstJitterRelayLate(t *testing.T) {
	clk, w, c, _ := setup(t)
	for n := 1; n <= 3; n++ {
		heartbeats(clk, w, tickAt(n), hb{Management, 0}, hb{Signal, 200 * ms}, hb{Relay, 4 * time.Second})
	}
	clk.advanceTo(tickAt(3).Add(10 * time.Second))
	assert.Equal(t, 0, c.total(), "relay 4 s late is jitter, no action")
}

// All three 4 s late together on every tick (bufferbloat, constant delay):
// one burst per period, no action.
func TestBurstConstantDelay(t *testing.T) {
	clk, w, c, _ := setup(t)
	for n := 1; n <= 10; n++ {
		heartbeats(clk, w, tickAt(n),
			hb{Management, 4 * time.Second}, hb{Signal, 4200 * ms}, hb{Relay, 4500 * ms})
	}
	clk.advanceTo(tickAt(10).Add(10 * time.Second))
	assert.Equal(t, 0, c.total(), "constant delay of all three, no action")
}

// Management 1.8 s early, Signal on time, relay 2.3 s late: one burst.
func TestBurstEarlyHeartbeat(t *testing.T) {
	clk, w, c, _ := setup(t)
	heartbeats(clk, w, tickAt(1), onTime...)
	for n := 2; n <= 3; n++ {
		heartbeats(clk, w, tickAt(n),
			hb{Management, -1800 * ms}, hb{Signal, 0}, hb{Relay, 2300 * ms})
	}
	clk.advanceTo(tickAt(3).Add(10 * time.Second))
	assert.Equal(t, 0, c.total(), "early heartbeat opens the burst, the late one joins it")
}

// A wake 2 s before the burst, then a burst with relay 0.5 s late.
func TestWakeBeforeBurst(t *testing.T) {
	clk, w, c, _ := setup(t)
	heartbeats(clk, w, tickAt(1), onTime...)
	p := tickAt(2)
	clk.advanceTo(p.Add(-2 * time.Second))
	w.CheckNow()
	heartbeats(clk, w, p, hb{Management, 100 * ms}, hb{Signal, 100 * ms}, hb{Relay, 500 * ms})
	clk.advanceTo(p.Add(10 * time.Second))
	assert.Equal(t, 0, c.total(), "no action")
}

// Relay silent for one tick: exactly one relay reconnect at B + 5 s.
func TestBurstRelaySilentOneTick(t *testing.T) {
	clk, w, c, _ := setup(t)
	heartbeats(clk, w, tickAt(1), onTime...)
	p := tickAt(2)
	heartbeats(clk, w, p, hb{Management, 0}, hb{Signal, 300 * ms})
	clk.advanceTo(p.Add(BurstDelay - ms))
	require.Equal(t, 0, c.get(Relay), "no action before B + 5 s")
	clk.advanceTo(p.Add(BurstDelay))
	assert.Equal(t, 1, c.get(Relay), "relay missed the burst, reconnect at B + 5 s")
	heartbeats(clk, w, tickAt(3), onTime...)
	clk.advanceTo(tickAt(3).Add(10 * time.Second))
	assert.Equal(t, 1, c.get(Relay), "exactly one relay action")
	assert.Equal(t, 1, c.total(), "no other action")
}

// A muted service gets one action per tick it misses, at B + 5 s.
func TestBurstMutedServiceOncePerTick(t *testing.T) {
	for _, muted := range services {
		t.Run(string(muted), func(t *testing.T) {
			clk, w, c, _ := setup(t)
			heartbeats(clk, w, tickAt(1), onTime...)
			for n := 2; n <= 4; n++ {
				var hbs []hb
				for _, h := range onTime {
					if h.svc != muted {
						hbs = append(hbs, h)
					}
				}
				heartbeats(clk, w, tickAt(n), hbs...)
				// The burst opens at the first heartbeat that came.
				clk.advanceTo(tickAt(n).Add(hbs[0].at + BurstDelay))
				assert.Equal(t, n-1, c.get(muted), "one action at tick %d", n)
			}
			assert.Equal(t, 3, c.total(), "only the muted service acts")
		})
	}
}

// A stale action blocks a wake action on the same service within the period.
func TestOneActionPerPeriod(t *testing.T) {
	clk, w, c, _ := setup(t)
	heartbeats(clk, w, tickAt(1), onTime...)
	p := tickAt(2)
	heartbeats(clk, w, p, hb{Management, 0}, hb{Signal, 300 * ms})
	clk.advanceTo(p.Add(10 * time.Second))
	w.CheckNow()
	clk.advance(Grace)
	assert.Equal(t, 1, c.get(Relay), "one relay action per period")
}

// Relay 10 s early on one tick only, then back in the burst: no action.
func TestOffBurstOneTickNoAction(t *testing.T) {
	clk, w, c, h := setup(t)
	heartbeats(clk, w, tickAt(1), onTime...)
	heartbeats(clk, w, tickAt(2), hb{Relay, -10 * time.Second}, hb{Management, 0}, hb{Signal, 300 * ms})
	for n := 3; n <= 4; n++ {
		heartbeats(clk, w, tickAt(n), onTime...)
	}
	clk.advanceTo(tickAt(4).Add(10 * time.Second))
	assert.Equal(t, 0, c.total(), "one off-burst tick, no action")
	assert.Len(t, lines(h, "hbwatch: offburst svc=relay off=-10000 confirm=false"), 1, "off-burst logged")
}

// Relay 10 s early on 2 ticks in a row: one reconnect on the second. The new
// connection is back in the burst and is left alone.
func TestOffBurstTwoTicksReconnectsOnce(t *testing.T) {
	clk, w, c, h := setup(t)
	heartbeats(clk, w, tickAt(1), onTime...)
	heartbeats(clk, w, tickAt(2), hb{Relay, -10 * time.Second}, hb{Management, 0}, hb{Signal, 300 * ms})
	heartbeats(clk, w, tickAt(3), hb{Relay, -10 * time.Second})
	clk.advanceTo(tickAt(3).Add(-10*time.Second + BurstDelay - ms))
	require.Equal(t, 0, c.reconnects(Relay), "no reconnect before B + 5 s")
	clk.advanceTo(tickAt(3).Add(-10*time.Second + BurstDelay))
	require.Equal(t, 1, c.reconnects(Relay), "second off-burst tick reconnects relay")
	assert.Len(t, lines(h, "hbwatch: offphase svc=relay off=-10000 action=reconnect"), 1, "offphase logged")

	register(w, c, Relay)
	heartbeats(clk, w, tickAt(3), hb{Management, 0}, hb{Signal, 300 * ms})
	for n := 4; n <= 6; n++ {
		heartbeats(clk, w, tickAt(n), onTime...)
	}
	clk.advanceTo(tickAt(6).Add(10 * time.Second))
	assert.Equal(t, 1, c.reconnects(Relay), "new connection in the burst is not reconnected")
	assert.Equal(t, 1, c.total(), "no other action")
}

// Offsets are taken mod period: a lone burst 15 s off is as far before the
// next burst as after the last one, and two such lone bursts confirm.
func TestOffBurstConfirmWrapsHalfPeriod(t *testing.T) {
	for _, tc := range []struct {
		name          string
		first, second time.Duration
	}{
		{"15s", 15 * time.Second, 15 * time.Second},
		{"-14.8s then 14.9s", 15200 * ms, 14900 * ms},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clk, w, c, _ := setup(t)
			heartbeats(clk, w, tickAt(1), onTime...)
			heartbeats(clk, w, tickAt(1), hb{Relay, tc.first})
			heartbeats(clk, w, tickAt(2), hb{Management, 0}, hb{Signal, 300 * ms}, hb{Relay, tc.second})
			clk.advanceTo(tickAt(2).Add(tc.second + BurstDelay))
			assert.Equal(t, 1, c.reconnects(Relay), "the two offsets confirm")
			assert.Equal(t, 1, c.total(), "no other action")
		})
	}
}

func TestCentered(t *testing.T) {
	p := 30 * time.Second
	assert.Equal(t, 15*time.Second, centered(-15*time.Second, p), "-15 s maps to +15 s")
	assert.Equal(t, time.Duration(0), centered(15*time.Second-(-15*time.Second), p), "+15 s and -15 s are equal")
	assert.Equal(t, -300*ms, centered(29700*ms, p), "29.7 s is 0.3 s before")
	assert.Equal(t, -10*time.Second, centered(20*time.Second, p), "20 s is 10 s before the next")
}

// Relay 10 s early, then 14 s early: the offsets differ by 4 s, no confirm.
func TestOffBurstDifferentOffsetsNoConfirm(t *testing.T) {
	clk, w, c, h := setup(t)
	heartbeats(clk, w, tickAt(1), onTime...)
	heartbeats(clk, w, tickAt(2), hb{Relay, -10 * time.Second}, hb{Management, 0}, hb{Signal, 300 * ms})
	heartbeats(clk, w, tickAt(3), hb{Relay, -14 * time.Second}, hb{Management, 0}, hb{Signal, 300 * ms})
	clk.advanceTo(tickAt(3).Add(10 * time.Second))
	assert.Equal(t, 0, c.total(), "no confirm, no action")
	assert.Len(t, lines(h, "hbwatch: offburst svc=relay", "confirm=false"), 2, "two off-burst lines")
}

// Register clears the stored off-burst offset: the first lone burst of a new
// connection never confirms.
func TestRegisterClearsOffBurst(t *testing.T) {
	clk, w, c, _ := setup(t)
	heartbeats(clk, w, tickAt(1), onTime...)
	heartbeats(clk, w, tickAt(2), hb{Relay, -10 * time.Second}, hb{Management, 0}, hb{Signal, 300 * ms})
	register(w, c, Relay)
	heartbeats(clk, w, tickAt(3), hb{Relay, -10 * time.Second}, hb{Management, 0}, hb{Signal, 300 * ms})
	clk.advanceTo(tickAt(3).Add(10 * time.Second))
	assert.Equal(t, 0, c.total(), "first off-burst tick of the new connection, no action")
}

// relayTickAndWake sends relay alone at tick n and a wake 10 s later.
func relayTickAndWake(clk *fakeClock, w *Watcher, n int) {
	heartbeats(clk, w, tickAt(n), hb{Relay, 600 * ms})
	clk.advanceTo(tickAt(n).Add(10600 * ms))
	w.CheckNow()
	clk.advance(Grace)
}

// Management and Signal muted while relay ticks: every burst is lone and the
// relay sits on the reference burst, so it is not off burst. Management and
// Signal act by the period plus tolerance rule while the gate is open, then
// the gate closes.
func TestLoneBurstsBothMuted(t *testing.T) {
	clk, w, c, h := setup(t)
	heartbeats(clk, w, tickAt(1), onTime...)
	for n := 2; n <= 6; n++ {
		relayTickAndWake(clk, w, n)
	}
	assert.Equal(t, 1, c.get(Management), "management acts once by the period rule")
	assert.Equal(t, 1, c.get(Signal), "signal acts once by the period rule")
	assert.Equal(t, 0, c.get(Relay), "relay sent every heartbeat")
	assert.Equal(t, 0, c.reconnects(Relay), "relay on the reference burst is not off burst")
	assert.Empty(t, lines(h, "hbwatch: offburst"), "no off-burst")
	assert.NotEmpty(t, lines(h, "hbwatch: check ", "gate=closed"), "the gate closes")
}

// No burst with 2 members ever (each service alone): no reference, so no
// off-burst action, and no stale action while the gaps stay under the period
// plus tolerance.
func TestNoReferenceBurstNoOffBurst(t *testing.T) {
	clk, w, c, h := setup(t)
	for n := 0; n <= 5; n++ {
		heartbeats(clk, w, tickAt(n),
			hb{Management, 0}, hb{Signal, 10 * time.Second}, hb{Relay, 20 * time.Second})
	}
	clk.advanceTo(tickAt(5).Add(29 * time.Second))
	assert.Equal(t, 0, c.total(), "no action")
	assert.Empty(t, lines(h, "hbwatch: offburst"), "no reference burst, no off-burst")
	assert.NotEmpty(t, lines(h, "hbwatch: check trigger=lone"), "lone checks ran")
}

// Against a server that sends no test heartbeats (mode off, old server,
// rollback) only the relay health check and wakes arrive. No action.
func TestGateNoTestHeartbeatNoAction(t *testing.T) {
	clk, w, c, _ := setup(t)
	for n := 1; n <= 10; n++ {
		relayTickAndWake(clk, w, n)
	}
	assert.Equal(t, 0, c.total(), "no test heartbeat: no action")
}

// Test heartbeats for 3 periods, then mode off. At most one action per
// service, then nothing for 10 periods.
func TestGateClosesAfterModeOff(t *testing.T) {
	clk, w, c, h := setup(t)
	for n := 1; n <= 3; n++ {
		heartbeats(clk, w, tickAt(n), onTime...)
	}
	clk.advanceTo(tickAt(3).Add(10 * time.Second))
	require.Equal(t, 0, c.total(), "steady ticks")

	relayTickAndWake(clk, w, 4)
	relayTickAndWake(clk, w, 5)
	for _, svc := range services {
		assert.LessOrEqual(t, c.get(svc)+c.reconnects(svc), 1, "at most one action after mode off: %s", svc)
	}
	first := c.total()
	for n := 6; n <= 15; n++ {
		relayTickAndWake(clk, w, n)
	}
	assert.Equal(t, first, c.total(), "no action once the gate is closed")
	assert.NotEmpty(t, lines(h, "hbwatch: check ", "gate=closed"), "checks log the closed gate")
}

// The phone sleeps past the burst timer and the next burst opens before the
// old check ran. The old check is closed without action; the new burst acts
// on the missing service.
func TestLateCheckSkippedByNewBurst(t *testing.T) {
	clk, w, c, h := setup(t)
	heartbeats(clk, w, tickAt(1), onTime...)
	heartbeats(clk, w, tickAt(2), onTime...)
	clk.jump(tickAt(3).Sub(clk.Now()))
	// Seen before any advance: the old timer has not run yet.
	w.Seen(Management)
	heartbeats(clk, w, tickAt(3), hb{Signal, 300 * ms})
	assert.Len(t, lines(h, "hbwatch: check ", "skipped=late"), 1, "old check skipped")
	clk.advanceTo(tickAt(3).Add(BurstDelay))
	assert.Equal(t, 1, c.get(Relay), "new burst acts on the missing relay")
	assert.Equal(t, 1, c.total(), "no other action")
}

// A burst check that runs over 1 s after B + 5 s logs late=.
func TestLateCheckLogsLate(t *testing.T) {
	clk, w, c, h := setup(t)
	heartbeats(clk, w, tickAt(1), onTime...)
	clk.jump(tickAt(1).Add(25 * time.Second).Sub(clk.Now()))
	clk.advance(0)
	assert.Len(t, lines(h, "hbwatch: check trigger=burst", "wait=25000", "late=20000"), 1, "late check logged")
	assert.Equal(t, 0, c.total(), "no action")
}

// Wakes between bursts check at T + 2 s with the period plus tolerance rule,
// measured at the wake.
func TestWakeBetweenBursts(t *testing.T) {
	clk, w, c, h := setup(t)
	heartbeats(clk, w, tickAt(1), onTime...)
	clk.advanceTo(tickAt(1).Add(18 * time.Second))
	w.CheckNow()
	clk.advance(Grace - ms)
	require.Empty(t, lines(h, "hbwatch: check trigger=wake"), "no wake check before T + 2 s")
	clk.advance(ms)
	require.Len(t, lines(h, "hbwatch: check trigger=wake", "wait=2000"), 1, "wake check at T + 2 s")
	assert.Equal(t, 0, c.total(), "18 s gaps are not stale")

	// All three silent at tick 2: a wake at P1 + 40 s sees gaps over 33 s.
	clk.advanceTo(tickAt(1).Add(40 * time.Second))
	w.CheckNow()
	clk.advance(Grace)
	for _, svc := range services {
		assert.Equal(t, 1, c.get(svc), "silent for 40 s: %s", svc)
	}
}

// A wake check that fires while a burst is open is skipped.
func TestWakeSkippedWhileBurstOpen(t *testing.T) {
	clk, w, c, h := setup(t)
	p := tickAt(1)
	heartbeats(clk, w, p, hb{Management, 0})
	clk.advanceTo(p.Add(time.Second))
	w.CheckNow()
	heartbeats(clk, w, p, hb{Signal, 1500 * ms}, hb{Relay, 2 * time.Second})
	clk.advanceTo(p.Add(10 * time.Second))
	assert.Len(t, lines(h, "hbwatch: check trigger=wake", "skipped=burst"), 1, "wake check skipped")
	assert.Len(t, lines(h, "hbwatch: check trigger=burst"), 1, "burst check ran")
	assert.Equal(t, 0, c.total(), "no action")
}

// NB_TEST_HB_BURST_DELAY_MS moves the check.
func TestBurstDelayFromEnv(t *testing.T) {
	t.Setenv(envBurstDelay, "3000")
	clk, w, c, _ := setup(t)
	heartbeats(clk, w, tickAt(1), onTime...)
	p := tickAt(2)
	heartbeats(clk, w, p, hb{Management, 0}, hb{Signal, 300 * ms})
	clk.advanceTo(p.Add(3*time.Second - ms))
	require.Equal(t, 0, c.get(Relay), "no action before B + 3 s")
	clk.advanceTo(p.Add(3 * time.Second))
	assert.Equal(t, 1, c.get(Relay), "check at B + 3 s")

	t.Setenv(envBurstDelay, "x")
	assert.Equal(t, BurstDelay, burstDelayFromEnv(), "unparsable keeps default")
	t.Setenv(envBurstDelay, "")
	assert.Equal(t, BurstDelay, burstDelayFromEnv(), "unset keeps default")
}

// After a sleep the monotonic timers have not run, but the first burst must
// see the real wall gap and act on the streams that stayed silent.
func TestWallGapSeenAtOnceAfterSleep(t *testing.T) {
	clk, w, c, _ := setup(t)

	clk.jump(100 * time.Second)
	w.Seen(Management)
	clk.advance(BurstDelay)

	assert.Equal(t, 0, c.get(Management), "management just sent a heartbeat")
	assert.Equal(t, 1, c.get(Signal), "signal silent for 100 s must fire its action")
	assert.Equal(t, 1, c.get(Relay), "relay silent for 100 s must fire its action")
}

// Only connected services are checked. A stale unregister from an old stream
// must not drop the registration of the new stream.
func TestUnregisterOnlyRemovesOwnRegistration(t *testing.T) {
	captureLogs(t)
	clk := newFakeClock()
	w := newTestWatcher(clk)
	var c counter

	oldUnregister := register(w, &c, Relay)
	newUnregister := register(w, &c, Relay)
	oldUnregister()

	clk.jump(60 * time.Second)
	w.Seen(Management)
	w.CheckNow()
	clk.advance(BurstDelay)
	assert.Equal(t, 1, c.get(Relay), "the newer registration must stay active")

	newUnregister()
	clk.jump(60 * time.Second)
	w.Seen(Management)
	w.CheckNow()
	clk.advance(BurstDelay)
	assert.Equal(t, 1, c.get(Relay), "an unregistered service is not checked")
}

// The Swift wake can call CheckNow before the engine runs and after it stops.
func TestCheckNowWithoutServicesIsNoop(t *testing.T) {
	clk := newFakeClock()
	w := newTestWatcher(clk)
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
