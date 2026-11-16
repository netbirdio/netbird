package hbwatch

import (
	"strings"
	"sync"
	"sync/atomic"
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

// counter counts stale actions (n) and records phase corrections (r) per
// service.
type counter struct {
	mu sync.Mutex
	n  map[Service]int
	r  map[Service][]time.Duration
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

func (c *counter) correct(svc Service) func(time.Duration) {
	return func(phase time.Duration) {
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.r == nil {
			c.r = map[Service][]time.Duration{}
		}
		c.r[svc] = append(c.r[svc], phase)
	}
}

func (c *counter) get(svc Service) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.n[svc]
}

// corrections returns the phases asked for svc.
func (c *counter) corrections(svc Service) []time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]time.Duration(nil), c.r[svc]...)
}

// total counts every stale action.
func (c *counter) total() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for _, svc := range services {
		n += c.n[svc]
	}
	return n
}

func register(w *Watcher, c *counter, svc Service) (unregister func()) {
	return w.Register(svc, Registration{Kind: ActionReconnect, Stale: c.action(svc), Correct: c.correct(svc)})
}

// registerReconnecting registers svc with a stale action that counts and then
// registers svc again, like a stream that reconnects.
func registerReconnecting(w *Watcher, c *counter, svc Service) {
	count := c.action(svc)
	w.Register(svc, Registration{Kind: ActionReconnect, Stale: func() {
		count()
		registerReconnecting(w, c, svc)
	}})
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
	level := log.GetLevel()
	log.SetLevel(log.DebugLevel)
	log.AddHook(hook)
	t.Cleanup(func() {
		log.SetLevel(level)
		log.StandardLogger().ReplaceHooks(old)
	})
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

const testPeriod = 30 * time.Second

// beat is a heartbeat of the test period on phase 0.
var beat = Heartbeat{Period: testPeriod}

// heartbeats delivers each heartbeat at p plus its offset. Offsets must
// ascend.
func heartbeats(clk *fakeClock, w *Watcher, p time.Time, hbs ...hb) {
	for _, h := range hbs {
		clk.advanceTo(p.Add(h.at))
		w.Seen(h.svc, beat)
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

// Relay silent for one tick is not stale yet: its gap is one period, inside
// the receive timeout. The second missed tick acts, exactly once.
func TestBurstRelaySilentTwoTicks(t *testing.T) {
	clk, w, c, _ := setup(t)
	heartbeats(clk, w, tickAt(1), onTime...)
	heartbeats(clk, w, tickAt(2), hb{Management, 0}, hb{Signal, 300 * ms})
	clk.advanceTo(tickAt(2).Add(BurstDelay))
	require.Equal(t, 0, c.get(Relay), "one missed tick is inside period plus margin")
	p := tickAt(3)
	heartbeats(clk, w, p, hb{Management, 0}, hb{Signal, 300 * ms})
	clk.advanceTo(p.Add(BurstDelay - ms))
	require.Equal(t, 0, c.get(Relay), "no action before B + 5 s")
	clk.advanceTo(p.Add(BurstDelay))
	assert.Equal(t, 1, c.get(Relay), "relay silent past period plus margin, reconnect at B + 5 s")
	heartbeats(clk, w, tickAt(4), onTime...)
	clk.advanceTo(tickAt(4).Add(10 * time.Second))
	assert.Equal(t, 1, c.get(Relay), "exactly one relay action")
	assert.Equal(t, 1, c.total(), "no other action")
}

// A muted service acts from the second tick it misses on, once per tick, at
// B + 5 s.
func TestBurstMutedServiceOncePerTick(t *testing.T) {
	for _, muted := range services {
		t.Run(string(muted), func(t *testing.T) {
			clk, w, c, _ := setup(t)
			heartbeats(clk, w, tickAt(1), onTime...)
			for n := 2; n <= 5; n++ {
				var hbs []hb
				for _, h := range onTime {
					if h.svc != muted {
						hbs = append(hbs, h)
					}
				}
				heartbeats(clk, w, tickAt(n), hbs...)
				// The burst opens at the first heartbeat that came.
				clk.advanceTo(tickAt(n).Add(hbs[0].at + BurstDelay))
				assert.Equal(t, max(n-2, 0), c.get(muted), "actions at tick %d", n)
			}
			assert.Equal(t, 3, c.total(), "only the muted service acts")
		})
	}
}

// A stale action blocks a wake action on the same service within the period.
func TestOneActionPerPeriod(t *testing.T) {
	clk, w, c, _ := setup(t)
	heartbeats(clk, w, tickAt(1), onTime...)
	heartbeats(clk, w, tickAt(2), hb{Management, 0}, hb{Signal, 300 * ms})
	p := tickAt(3)
	heartbeats(clk, w, p, hb{Management, 0}, hb{Signal, 300 * ms})
	clk.advanceTo(p.Add(BurstDelay))
	require.Equal(t, 1, c.get(Relay), "relay acts at the second missed tick")
	clk.advanceTo(p.Add(10 * time.Second))
	w.CheckNow()
	clk.advance(Grace)
	assert.Equal(t, 1, c.get(Relay), "one relay action per period")
}

// A stream that lands off phase, later than the burst delay, still arrives
// within its period. It is not stale: the phase correction moves it instead.
func TestOffPhaseStreamNotStale(t *testing.T) {
	clk, w, c, _ := setup(t)
	for n := 1; n <= 5; n++ {
		heartbeats(clk, w, tickAt(n), hb{Management, 0}, hb{Relay, 300 * ms}, hb{Signal, 12 * time.Second})
	}
	clk.advanceTo(tickAt(5).Add(20 * time.Second))
	assert.Equal(t, 0, c.total(), "an off-phase stream must not be reconnected")
	assert.NotEmpty(t, c.corrections(Signal), "the off-phase stream must be corrected")
}

// A heartbeat or frame from another connection of the service, such as a relay
// connection to a peer's home relay, does not keep the registered one alive.
func TestForeignStreamDoesNotHideStale(t *testing.T) {
	clk := newFakeClock()
	w := newTestWatcher(clk)
	c := &counter{}
	register(w, c, Management)
	register(w, c, Signal)
	registered, foreign := new(int), new(int)
	w.Register(Relay, Registration{Kind: ActionReconnect, Stale: c.action(Relay), Stream: registered})

	at := func(n int, off time.Duration) {
		clk.advanceTo(tickAt(n).Add(off))
	}
	at(1, 0)
	w.Seen(Management, beat)
	w.Seen(Signal, beat)
	w.Seen(Relay, Heartbeat{Period: testPeriod, Stream: registered})
	for n := 2; n <= 3; n++ {
		at(n, 0)
		w.Seen(Management, beat)
		w.Seen(Signal, beat)
		at(n, 300*ms)
		w.Seen(Relay, Heartbeat{Period: testPeriod, Stream: foreign})
		w.TouchStream(Relay, foreign)
	}
	at(3, BurstDelay+ms)
	assert.Equal(t, 1, c.get(Relay), "only the registered relay connection counts")
	assert.Equal(t, 1, c.total(), "no other action")
}

// Two relay clients of one server pick: the winner registers, a losing
// candidate registers after it and closes. The winner takes the slot back and
// keeps the stale check, the phase correction and the retry gate count.
func TestRelayLoserCloseRestoresWinner(t *testing.T) {
	clk := newFakeClock()
	w := newTestWatcher(clk)
	c := &counter{}
	register(w, c, Management)
	register(w, c, Signal)
	winner, loser := new(int), new(int)
	unregWinner := w.Register(Relay, Registration{
		Kind: ActionReconnect, Stale: c.action(Relay), Correct: c.correct(Relay), Stream: winner, Addr: "rel://winner",
	})
	unregLoser := w.Register(Relay, Registration{
		Kind: ActionReconnect, Stale: func() { t.Error("the closed loser must not act") }, Stream: loser, Addr: "rel://loser",
	})

	clk.advanceTo(tickAt(1))
	w.Seen(Management, beat)
	w.Seen(Signal, beat)
	w.Seen(Relay, Heartbeat{Period: testPeriod, Stream: winner})
	unregLoser()

	s := w.svcs[Relay]
	require.True(t, s.registered, "the slot must not stay empty")
	assert.Same(t, winner, s.reg.Stream, "the winner holds the slot again")
	assert.NotNil(t, s.reg.Correct, "the winner keeps its phase correction")
	assert.True(t, s.ticks(clk.Now()), "the winner counts as ticking for the retry gate")
	assert.Empty(t, w.others, "the winner left the replaced streams")
	snap := w.Snapshot()
	var relays []string
	for _, st := range snap.Streams {
		if st.Service == Relay {
			relays = append(relays, st.Addr)
		}
	}
	assert.Equal(t, []string{"rel://winner"}, relays, "the status shows the winner once")

	for n := 2; n <= 3; n++ {
		clk.advanceTo(tickAt(n))
		w.Seen(Management, beat)
		w.Seen(Signal, beat)
	}
	clk.advanceTo(tickAt(3).Add(BurstDelay + ms))
	assert.Equal(t, 1, c.get(Relay), "the silent winner is found stale")

	unregWinner()
	assert.False(t, s.registered, "the winner close empties the slot")
}

// A loser that registered before the winner closes while the winner holds
// the slot: the slot stays with the winner.
func TestRelayEarlierLoserCloseKeepsWinner(t *testing.T) {
	clk := newFakeClock()
	w := newTestWatcher(clk)
	winner, loser := new(int), new(int)
	unregLoser := w.Register(Relay, Registration{Stale: func() {}, Stream: loser})
	w.Register(Relay, Registration{Stale: func() {}, Stream: winner})
	unregLoser()

	s := w.svcs[Relay]
	assert.Same(t, winner, s.reg.Stream, "the winner keeps the slot")
	assert.Empty(t, w.others, "the closed loser left the replaced streams")
}

// A relay connection busy with relayed frames is alive even when its
// heartbeats stop. The frames only move a counter; the watcher reads it at
// heartbeats and checks. Once the frames stop too, the stream is stale.
func TestRelayBusyFramesNotStale(t *testing.T) {
	clk := newFakeClock()
	w := newTestWatcher(clk)
	c := &counter{}
	register(w, c, Management)
	register(w, c, Signal)
	var frames atomic.Uint64
	relay := new(int)
	w.Register(Relay, Registration{Kind: ActionReconnect, Stale: c.action(Relay), Stream: relay, Frames: frames.Load})

	clk.advanceTo(tickAt(1))
	w.Seen(Management, beat)
	w.Seen(Signal, beat)
	w.Seen(Relay, Heartbeat{Period: testPeriod, Stream: relay})
	for n := 2; n <= 5; n++ {
		clk.advanceTo(tickAt(n).Add(-10 * time.Second))
		frames.Add(100)
		clk.advanceTo(tickAt(n))
		w.Seen(Management, beat)
		w.Seen(Signal, beat)
	}
	clk.advanceTo(tickAt(5).Add(BurstDelay + ms))
	assert.Zero(t, c.get(Relay), "a relay connection that carries frames must not be judged stale")

	clk.advanceTo(tickAt(6))
	w.Seen(Management, beat)
	w.Seen(Signal, beat)
	clk.advanceTo(tickAt(6).Add(BurstDelay + ms))
	assert.Equal(t, 1, c.get(Relay), "without frames and heartbeats the relay is stale at the next check")
}

func TestCentered(t *testing.T) {
	p := 30 * time.Second
	assert.Equal(t, 15*time.Second, centered(-15*time.Second, p), "-15 s maps to +15 s")
	assert.Equal(t, time.Duration(0), centered(15*time.Second-(-15*time.Second), p), "+15 s and -15 s are equal")
	assert.Equal(t, -300*ms, centered(29700*ms, p), "29.7 s is 0.3 s before")
	assert.Equal(t, -10*time.Second, centered(20*time.Second, p), "20 s is 10 s before the next")
}

// relayTickAndWake sends relay alone at tick n and a wake 10 s later.
func relayTickAndWake(clk *fakeClock, w *Watcher, n int) {
	heartbeats(clk, w, tickAt(n), hb{Relay, 600 * ms})
	clk.advanceTo(tickAt(n).Add(10600 * ms))
	w.CheckNow()
	clk.advance(Grace)
}

// Management and Signal muted while relay ticks: each acts once by the period
// plus tolerance rule. The new streams sent no heartbeat yet, so they are not
// checked again.
func TestLoneBurstsBothMuted(t *testing.T) {
	captureLogs(t)
	clk := newFakeClock()
	w := newTestWatcher(clk)
	c := &counter{}
	registerReconnecting(w, c, Management)
	registerReconnecting(w, c, Signal)
	registerReconnecting(w, c, Relay)
	heartbeats(clk, w, tickAt(1), onTime...)
	for n := 2; n <= 8; n++ {
		relayTickAndWake(clk, w, n)
	}
	assert.Equal(t, 1, c.get(Management), "management acts once")
	assert.Equal(t, 1, c.get(Signal), "signal acts once")
	assert.Equal(t, 0, c.get(Relay), "relay sent every heartbeat")
}

// No burst with 2 members ever (each service alone): no stale action while the
// gaps stay under the period plus tolerance.
func TestNoReferenceBurstNoAction(t *testing.T) {
	clk, w, c, h := setup(t)
	for n := 0; n <= 5; n++ {
		heartbeats(clk, w, tickAt(n),
			hb{Management, 0}, hb{Signal, 10 * time.Second}, hb{Relay, 20 * time.Second})
	}
	clk.advanceTo(tickAt(5).Add(29 * time.Second))
	assert.Equal(t, 0, c.total(), "no action")
	assert.NotEmpty(t, lines(h, "hbwatch: check trigger=lone"), "lone checks ran")
}

// A stream that never sent a heartbeat is stock (old server, server without
// the feature): only frames and wakes arrive, and it is never acted on.
func TestStockStreamsNoAction(t *testing.T) {
	clk, w, c, h := setup(t)
	for n := 1; n <= 10; n++ {
		clk.advanceTo(tickAt(n))
		w.Touch(Relay)
		clk.advanceTo(tickAt(n).Add(10 * time.Second))
		w.CheckNow()
		clk.advance(Grace)
	}
	assert.Equal(t, 0, c.total(), "no heartbeat on any stream: no action")
	assert.NotEmpty(t, lines(h, "hbwatch: check trigger=wake", "gaps=management:-1,signal:-1,relay:-1"),
		"stock streams are not checked")
}

// Heartbeats for 3 periods, then the server restarts without the feature: each
// stream acts once, and its new stock stream is left alone.
func TestServerBackToStockActsOnce(t *testing.T) {
	captureLogs(t)
	clk := newFakeClock()
	w := newTestWatcher(clk)
	c := &counter{}
	for _, svc := range services {
		registerReconnecting(w, c, svc)
	}
	for n := 1; n <= 3; n++ {
		heartbeats(clk, w, tickAt(n), onTime...)
	}
	for n := 4; n <= 15; n++ {
		clk.advanceTo(tickAt(n).Add(10 * time.Second))
		w.CheckNow()
		clk.advance(Grace)
	}
	for _, svc := range services {
		assert.Equal(t, 1, c.get(svc), "one action, then the stock stream is not checked: %s", svc)
	}
}

// The phone sleeps past the burst timer and the next burst opens before the
// old check ran. The old burst was full, so its late check finds nothing; the
// later bursts act on the missing service once it is silent past the timeout.
func TestLateCheckJudgedByNextBurst(t *testing.T) {
	clk, w, c, h := setup(t)
	heartbeats(clk, w, tickAt(1), onTime...)
	heartbeats(clk, w, tickAt(2), onTime...)
	clk.jump(tickAt(3).Sub(clk.Now()))
	// Seen before any advance: the old timer has not run yet.
	w.Seen(Management, beat)
	assert.Len(t, lines(h, "hbwatch: check trigger=burst", "members=management,signal,relay", "late="), 1,
		"old burst judged late by the next heartbeat")
	assert.Empty(t, lines(h, "hbwatch: check ", "skipped=late"), "no burst is dropped unjudged")
	assert.Equal(t, 0, c.total(), "full old burst, no action")
	heartbeats(clk, w, tickAt(3), hb{Signal, 300 * ms})
	clk.advanceTo(tickAt(3).Add(BurstDelay))
	assert.Equal(t, 0, c.total(), "relay missed one tick, inside the timeout")
	heartbeats(clk, w, tickAt(4), hb{Management, 0}, hb{Signal, 300 * ms})
	clk.advanceTo(tickAt(4).Add(BurstDelay))
	assert.Equal(t, 1, c.get(Relay), "the next burst acts on the silent relay")
	assert.Equal(t, 1, c.total(), "no other action")
}

// sleepTick delivers Management and Signal at tick n on a phone that woke for
// them and sleeps again before any timer runs.
func sleepTick(clk *fakeClock, w *Watcher, n int) {
	clk.jump(tickAt(n).Sub(clk.Now()))
	w.Seen(Management, beat)
	clk.jump(300 * ms)
	w.Seen(Signal, beat)
}

// levelOf returns the levels of the logged messages that start with prefix.
func levelOf(h *logtest.Hook, prefix string) []log.Level {
	var out []log.Level
	for _, e := range h.AllEntries() {
		if strings.HasPrefix(e.Message, prefix) {
			out = append(out, e.Level)
		}
	}
	return out
}

// The check that runs on every tick logs at Debug, so routine operation adds
// no Info lines. A stale stream is a state change and stays at Info.
func TestTickCheckLogsDebugStaleInfo(t *testing.T) {
	clk, w, _, h := setup(t)
	heartbeats(clk, w, tickAt(1), onTime...)
	for n := 2; n <= 4; n++ {
		sleepTick(clk, w, n)
	}
	checks := levelOf(h, "hbwatch: check ")
	require.NotEmpty(t, checks, "checks ran")
	for _, l := range checks {
		assert.Equal(t, log.DebugLevel, l, "the routine check logs at Debug")
	}
	stale := levelOf(h, "hbwatch: stale ")
	require.NotEmpty(t, stale, "the silent relay is found stale")
	for _, l := range stale {
		assert.Equal(t, log.InfoLevel, l, "a stale stream logs at Info")
	}
}

// Relay goes silent while the phone sleeps before every burst check. Each tick
// judges the last burst, so the relay acts once per tick from the burst where
// its gap first passed the timeout.
func TestSleepSilentStreamFoundAtNextTick(t *testing.T) {
	clk, w, c, h := setup(t)
	heartbeats(clk, w, tickAt(1), onTime...)
	sleepTick(clk, w, 2)
	sleepTick(clk, w, 3)
	require.Equal(t, 0, c.total(), "the burst of tick 2 had a gap of one period")
	for n := 4; n <= 6; n++ {
		sleepTick(clk, w, n)
		assert.Equal(t, n-3, c.get(Relay), "relay acts at tick %d for the burst before", n)
	}
	assert.Len(t, lines(h, "hbwatch: stale svc=relay"), 3, "one stale line per tick")
	assert.Equal(t, 0, c.get(Management), "management sent every heartbeat")
	assert.Equal(t, 0, c.get(Signal), "signal sent every heartbeat")
	// The phone stays awake: the timers left over from the sleeps add nothing.
	clk.advance(BurstDelay - ms)
	assert.Equal(t, 3, c.get(Relay), "one action per period")
}

// A heartbeat that comes after the burst delay, on a phone that slept in
// between, settles the burst it missed. Its own arrival shows it is alive.
func TestSleepLateHeartbeatNotStale(t *testing.T) {
	for _, late := range []time.Duration{5500 * ms, 7 * time.Second} {
		clk, w, c, _ := setup(t)
		heartbeats(clk, w, tickAt(1), onTime...)
		sleepTick(clk, w, 2)
		clk.jump(tickAt(2).Add(late).Sub(clk.Now()))
		w.Seen(Relay, beat)
		assert.Equal(t, 0, c.total(), "relay %s late is alive, no action", late)
		clk.advance(BurstDelay)
		assert.Equal(t, 0, c.total(), "relay %s late, no action after the burst delay", late)
	}
}

// The phone sleeps before the grace of a wake. The next wake replaces it: the
// check waits the grace again and measures at the new wake.
func TestWakeAfterSleepUsesNewestWake(t *testing.T) {
	clk, w, c, h := setup(t)
	heartbeats(clk, w, tickAt(1), onTime...)
	clk.advanceTo(tickAt(1).Add(18 * time.Second))
	w.CheckNow()
	// Asleep before the grace; every stream goes silent.
	clk.jump(32 * time.Second)
	w.CheckNow()
	clk.advance(0)
	require.Empty(t, lines(h, "hbwatch: check trigger=wake"), "the timer of the old wake does not check")
	require.Equal(t, 0, c.total(), "no action inside the grace of the new wake")
	clk.advance(Grace)
	assert.Len(t, lines(h, "hbwatch: check trigger=wake", "wait=2000"), 1, "one check, at the new wake + 2 s")
	for _, svc := range services {
		assert.Equal(t, 1, c.get(svc), "silent for 50 s at the new wake: %s", svc)
	}
}

// The phone sleeps before the burst check and every stream dies. A wake with
// no heartbeat finds the old burst still open; it does not cover the wake.
func TestWakeSettlesOverdueBurst(t *testing.T) {
	clk, w, c, h := setup(t)
	heartbeats(clk, w, tickAt(1), onTime...)
	clk.jump(50 * time.Second)
	w.CheckNow()
	clk.jump(Grace)
	// The wake timer runs before the burst timer, which still has time left.
	w.checkWake()
	assert.Len(t, lines(h, "hbwatch: check trigger=burst", "late="), 1, "old burst judged at the wake")
	assert.Empty(t, lines(h, "hbwatch: check trigger=wake", "skipped=burst"), "old burst does not cover the wake")
	for _, svc := range services {
		assert.Equal(t, 1, c.get(svc), "silent for 50 s at the wake: %s", svc)
	}
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

// Wakes between bursts check at T + 2 s with the receive timeout rule,
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

	// All three silent at tick 2: a wake at P1 + 38 s sees gaps under 40 s.
	clk.advanceTo(tickAt(1).Add(38 * time.Second))
	w.CheckNow()
	clk.advance(Grace)
	assert.Equal(t, 0, c.total(), "gaps inside period plus margin are not stale")

	// A wake at P1 + 45 s sees gaps over 40 s.
	clk.advanceTo(tickAt(1).Add(45 * time.Second))
	w.CheckNow()
	clk.advance(Grace)
	for _, svc := range services {
		assert.Equal(t, 1, c.get(svc), "silent for 45 s: %s", svc)
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

// After a sleep the monotonic timers have not run, but the first burst must
// see the real wall gap and act on the streams that stayed silent.
func TestWallGapSeenAtOnceAfterSleep(t *testing.T) {
	clk, w, c, _ := setup(t)
	heartbeats(clk, w, tickAt(1), onTime...)

	clk.jump(100 * time.Second)
	w.Seen(Management, beat)
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
	w.Seen(Relay, beat)

	clk.jump(60 * time.Second)
	w.Seen(Management, beat)
	w.CheckNow()
	clk.advance(BurstDelay)
	assert.Equal(t, 1, c.get(Relay), "the newer registration must stay active")

	newUnregister()
	clk.jump(60 * time.Second)
	w.Seen(Management, beat)
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
