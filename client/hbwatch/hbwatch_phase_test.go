package hbwatch

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// phaseBeat is one heartbeat of a phase correction test: svc at the tick plus
// at, sent on phase.
type phaseBeat struct {
	svc   Service
	at    time.Duration
	phase time.Duration
}

func phaseTick(clk *fakeClock, w *Watcher, n int, beats ...phaseBeat) {
	for _, b := range beats {
		clk.advanceTo(tickAt(n).Add(b.at))
		w.Seen(b.svc, Heartbeat{Period: testPeriod, Phase: b.phase})
	}
}

func mgmt(at time.Duration) phaseBeat { return phaseBeat{svc: Management, at: at} }

// newPhaseWatcher returns a watcher with stale checks off, as on a release
// build, and every service registered.
func newPhaseWatcher(t *testing.T) (*fakeClock, *Watcher, *counter) {
	t.Helper()
	captureLogs(t)
	clk := newFakeClock()
	w := newTestWatcher(clk)
	w.staleOn = func() bool { return false }
	c := &counter{}
	registerAll(w, c)
	return clk, w, c
}

// Signal lands 3 s after Management on two ticks in a row: one correction on
// the second, to the phase that moves it onto Management.
func TestPhaseCorrectionAfterTwoTicks(t *testing.T) {
	clk, w, c := newPhaseWatcher(t)
	h := captureLogs(t)
	signal := phaseBeat{Signal, 3 * time.Second, 5 * time.Second}
	phaseTick(clk, w, 1, mgmt(0), signal)
	phaseTick(clk, w, 2, mgmt(0), signal)
	assert.Empty(t, c.corrections(Signal), "first off tick after the reference only records the offset")
	phaseTick(clk, w, 3, mgmt(0), signal)
	assert.Equal(t, []time.Duration{2 * time.Second}, c.corrections(Signal), "phase 5 s minus offset 3 s")
	assert.Len(t, lines(h, "hbwatch: correct svc=signal off=3000 phase=5000 wanted=2000"), 1, "correction logged")

	// The server moved: Signal now lands with Management.
	for n := 4; n <= 8; n++ {
		phaseTick(clk, w, n, mgmt(0), phaseBeat{Signal, 100 * ms, 2 * time.Second})
	}
	assert.Len(t, c.corrections(Signal), 1, "an aligned stream is left alone")
	assert.Empty(t, c.corrections(Relay), "relay never ticked")
}

// One delayed heartbeat (a TCP resend, a paging delay) causes no correction.
func TestPhaseOneDelayedHeartbeatNoCorrection(t *testing.T) {
	clk, w, c := newPhaseWatcher(t)
	for n := 1; n <= 6; n++ {
		at := 200 * ms
		if n == 3 {
			at = 4 * time.Second
		}
		phaseTick(clk, w, n, mgmt(0), phaseBeat{svc: Relay, at: at})
	}
	assert.Empty(t, c.corrections(Relay), "one late heartbeat is not a wrong phase")
}

// Offsets of two ticks that differ by more than the match window are jitter.
func TestPhaseDifferentOffsetsNoCorrection(t *testing.T) {
	clk, w, c := newPhaseWatcher(t)
	phaseTick(clk, w, 1, mgmt(0))
	phaseTick(clk, w, 2, mgmt(0), phaseBeat{svc: Relay, at: 3 * time.Second})
	phaseTick(clk, w, 3, mgmt(0), phaseBeat{svc: Relay, at: 4 * time.Second})
	phaseTick(clk, w, 4, mgmt(0), phaseBeat{svc: Relay, at: 2 * time.Second})
	assert.Empty(t, c.corrections(Relay), "offsets 1 s apart do not confirm")
}

// An offset up to CorrectThreshold is left alone.
func TestPhaseSmallOffsetNoCorrection(t *testing.T) {
	clk, w, c := newPhaseWatcher(t)
	for n := 1; n <= 5; n++ {
		phaseTick(clk, w, n, mgmt(0), phaseBeat{svc: Signal, at: CorrectThreshold})
	}
	assert.Empty(t, c.corrections(Signal), "1 s off is inside the threshold")
}

// A stream that lands before Management (the server ticks early) is moved later.
// The wanted phase wraps inside the period.
func TestPhaseEarlyStreamWraps(t *testing.T) {
	clk, w, c := newPhaseWatcher(t)
	relay := phaseBeat{Relay, -10 * time.Second, 25 * time.Second}
	phaseTick(clk, w, 1, mgmt(0))
	phaseTick(clk, w, 2, relay, mgmt(0))
	phaseTick(clk, w, 3, relay, mgmt(0))
	assert.Empty(t, c.corrections(Relay), "tick 2 had no reference yet, tick 3 records the offset")
	phaseTick(clk, w, 4, relay, mgmt(0))
	assert.Equal(t, []time.Duration{5 * time.Second}, c.corrections(Relay), "25 s plus 10 s wraps to 5 s")
}

// A Management heartbeat that does not land at its previous arrival plus the
// period is no reference: the streams of that tick are not judged.
func TestPhaseLateReferenceSkipped(t *testing.T) {
	clk, w, c := newPhaseWatcher(t)
	signal := phaseBeat{svc: Signal, at: 3500 * ms}
	phaseTick(clk, w, 1, mgmt(0))
	phaseTick(clk, w, 2, mgmt(0), signal)
	// Management 2 s late: Signal is only 1.5 s after it, but the tick is skipped.
	phaseTick(clk, w, 3, mgmt(2*time.Second), signal)
	assert.Empty(t, c.corrections(Signal), "tick 3 has no reference")
	// Tick 4: Management back on time, but 2 s early against the late one.
	phaseTick(clk, w, 4, mgmt(0), signal)
	assert.Empty(t, c.corrections(Signal), "tick 4 has no reference either")
	phaseTick(clk, w, 5, mgmt(0), signal)
	assert.Empty(t, c.corrections(Signal), "tick 5 is the first off tick after the gap")
	phaseTick(clk, w, 6, mgmt(0), signal)
	assert.Len(t, c.corrections(Signal), 1, "two good ticks in a row correct")
}

// While Management is gone the streams keep their phase.
func TestPhaseFrozenWithoutManagement(t *testing.T) {
	clk, w, c := newPhaseWatcher(t)
	phaseTick(clk, w, 1, mgmt(0))
	phaseTick(clk, w, 2, mgmt(0))
	for n := 3; n <= 8; n++ {
		phaseTick(clk, w, n, phaseBeat{svc: Signal, at: 5 * time.Second}, phaseBeat{svc: Relay, at: 7 * time.Second})
	}
	assert.Empty(t, c.corrections(Signal), "no correction without Management")
	assert.Empty(t, c.corrections(Relay), "no correction without Management")

	// Management back on a new stream: it needs two heartbeats for a reference.
	register(w, c, Management)
	phaseTick(clk, w, 9, mgmt(0), phaseBeat{svc: Signal, at: 5 * time.Second})
	phaseTick(clk, w, 10, mgmt(0), phaseBeat{svc: Signal, at: 5 * time.Second})
	phaseTick(clk, w, 11, mgmt(0), phaseBeat{svc: Signal, at: 5 * time.Second})
	assert.Len(t, c.corrections(Signal), 1, "corrections resume after two good ticks")
}

// A new stream starts with no recorded offset.
func TestPhaseRegisterClearsOffset(t *testing.T) {
	clk, w, c := newPhaseWatcher(t)
	signal := phaseBeat{svc: Signal, at: 3 * time.Second}
	phaseTick(clk, w, 1, mgmt(0))
	phaseTick(clk, w, 2, mgmt(0), signal)
	register(w, c, Signal)
	phaseTick(clk, w, 3, mgmt(0), signal)
	assert.Empty(t, c.corrections(Signal), "first off tick of the new stream")
}

// A stream on another period than Management cannot be aligned to it.
func TestPhaseOtherPeriodNoCorrection(t *testing.T) {
	clk, w, c := newPhaseWatcher(t)
	for n := 1; n <= 5; n++ {
		phaseTick(clk, w, n, mgmt(0))
		clk.advanceTo(tickAt(n).Add(3 * time.Second))
		w.Seen(Signal, Heartbeat{Period: 2 * testPeriod})
	}
	assert.Empty(t, c.corrections(Signal), "periods differ")
}

// A stream without a correction func, and Management itself, are never corrected.
func TestPhaseNoCorrectFunc(t *testing.T) {
	h := captureLogs(t)
	clk := newFakeClock()
	w := newTestWatcher(clk)
	w.Register(Signal, Registration{Kind: ActionReconnect})
	for n := 1; n <= 4; n++ {
		phaseTick(clk, w, n, mgmt(0), phaseBeat{svc: Signal, at: 3 * time.Second})
	}
	assert.Empty(t, lines(h, "hbwatch: correct"), "no correction without a func")
}

// With stale checks off a wake schedules nothing and a silent stream is not
// acted on, but corrections still run.
func TestPhaseStaleOffNoStaleAction(t *testing.T) {
	clk, w, c := newPhaseWatcher(t)
	for n := 1; n <= 3; n++ {
		phaseTick(clk, w, n, mgmt(0), phaseBeat{svc: Relay, at: 3 * time.Second})
	}
	before := clk.scheduledCount()
	w.CheckNow()
	clk.advance(100 * time.Second)
	assert.Equal(t, before, clk.scheduledCount(), "no stale timers")
	assert.Equal(t, 0, c.total(), "no stale action")
	require.Len(t, c.corrections(Relay), 1, "the correction still runs")
}

func TestWantedPhase(t *testing.T) {
	assert.Equal(t, 2*time.Second, wantedPhase(5*time.Second, 3*time.Second, testPeriod), "later stream moves earlier")
	assert.Equal(t, 28*time.Second, wantedPhase(time.Second, 3*time.Second, testPeriod), "wraps below zero")
	assert.Equal(t, 1235*ms, wantedPhase(1234*ms, -600*time.Microsecond, testPeriod), "rounds to whole ms")
}

// Heartbeats of a stream other than the registered one are not judged.
func TestPhaseOtherStreamNotJudged(t *testing.T) {
	captureLogs(t)
	clk := newFakeClock()
	w := newTestWatcher(clk)
	c := &counter{}
	registered, other := new(int), new(int)
	w.Register(Relay, Registration{Correct: c.correct(Relay), Stream: registered})
	for n := 1; n <= 4; n++ {
		phaseTick(clk, w, n, mgmt(0))
		clk.advanceTo(tickAt(n).Add(3 * time.Second))
		w.Seen(Relay, Heartbeat{Period: testPeriod, Stream: other})
	}
	assert.Empty(t, c.corrections(Relay), "another stream is not corrected")
	for n := 5; n <= 7; n++ {
		phaseTick(clk, w, n, mgmt(0))
		clk.advanceTo(tickAt(n).Add(3 * time.Second))
		w.Seen(Relay, Heartbeat{Period: testPeriod, Stream: registered})
	}
	assert.Len(t, c.corrections(Relay), 1, "the registered stream is corrected")
}
