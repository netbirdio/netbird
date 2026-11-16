package hbwatch

import (
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// clampServer plays a Signal server whose clock is 8 s off: its heartbeats land
// 8 s after Management, and it clamps every correction to the 5 s window around
// the signed phase of 10 s. It returns the phase of the next heartbeat.
type clampServer struct {
	signed time.Duration
	phase  time.Duration
}

func (s *clampServer) apply(wanted time.Duration) {
	const window = 5 * time.Second
	delta := wanted - s.signed
	delta = min(max(delta, -window), window)
	s.phase = s.signed + delta
}

// at returns when its heartbeat lands relative to Management: the clock offset
// of 8 s plus the move from the signed phase.
func (s *clampServer) at() time.Duration {
	return 8*time.Second + (s.phase - s.signed)
}

// runClampTicks runs ticks from..to with Management on time and the clamping
// Signal server, applying every correction the watcher asks for before the
// next tick.
func runClampTicks(clk *fakeClock, w *Watcher, c *counter, srv *clampServer, from, to int) {
	for n := from; n <= to; n++ {
		asked := len(c.corrections(Signal))
		phaseTick(clk, w, n, mgmt(0), phaseBeat{Signal, srv.at(), srv.phase})
		if got := c.corrections(Signal); len(got) > asked {
			srv.apply(got[len(got)-1])
		}
	}
}

func signalStatus(t *testing.T, w *Watcher) StreamStatus {
	t.Helper()
	for _, st := range w.Snapshot().Streams {
		if st.Service == Signal {
			return st
		}
	}
	require.FailNow(t, "no Signal stream in the snapshot")
	return StreamStatus{}
}

// A server that clamps every correction: the client asks, sees the server not
// follow, and stops after BlockAfter corrections in a row instead of asking
// every two ticks for as long as it lasts. It warns once.
func TestCorrectionsStopAfterBlockedInRow(t *testing.T) {
	clk, w, c := newPhaseWatcher(t)
	h := captureLogs(t)
	srv := &clampServer{signed: 10 * time.Second, phase: 10 * time.Second}

	phaseTick(clk, w, 1, mgmt(0))
	runClampTicks(clk, w, c, srv, 2, 20)

	assert.Len(t, c.corrections(Signal), BlockAfter, "asks %d times, then stops", BlockAfter)
	st := signalStatus(t, w)
	assert.True(t, st.Blocked, "corrections blocked")
	assert.Equal(t, BlockAfter, st.BlockedInRow, "blocked in a row")
	assert.Equal(t, BlockAfter, st.ClampHits, "clamp hits")
	require.NotNil(t, st.LastCorrection, "last correction kept")
	assert.Equal(t, ResultIgnored, st.LastCorrection.Result, "the last one hit the edge the tick was on")

	snap := w.Snapshot()
	require.Len(t, snap.Corrections, BlockAfter, "history")
	assert.Equal(t, ResultClamped, snap.Corrections[0].Result, "first correction moved the tick to the window edge")
	assert.Equal(t, 5*time.Second, srv.phase, "server sits on the window edge")

	var warns int
	for _, e := range h.AllEntries() {
		if e.Level == log.WarnLevel {
			warns++
			assert.Contains(t, e.Message, "not applied by the signal server", "warning names the server")
		}
	}
	assert.Equal(t, 1, warns, "one warning, not one per tick")
}

// A new phase from the server, such as the signed phase of the next day, ends
// the block: the client corrects again.
func TestCorrectionsResumeOnNewServerPhase(t *testing.T) {
	clk, w, c := newPhaseWatcher(t)
	srv := &clampServer{signed: 10 * time.Second, phase: 10 * time.Second}
	phaseTick(clk, w, 1, mgmt(0))
	runClampTicks(clk, w, c, srv, 2, 12)
	require.True(t, signalStatus(t, w).Blocked, "precondition: blocked")

	srv.signed, srv.phase = 20*time.Second, 20*time.Second
	runClampTicks(clk, w, c, srv, 13, 15)
	assert.Len(t, c.corrections(Signal), BlockAfter+1, "a correction for the new phase")
	assert.False(t, signalStatus(t, w).Blocked, "block ended")
}

// A new stream starts with a clean state.
func TestCorrectionsResumeOnRegister(t *testing.T) {
	clk, w, c := newPhaseWatcher(t)
	srv := &clampServer{signed: 10 * time.Second, phase: 10 * time.Second}
	phaseTick(clk, w, 1, mgmt(0))
	runClampTicks(clk, w, c, srv, 2, 12)
	require.True(t, signalStatus(t, w).Blocked, "precondition: blocked")

	register(w, c, Signal)
	st := signalStatus(t, w)
	assert.False(t, st.Blocked, "new stream not blocked")
	assert.Equal(t, LevelStock, st.Level, "no heartbeat on the new stream yet")
	assert.Nil(t, st.LastCorrection, "no correction on the new stream")
	assert.Equal(t, BlockAfter, st.ClampHits, "clamp hits count since start")

	runClampTicks(clk, w, c, srv, 13, 15)
	assert.Len(t, c.corrections(Signal), BlockAfter+1, "asks again on the new stream")
}

// A correction the server follows is recorded as applied and resets the run.
func TestCorrectionAppliedInStatus(t *testing.T) {
	clk, w, c := newPhaseWatcher(t)
	signal := phaseBeat{Signal, 3 * time.Second, 5 * time.Second}
	phaseTick(clk, w, 1, mgmt(0), signal)
	phaseTick(clk, w, 2, mgmt(0), signal)
	phaseTick(clk, w, 3, mgmt(0), signal)
	require.Equal(t, []time.Duration{2 * time.Second}, c.corrections(Signal), "precondition: one correction")

	st := signalStatus(t, w)
	require.NotNil(t, st.LastCorrection, "correction recorded")
	assert.Equal(t, ResultPending, st.LastCorrection.Result, "no heartbeat since")
	assert.Equal(t, 3*time.Second, st.LastCorrection.Offset, "offset")
	assert.Equal(t, 5*time.Second, st.LastCorrection.From, "from")
	assert.Equal(t, 2*time.Second, st.LastCorrection.Wanted, "wanted")

	phaseTick(clk, w, 4, mgmt(0), phaseBeat{Signal, 100 * ms, 2 * time.Second})
	st = signalStatus(t, w)
	assert.Equal(t, ResultApplied, st.LastCorrection.Result, "server moved to the wanted phase")
	assert.Zero(t, st.BlockedInRow, "nothing blocked")
	assert.Zero(t, st.ClampHits, "no clamp hit")
	assert.Equal(t, LevelAligned, st.Level, "aligned")
	assert.Equal(t, testPeriod, st.Period, "period of the last heartbeat")
	assert.Equal(t, 2*time.Second, st.Phase, "phase of the last heartbeat")
	assert.Equal(t, tickAt(4).Add(100*ms), st.LastHeartbeat, "last heartbeat")
}

// The snapshot lists every registered stream with its address. A relay
// connection a newer one replaced stays listed while it is open.
func TestSnapshotStreams(t *testing.T) {
	captureLogs(t)
	clk := newFakeClock()
	w := newTestWatcher(clk)
	w.staleOn = func() bool { return false }

	assert.Empty(t, w.Snapshot().Streams, "nothing registered")

	w.Register(Management, Registration{Addr: "https://mgmt:443"})
	streamA, streamB := new(int), new(int)
	unregA := w.Register(Relay, Registration{Stream: streamA, Addr: "rels://relay-a:443"})
	w.Seen(Relay, Heartbeat{Period: testPeriod, Phase: 7 * time.Second, Stream: streamA})
	w.Register(Relay, Registration{Stream: streamB, Addr: "rels://relay-b:443"})

	clk.advanceTo(t0.Add(time.Second))
	w.Seen(Relay, Heartbeat{Period: testPeriod, Phase: 9 * time.Second, Stream: streamA})

	snap := w.Snapshot()
	require.Len(t, snap.Streams, 3, "management, registered relay, replaced relay")
	assert.Equal(t, StreamStatus{Service: Management, Addr: "https://mgmt:443", Level: LevelStock}, snap.Streams[0], "management stock")
	assert.Equal(t, StreamStatus{Service: Relay, Addr: "rels://relay-b:443", Level: LevelStock}, snap.Streams[1], "registered relay")
	assert.Equal(t, StreamStatus{
		Service: Relay, Addr: "rels://relay-a:443", Level: LevelAligned,
		Period: testPeriod, Phase: 9 * time.Second, LastHeartbeat: t0.Add(time.Second),
	}, snap.Streams[2], "replaced relay keeps its heartbeats")

	unregA()
	assert.Len(t, w.Snapshot().Streams, 2, "closed relay connection dropped")
}

// The history keeps the latest corrections only.
func TestCorrectionHistoryCapped(t *testing.T) {
	clk, w, c := newPhaseWatcher(t)
	phaseTick(clk, w, 1, mgmt(0))
	// Every second tick confirms a 3 s offset; the server never moves, and each
	// correction counts as ignored until the block, so register again to keep
	// asking.
	for n := 2; len(c.corrections(Relay)) < historySize+4; n++ {
		if n%6 == 0 {
			register(w, c, Relay)
		}
		phaseTick(clk, w, n, mgmt(0), phaseBeat{Relay, 3 * time.Second, 5 * time.Second})
	}
	snap := w.Snapshot()
	require.Len(t, snap.Corrections, historySize, "history capped")
	assert.True(t, snap.Corrections[0].At.Before(snap.Corrections[historySize-1].At), "oldest first")
}
