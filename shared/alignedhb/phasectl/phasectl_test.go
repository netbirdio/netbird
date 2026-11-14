package phasectl

import (
	"sync"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	logtest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/shared/alignedhb"
	"github.com/netbirdio/netbird/shared/alignedhb/hbmetrics"
	"github.com/netbirdio/netbird/shared/alignedhb/hbmetrics/hbmetricstest"
	"github.com/netbirdio/netbird/shared/alignedhb/phasesig"
	"github.com/netbirdio/netbird/shared/relay/messages"
)

const (
	testSecret    = "phasectl-test-secret"
	metricApplied = "aligned_heartbeat_corrections_applied_total"
	metricIgnored = "aligned_heartbeat_corrections_ignored_total"
	metricClamp   = "aligned_heartbeat_clamp_hits_total"
	metricBadSig  = "aligned_heartbeat_bad_signatures_total"
)

// alignedPhase returns the schedule of a stream that opened with a phase signed
// on signed for day 10, period one minute.
func alignedPhase(signed time.Duration, m *hbmetrics.Metrics) *Phase {
	p := New("test", "peer", m, nil)
	p.Start(alignedhb.Answer{Period: time.Minute, Phase: signed}, 10)
	return p
}

func phaseOf(t *testing.T, p *Phase) time.Duration {
	t.Helper()
	sched, ok := p.Schedule()
	require.True(t, ok, "the stream must be aligned")
	return sched.Phase
}

func newMetrics(t *testing.T) (*hbmetrics.Metrics, func() map[string]int64) {
	t.Helper()
	meter, reader := hbmetricstest.NewMeter()
	m, err := hbmetrics.New(meter, "")
	require.NoError(t, err)
	return m, func() map[string]int64 { return hbmetricstest.Counts(t, reader) }
}

func TestNewIsStock(t *testing.T) {
	p := New("test", "peer", nil, nil)
	_, ok := p.Schedule()
	assert.False(t, ok, "a new stream must be stock")

	p.Tick()
	_, ok = p.Correct(time.Second)
	assert.False(t, ok, "a correction must not turn a stock stream aligned")
	_, ok = p.Schedule()
	assert.False(t, ok, "the stream must stay stock after a correction")
}

// A correction moves the tick only inside the window around the signed phase.
// A request outside it moves the tick to the nearest edge of the window.
func TestCorrectWindow(t *testing.T) {
	p := alignedPhase(20*time.Second, nil)

	p.Tick()
	next, ok := p.Correct(24 * time.Second)
	assert.True(t, ok, "a correction inside the window must apply")
	assert.Equal(t, alignedhb.Answer{Period: time.Minute, Phase: 24 * time.Second}, next, "returned schedule")
	assert.Equal(t, 24*time.Second, phaseOf(t, p), "a correction inside the window must apply")

	p.Tick()
	p.Correct(40 * time.Second)
	assert.Equal(t, 25*time.Second, phaseOf(t, p), "a correction past the window must stop at its edge")

	p.Tick()
	p.Correct(5 * time.Second)
	assert.Equal(t, 15*time.Second, phaseOf(t, p), "a correction before the window must stop at its edge")

	p.Tick()
	_, ok = p.Correct(61 * time.Second)
	assert.False(t, ok, "a phase outside the period must be ignored")
	assert.Equal(t, 15*time.Second, phaseOf(t, p), "a phase outside the period must be ignored")
}

// The window is measured on the circle of the period, so it wraps at zero.
func TestCorrectWindowWraps(t *testing.T) {
	p := alignedPhase(2*time.Second, nil)

	p.Tick()
	p.Correct(58 * time.Second)
	assert.Equal(t, 58*time.Second, phaseOf(t, p), "a correction 4 s back across zero must apply")

	p.Tick()
	p.Correct(40 * time.Second)
	assert.Equal(t, 57*time.Second, phaseOf(t, p), "a correction far back must stop at the window edge across zero")
}

// A stream applies one correction per tick and none before the first.
func TestCorrectOncePerTick(t *testing.T) {
	p := alignedPhase(20*time.Second, nil)

	_, ok := p.Correct(21 * time.Second)
	assert.False(t, ok, "no correction before the first tick")
	assert.Equal(t, 20*time.Second, phaseOf(t, p), "no correction before the first tick")

	p.Tick()
	p.Correct(21 * time.Second)
	p.Correct(22 * time.Second)
	assert.Equal(t, 21*time.Second, phaseOf(t, p), "the second correction in one tick must be ignored")

	// A request for the current phase or one clamped onto it uses no correction.
	p.Correct(21 * time.Second)
	p.Tick()
	p.Correct(21 * time.Second)
	p.Correct(23 * time.Second)
	assert.Equal(t, 23*time.Second, phaseOf(t, p), "the next tick allows a new correction")
}

// Signatures stay valid for days around today. Once a stream has a verified
// signed phase, only a phase of a newer day replaces it, so a client cannot
// flip the tick between the phases of two days.
func TestAcceptSignedOnlyNewerDay(t *testing.T) {
	m, counts := newMetrics(t)
	p := New("test", "peer", m, nil)
	today := alignedhb.Answer{Period: time.Minute, Phase: 20 * time.Second}

	assert.True(t, p.AcceptSigned(today, 10), "the first signed phase must turn the stream aligned")
	assert.Equal(t, today.Phase, phaseOf(t, p), "aligned on the first signed phase")

	assert.False(t, p.AcceptSigned(today, 10), "the same phase again must change nothing")
	assert.False(t, p.AcceptSigned(alignedhb.Answer{Period: time.Minute, Phase: 40 * time.Second}, 9),
		"a phase of an older day must be ignored")
	assert.False(t, p.AcceptSigned(alignedhb.Answer{Period: 2 * time.Minute, Phase: 40 * time.Second}, 10),
		"another phase of the same day must be ignored")
	sched, _ := p.Schedule()
	assert.Equal(t, today, sched, "the schedule must stay on the verified phase")

	tomorrow := alignedhb.Answer{Period: time.Minute, Phase: 50 * time.Second}
	assert.True(t, p.AcceptSigned(tomorrow, 11), "the phase of a newer day must apply")
	assert.Equal(t, tomorrow.Phase, phaseOf(t, p), "the phase of a newer day must apply")
	assert.False(t, p.AcceptSigned(today, 10), "the tick must not flip back to the older day")

	assert.Equal(t, int64(3), counts()[metricIgnored+"/old_day"], "older, same-day and flip-back phases counted")
}

// A newer signed phase becomes the centre of the window, also after
// corrections moved the tick.
func TestAcceptSignedMovesWindow(t *testing.T) {
	p := alignedPhase(20*time.Second, nil)
	p.Tick()
	p.Correct(24 * time.Second)

	require.True(t, p.AcceptSigned(alignedhb.Answer{Period: time.Minute, Phase: 40 * time.Second}, 11))
	assert.Equal(t, 40*time.Second, phaseOf(t, p), "the new signed phase replaces the corrected tick")

	p.Tick()
	p.Correct(20 * time.Second)
	assert.Equal(t, 35*time.Second, phaseOf(t, p), "the window must follow the new signed phase")
}

// Corrections are counted by outcome: applied, clamped, and ignored by reason.
func TestCorrectMetrics(t *testing.T) {
	m, counts := newMetrics(t)
	p := alignedPhase(20*time.Second, m)

	p.Tick()
	p.Correct(22 * time.Second) // applied
	p.Correct(23 * time.Second) // rate limit
	p.Tick()
	p.Correct(40 * time.Second) // clamped to 25 s, applied
	p.Tick()
	p.Correct(40 * time.Second) // clamped to 25 s, the tick is there already
	p.Correct(90 * time.Second) // outside the period
	p.Correct(25 * time.Second) // the current phase, nothing to count

	assert.Equal(t, map[string]int64{
		metricApplied:                     2,
		metricIgnored + "/rate_limit":     1,
		metricIgnored + "/at_window_edge": 1,
		metricIgnored + "/invalid":        1,
		metricClamp:                       2,
	}, counts(), "correction counters")

	stock := New("test", "stock", m, nil)
	stock.Tick()
	stock.Correct(time.Second)
	assert.Equal(t, int64(1), counts()[metricIgnored+"/stock"], "correction on a stock stream")
}

// Corrections clamped several times in a row warn: a host clock off by more
// than the window keeps the stream from aligning. One inside the window or a
// newer signed phase ends the streak. A stream warns once at most.
func TestClampStreakWarns(t *testing.T) {
	hook := &logtest.Hook{}
	old := log.StandardLogger().ReplaceHooks(log.LevelHooks{})
	log.AddHook(hook)
	t.Cleanup(func() { log.StandardLogger().ReplaceHooks(old) })
	p := alignedPhase(20*time.Second, nil)
	clamped := func() {
		p.Tick()
		p.Correct(40 * time.Second)
	}
	inWindow := func() {
		p.Tick()
		p.Correct(22 * time.Second)
	}
	warnings := func() int {
		n := 0
		for _, e := range hook.AllEntries() {
			if e.Level == log.WarnLevel {
				n++
			}
		}
		return n
	}

	for i := 0; i < hbmetrics.ClampWarnAfter-1; i++ {
		clamped()
	}
	inWindow()
	for i := 0; i < hbmetrics.ClampWarnAfter-1; i++ {
		clamped()
	}
	assert.Zero(t, warnings(), "a correction inside the window ends the streak")

	require.True(t, p.AcceptSigned(alignedhb.Answer{Period: time.Minute, Phase: 20 * time.Second}, 11))
	for i := 0; i < hbmetrics.ClampWarnAfter-1; i++ {
		clamped()
	}
	assert.Zero(t, warnings(), "a newer signed phase ends the streak")
	clamped()
	assert.Equal(t, 1, warnings(), "warning at the limit")
	clamped()
	assert.Equal(t, 1, warnings(), "one warning per streak")

	inWindow()
	for i := 0; i < hbmetrics.ClampWarnAfter; i++ {
		clamped()
	}
	assert.Equal(t, 1, warnings(), "one warning per stream")
}

// A client that loops phase requests, out of the window and back into it,
// gets at most one warning per stream: dropped requests and in-window requests
// do not start a new streak warning.
func TestClampStreakWarnBounded(t *testing.T) {
	hook := &logtest.Hook{}
	old := log.StandardLogger().ReplaceHooks(log.LevelHooks{})
	log.AddHook(hook)
	t.Cleanup(func() { log.StandardLogger().ReplaceHooks(old) })
	m, counts := newMetrics(t)
	p := alignedPhase(20*time.Second, m)

	const ticks = 50
	for i := 0; i < ticks; i++ {
		p.Tick()
		for j := 0; j < hbmetrics.ClampWarnAfter; j++ {
			p.Correct(40 * time.Second)
			p.Correct(time.Duration(41+j) * time.Second)
		}
		p.Correct(22 * time.Second)
	}

	warnings := 0
	for _, e := range hook.AllEntries() {
		if e.Level == log.WarnLevel {
			warnings++
		}
	}
	assert.LessOrEqual(t, warnings, 1, "one warning per stream at most")
	assert.LessOrEqual(t, counts()[metricClamp], int64(ticks), "at most one clamp counted per tick")
}

func TestVerify(t *testing.T) {
	m, counts := newMetrics(t)
	verifier, err := phasesig.NewVerifier(testSecret)
	require.NoError(t, err)
	peer := messages.HashID("verify-client")
	now := time.Now()
	sign := func(secret string, peer messages.PeerID, period time.Duration) alignedhb.SignedPhase {
		signer, err := phasesig.NewSigner(secret)
		require.NoError(t, err)
		sp, err := signer.SignedPhase(peer, period, now)
		require.NoError(t, err)
		return sp
	}

	signed := sign(testSecret, peer, time.Minute)
	answer, err := Verify(verifier, alignedhb.PeriodLimits{}, peer, time.Minute, signed, now, m)
	require.NoError(t, err, "a phase signed for the peer must verify")
	assert.Equal(t, alignedhb.Answer{Period: time.Minute, Phase: signed.Phase}, answer, "answer")

	_, err = Verify(verifier, alignedhb.PeriodLimits{}, messages.HashID("other-client"), time.Minute, signed, now, m)
	assert.Error(t, err, "a phase signed for another peer must not verify")

	_, err = Verify(verifier, alignedhb.PeriodLimits{}, peer, time.Minute, sign("other-secret", peer, time.Minute), now, m)
	assert.Error(t, err, "a phase signed with another secret must not verify")

	_, err = Verify(nil, alignedhb.PeriodLimits{}, peer, time.Minute, signed, now, m)
	assert.Error(t, err, "without a verifier nothing verifies")

	assert.Equal(t, int64(2), counts()[metricBadSig], "bad signatures counted, a missing verifier is not")
}

// Management signs for the period clamped to the limits, so Verify checks the
// clamped period. A phase signed for a period outside the limits never verifies.
func TestVerifyClampsPeriod(t *testing.T) {
	verifier, err := phasesig.NewVerifier(testSecret)
	require.NoError(t, err)
	signer, err := phasesig.NewSigner(testSecret)
	require.NoError(t, err)
	peer := messages.HashID("clamp-client")
	now := time.Now()

	for requested, want := range map[time.Duration]time.Duration{
		time.Second:        30 * time.Second,
		1000 * time.Second: 300 * time.Second,
		time.Minute:        time.Minute,
	} {
		signed, err := signer.SignedPhase(peer, want, now)
		require.NoError(t, err)
		answer, err := Verify(verifier, alignedhb.PeriodLimits{}, peer, requested, signed, now, nil)
		require.NoError(t, err, "requested %s: phase signed for the clamped period must verify", requested)
		assert.Equal(t, alignedhb.Answer{Period: want, Phase: signed.Phase}, answer, "requested %s", requested)
	}

	below, err := signer.SignedPhase(peer, time.Second, now)
	require.NoError(t, err)
	answer, err := Verify(verifier, alignedhb.PeriodLimits{}, peer, time.Second, below, now, nil)
	assert.Error(t, err, "a phase signed for a period below the limits must not verify")
	assert.Equal(t, 30*time.Second, answer.Period, "the answer carries the clamped period on failure")
}

// The stream reader corrects while the heartbeat loop ticks and reads the
// schedule. Run with -race.
func TestConcurrentUse(t *testing.T) {
	p := alignedPhase(20*time.Second, nil)
	var wg sync.WaitGroup
	wg.Add(3)
	go func() {
		defer wg.Done()
		for i := 0; i < 1000; i++ {
			p.Tick()
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 1000; i++ {
			p.Correct(time.Duration(18+i%5) * time.Second)
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 1000; i++ {
			p.Schedule()
			p.AcceptSigned(alignedhb.Answer{Period: time.Minute, Phase: 20 * time.Second}, int64(10+i/100))
		}
	}()
	wg.Wait()

	sched, ok := p.Schedule()
	require.True(t, ok, "the stream must stay aligned")
	assert.LessOrEqual(t, sched.Phase, 25*time.Second, "the tick must stay inside the window")
	assert.GreaterOrEqual(t, sched.Phase, 15*time.Second, "the tick must stay inside the window")
}
