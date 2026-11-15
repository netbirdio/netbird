package server

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/shared/alignedhb"
	"github.com/netbirdio/netbird/shared/alignedhb/hbmetrics"
	"github.com/netbirdio/netbird/shared/alignedhb/hbmetrics/hbmetricstest"
	"github.com/netbirdio/netbird/shared/alignedhb/phasesig"
	"github.com/netbirdio/netbird/shared/relay/messages"
)

const (
	metricApplied = "aligned_heartbeat_corrections_applied_total"
	metricIgnored = "aligned_heartbeat_corrections_ignored_total"
	metricClamp   = "aligned_heartbeat_clamp_hits_total"
	metricBadSig  = "aligned_heartbeat_bad_signatures_total"
)

// Corrections reach the Signal counters: the rules themselves are tested in
// phasectl.
func TestStreamPhaseCorrectionMetrics(t *testing.T) {
	meter, reader := hbmetricstest.NewMeter()
	m, err := hbmetrics.New(meter, "")
	require.NoError(t, err)
	sp := newStreamPhase("peer", &streamAnswer{
		period:  time.Minute,
		aligned: &alignedhb.Answer{Period: time.Minute, Phase: 20 * time.Second},
	}, m)
	now := time.Now()

	sp.tick()
	sp.handleRequest(correctionReq(40*time.Second), nil, alignedhb.PeriodLimits{}, now) // clamped to 25 s, applied
	sp.handleRequest(correctionReq(23*time.Second), nil, alignedhb.PeriodLimits{}, now) // rate limit

	assert.Equal(t, map[string]int64{
		metricApplied:                 1,
		metricIgnored + "/rate_limit": 1,
		metricClamp:                   1,
	}, hbmetricstest.Counts(t, reader), "correction counters")
	assert.Equal(t, 25*time.Second, phaseOf(t, sp), "the tick moved to the window edge")
}

// A signed phase that fails to verify is counted, the stream stays stock.
func TestStreamPhaseBadSignatureMetric(t *testing.T) {
	const peerKey = "Zm9vYmFyZm9vYmFyZm9vYmFyZm9vYmFyZm9vYmFyMzY="
	meter, reader := hbmetricstest.NewMeter()
	m, err := hbmetrics.New(meter, "")
	require.NoError(t, err)
	verifier, err := phasesig.NewVerifier(testPhaseSecret)
	require.NoError(t, err)
	signer, err := phasesig.NewSigner("other-secret")
	require.NoError(t, err)
	now := time.Now()
	signed, err := signer.SignedPhase(messages.HashID(peerKey), time.Minute, now)
	require.NoError(t, err)

	sp := newStreamPhase(peerKey, &streamAnswer{period: time.Minute}, m)
	sp.handleRequest(phaseRequest(peerKey, time.Minute, signed).GetPhaseRequest(), verifier, alignedhb.PeriodLimits{}, now)

	_, ok := sp.schedule()
	assert.False(t, ok, "stream stays stock")
	assert.Equal(t, int64(1), hbmetricstest.Counts(t, reader)[metricBadSig], "bad signature counted")
}

// The server counts the heartbeats it sends and the signed phases on stream
// open that fail to verify.
func TestServerAlignedHeartbeatMetrics(t *testing.T) {
	meter, reader := hbmetricstest.NewMeter()
	s, err := NewServer(context.Background(), meter)
	require.NoError(t, err)
	v, err := phasesig.NewVerifier(testPhaseSecret)
	require.NoError(t, err)
	s.SetPhaseVerifier(v)
	s.lowerPeriodFloorForTest(time.Second)

	const peerKey = "Zm9vYmFyZm9vYmFyZm9vYmFyZm9vYmFyZm9vYmFyMzc="
	good := signedRequest(t, testPhaseSecret, peerKey, time.Second)
	stream := connectTestPeer(t, s, peerKey, alignedhb.MetadataKey, good.Value())
	require.Eventually(t, func() bool { return len(stream.heartbeats()) >= 2 }, 4*time.Second, 20*time.Millisecond)
	assert.GreaterOrEqual(t, hbmetricstest.Counts(t, reader)["aligned_heartbeat_sent_total"], int64(2), "heartbeats counted")

	const otherKey = "Zm9vYmFyZm9vYmFyZm9vYmFyZm9vYmFyZm9vYmFyMzg="
	bad := signedRequest(t, "other-secret", otherKey, time.Second)
	badStream := connectTestPeer(t, s, otherKey, alignedhb.MetadataKey, bad.Value())
	// The answer goes out after the check, so the header shows it ran.
	require.Eventually(t, func() bool { return len(badStream.answer()) == 1 }, time.Second, 10*time.Millisecond)
	assert.Equal(t, int64(1), hbmetricstest.Counts(t, reader)[metricBadSig], "bad signature on open counted")
}
