package server

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/relay/metrics"
	"github.com/netbirdio/netbird/shared/alignedhb"
	"github.com/netbirdio/netbird/shared/alignedhb/hbmetrics/hbmetricstest"
	"github.com/netbirdio/netbird/shared/alignedhb/phasesig"
	"github.com/netbirdio/netbird/shared/relay/healthcheck"
	"github.com/netbirdio/netbird/shared/relay/messages"
)

const (
	relayMetricSent    = "relay_aligned_heartbeat_sent_total"
	relayMetricApplied = "relay_aligned_heartbeat_corrections_applied_total"
	relayMetricIgnored = "relay_aligned_heartbeat_corrections_ignored_total"
	relayMetricClamp   = "relay_aligned_heartbeat_clamp_hits_total"
	relayMetricBadSig  = "relay_aligned_heartbeat_bad_signatures_total"
)

// Corrections reach the relay counters: the rules themselves are tested in
// phasectl.
func TestRelay_CorrectionMetrics(t *testing.T) {
	meter, reader := hbmetricstest.NewMeter()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	m, err := metrics.NewMetrics(ctx, meter)
	require.NoError(t, err)

	p := NewPeer(m, messages.HashID("metrics-client"), messages.ProtocolV2, newScriptedConn(), nil, nil)
	s := healthcheck.AlignedSchedule{Period: time.Minute, Phase: 20 * time.Second}
	p.setAlignedSchedule(&verifiedPhase{schedule: s, day: 1})
	hc := healthcheck.NewAlignedSender(p.log, s)

	p.phase.Tick()
	p.handleHealthcheckEcho(phaseEcho(40*time.Second), hc) // clamped to 25 s, applied
	p.handleHealthcheckEcho(phaseEcho(23*time.Second), hc) // rate limit

	counts := hbmetricstest.Counts(t, reader)
	assert.Equal(t, int64(1), counts[relayMetricApplied], "applied")
	assert.Equal(t, int64(1), counts[relayMetricIgnored+"/rate_limit"], "rate limited")
	assert.Equal(t, int64(1), counts[relayMetricClamp], "clamp hits")
	assert.Equal(t, 25*time.Second, relayPhase(t, p), "the tick moved to the window edge")
}

// The relay counts the aligned heartbeats it sends and the signed phases that
// fail to verify, in the handshake and in a later echo.
func TestRelay_HeartbeatAndSignatureMetrics(t *testing.T) {
	meter, reader := hbmetricstest.NewMeter()
	verifier, err := phasesig.NewVerifier(testPhaseSecret)
	require.NoError(t, err)
	validator := &recordingValidator{}
	relay, err := NewRelay(Config{
		ExposedAddress: "rel://127.0.0.1:1234",
		AuthValidator:  validator,
		PhaseVerifier:  verifier,
		Meter:          meter,
	})
	require.NoError(t, err)
	t.Cleanup(func() { relay.Shutdown(context.Background()) })
	relay.periodLimits = alignedhb.PeriodLimits{Min: time.Second, Max: alignedhb.MaxPeriod}

	peerID := messages.HashID("metrics-aligned-client")
	ext, _ := signedExtension(t, testPhaseSecret, peerID, time.Second)
	p := acceptEnvelope(t, relay, validator, messages.ProtocolV2, peerID, ext)
	waitHeartbeats(t, p.conn.(*scriptedConn), 1, 2)
	assert.GreaterOrEqual(t, hbmetricstest.Counts(t, reader)[relayMetricSent], int64(2), "aligned heartbeats counted")

	badID := messages.HashID("metrics-bad-client")
	badExt, sp := signedExtension(t, "other-secret", badID, time.Second)
	badValidator := &recordingValidator{}
	relay.validator = badValidator
	bad := acceptEnvelope(t, relay, badValidator, messages.ProtocolV2, badID, badExt)
	assert.Equal(t, int64(1), hbmetricstest.Counts(t, reader)[relayMetricBadSig], "bad signature in the handshake")

	bad.conn.(*scriptedConn).deliver(t, echo(uint32(sp.Phase.Milliseconds()), badExt))
	require.Eventually(t, func() bool {
		return hbmetricstest.Counts(t, reader)[relayMetricBadSig] == 2
	}, 2*time.Second, 10*time.Millisecond, "bad signature in an echo")
}
