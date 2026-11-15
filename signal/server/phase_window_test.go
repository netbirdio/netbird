package server

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/metadata"

	"github.com/netbirdio/netbird/shared/alignedhb"
	"github.com/netbirdio/netbird/shared/alignedhb/phasesig"
	"github.com/netbirdio/netbird/shared/relay/messages"
	"github.com/netbirdio/netbird/shared/signal/proto"
)

func phaseOf(t *testing.T, sp *streamPhase) time.Duration {
	t.Helper()
	sched, ok := sp.schedule()
	require.True(t, ok, "the stream must be aligned")
	return sched.Phase
}

func correctionReq(phase time.Duration) *proto.PhaseRequest {
	return &proto.PhaseRequest{PhaseMillis: uint32(phase.Milliseconds())}
}

// A signed phase in a phase request turns a stock stream aligned only when
// Management signed it for this peer key.
func TestStreamPhaseSignedRequestVerifiesPeer(t *testing.T) {
	const peerKey = "Zm9vYmFyZm9vYmFyZm9vYmFyZm9vYmFyZm9vYmFyMzA="
	const otherKey = "Zm9vYmFyZm9vYmFyZm9vYmFyZm9vYmFyZm9vYmFyMzE="
	verifier, err := phasesig.NewVerifier(testPhaseSecret)
	require.NoError(t, err)
	now := time.Now()
	request := func(secret, key string) *proto.PhaseRequest {
		signer, err := phasesig.NewSigner(secret)
		require.NoError(t, err)
		signed, err := signer.SignedPhase(messages.HashID(key), time.Minute, now)
		require.NoError(t, err)
		return phaseRequest(key, time.Minute, signed).GetPhaseRequest()
	}

	sp := newStreamPhase(peerKey, &streamAnswer{period: time.Minute}, nil)
	sp.handleRequest(request(testPhaseSecret, otherKey), verifier, alignedhb.PeriodLimits{}, now)
	_, ok := sp.schedule()
	assert.False(t, ok, "a phase signed for another peer key must keep the stream stock")

	sp.handleRequest(request("other-secret", peerKey), verifier, alignedhb.PeriodLimits{}, now)
	_, ok = sp.schedule()
	assert.False(t, ok, "a bad signature must keep the stream stock")

	sp.tick()
	sp.handleRequest(correctionReq(time.Second), verifier, alignedhb.PeriodLimits{}, now)
	_, ok = sp.schedule()
	assert.False(t, ok, "a correction must not turn a stock stream aligned")

	valid := request(testPhaseSecret, peerKey)
	sp.handleRequest(valid, verifier, alignedhb.PeriodLimits{}, now)
	assert.Equal(t, time.Duration(valid.GetPhaseMillis())*time.Millisecond, phaseOf(t, sp),
		"a phase signed for the peer must turn the stream aligned")
}

// signedReqAt returns the phase request with the phase Management signs for
// peerKey and period on the day of at.
func signedReqAt(t *testing.T, peerKey string, period time.Duration, at time.Time) *proto.PhaseRequest {
	t.Helper()
	signer, err := phasesig.NewSigner(testPhaseSecret)
	require.NoError(t, err)
	signed, err := signer.SignedPhase(messages.HashID(peerKey), period, at)
	require.NoError(t, err)
	return phaseRequest(peerKey, period, signed).GetPhaseRequest()
}

func reqPhase(req *proto.PhaseRequest) time.Duration {
	return time.Duration(req.GetPhaseMillis()) * time.Millisecond
}

// A signed phase on an open stream has its period clamped to the limits before
// it is verified. Only a newer day replaces the verified phase, so a period
// change on the same day waits for the next stream open.
func TestStreamPhaseSignedClampsPeriod(t *testing.T) {
	const peerKey = "Zm9vYmFyZm9vYmFyZm9vYmFyZm9vYmFyZm9vYmFyMzY="
	verifier, err := phasesig.NewVerifier(testPhaseSecret)
	require.NoError(t, err)
	now := time.Now()

	for requested, want := range map[time.Duration]time.Duration{
		time.Second:        30 * time.Second,
		1000 * time.Second: 300 * time.Second,
		time.Minute:        time.Minute,
	} {
		req := signedReqAt(t, peerKey, want, now)
		req.PeriodSeconds = uint32(requested / time.Second)
		sp := newStreamPhase(peerKey, &streamAnswer{period: want}, nil)
		sp.handleRequest(req, verifier, alignedhb.PeriodLimits{}, now)
		sched, ok := sp.schedule()
		require.True(t, ok, "requested %s: phase signed for the clamped period must turn the stream aligned", requested)
		assert.Equal(t, alignedhb.Answer{Period: want, Phase: reqPhase(req)}, sched, "requested %s", requested)
	}

	sp := newStreamPhase(peerKey, &streamAnswer{period: time.Minute}, nil)
	sp.handleRequest(signedReqAt(t, peerKey, time.Second, now), verifier, alignedhb.PeriodLimits{}, now)
	_, ok := sp.schedule()
	assert.False(t, ok, "a phase signed for a period below the limits must keep the stream stock")
}

// Signatures stay valid for a day around today. Once a stream has a verified
// signed phase, only a phase of a newer day replaces it, so a client cannot
// flip the tick between the phases of two days.
func TestStreamPhaseSignedOnlyNewerDay(t *testing.T) {
	const peerKey = "Zm9vYmFyZm9vYmFyZm9vYmFyZm9vYmFyZm9vYmFyMzQ="
	verifier, err := phasesig.NewVerifier(testPhaseSecret)
	require.NoError(t, err)
	now := time.Now()
	yesterday := signedReqAt(t, peerKey, time.Minute, now.Add(-24*time.Hour))
	today := signedReqAt(t, peerKey, time.Minute, now)
	tomorrow := signedReqAt(t, peerKey, time.Minute, now.Add(24*time.Hour))
	if reqPhase(yesterday) == reqPhase(today) || reqPhase(today) == reqPhase(tomorrow) {
		t.Skip("two days share a phase")
	}

	sp := newStreamPhase(peerKey, &streamAnswer{period: time.Minute}, nil)
	sp.handleRequest(today, verifier, alignedhb.PeriodLimits{}, now)
	assert.Equal(t, reqPhase(today), phaseOf(t, sp), "the first signed phase must turn the stream aligned")

	sp.handleRequest(yesterday, verifier, alignedhb.PeriodLimits{}, now)
	assert.Equal(t, reqPhase(today), phaseOf(t, sp), "a phase of an older day must be ignored")

	sameDay := signedReqAt(t, peerKey, 2*time.Minute, now)
	sp.handleRequest(sameDay, verifier, alignedhb.PeriodLimits{}, now)
	sched, _ := sp.schedule()
	assert.Equal(t, alignedhb.Answer{Period: time.Minute, Phase: reqPhase(today)}, sched,
		"another phase of the same day must be ignored")

	sp.handleRequest(tomorrow, verifier, alignedhb.PeriodLimits{}, now)
	assert.Equal(t, reqPhase(tomorrow), phaseOf(t, sp), "the phase of a newer day must apply")

	sp.handleRequest(today, verifier, alignedhb.PeriodLimits{}, now)
	assert.Equal(t, reqPhase(tomorrow), phaseOf(t, sp), "the tick must not flip back to the older day")
}

// A stream that opened with a signed phase keeps its day: an older phase sent
// on the stream later is ignored.
func TestStreamPhaseOpenSignedKeepsDay(t *testing.T) {
	const peerKey = "Zm9vYmFyZm9vYmFyZm9vYmFyZm9vYmFyZm9vYmFyMzU="
	verifier, err := phasesig.NewVerifier(testPhaseSecret)
	require.NoError(t, err)
	now := time.Now()
	s := newAlignedTestServer(t)
	open := signedRequest(t, testPhaseSecret, peerKey, time.Minute)
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(alignedhb.MetadataKey, open.Value()))
	answer := s.alignedHeartbeatAnswer(ctx, peerKey)
	require.NotNil(t, answer)
	require.NotNil(t, answer.aligned, "the stream must open aligned")

	yesterday := signedReqAt(t, peerKey, time.Minute, now.Add(-24*time.Hour))
	if reqPhase(yesterday) == open.Signed.Phase {
		t.Skip("two days share a phase")
	}
	sp := newStreamPhase(peerKey, answer, nil)
	sp.handleRequest(yesterday, verifier, alignedhb.PeriodLimits{}, now)
	assert.Equal(t, open.Signed.Phase, phaseOf(t, sp), "a phase of an older day must be ignored")
}
