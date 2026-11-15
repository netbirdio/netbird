package server

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	"google.golang.org/grpc/metadata"

	"github.com/netbirdio/netbird/shared/alignedhb"
	"github.com/netbirdio/netbird/shared/alignedhb/phasesig"
	"github.com/netbirdio/netbird/shared/relay/messages"
	"github.com/netbirdio/netbird/shared/signal/proto"
)

const testPhaseSecret = "relay-auth-secret"

// lowerPeriodFloorForTest lets tests in this package tick faster than
// alignedhb.MinPeriod. It skips the check of SetPeriodLimits on purpose, so
// no config or flag reaches it: production code sets limits only through
// SetPeriodLimits.
func (s *Server) lowerPeriodFloorForTest(floor time.Duration) {
	l := alignedhb.PeriodLimits{Min: floor, Max: alignedhb.MaxPeriod}
	s.periodLimits.Store(&l)
}

// newAlignedTestServer returns a Signal server that accepts phases signed with
// testPhaseSecret, with periods down to one second.
func newAlignedTestServer(t *testing.T) *Server {
	t.Helper()
	s, err := NewServer(context.Background(), otel.Meter(""))
	require.NoError(t, err)
	v, err := phasesig.NewVerifier(testPhaseSecret)
	require.NoError(t, err)
	s.SetPhaseVerifier(v)
	// Stream tests tick every second instead of every 30.
	s.lowerPeriodFloorForTest(time.Second)
	return s
}

// signedRequest returns the stream request a client sends after Management
// signed its phase with secret.
func signedRequest(t *testing.T, secret, peerKey string, period time.Duration) alignedhb.StreamRequest {
	t.Helper()
	signer, err := phasesig.NewSigner(secret)
	require.NoError(t, err)
	sp, err := signer.SignedPhase(messages.HashID(peerKey), period, time.Now())
	require.NoError(t, err)
	return alignedhb.StreamRequest{Period: period, Signed: &sp}
}

func TestAlignedHeartbeatAnswerVerifiesPhase(t *testing.T) {
	const peerKey = "Zm9vYmFyZm9vYmFyZm9vYmFyZm9vYmFyZm9vYmFyMTA="
	const otherKey = "Zm9vYmFyZm9vYmFyZm9vYmFyZm9vYmFyZm9vYmFyMTE="
	s := newAlignedTestServer(t)
	answer := func(req alignedhb.StreamRequest) *streamAnswer {
		ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(alignedhb.MetadataKey, req.Value()))
		return s.alignedHeartbeatAnswer(ctx, peerKey)
	}
	// stockAnswer checks that the stream got the answer without a phase: the
	// server reads the stream, but ticks stock until a signed phase arrives.
	stockAnswer := func(req alignedhb.StreamRequest, msg string) {
		t.Helper()
		got := answer(req)
		require.NotNil(t, got, msg)
		assert.Nil(t, got.aligned, msg)
		assert.Equal(t, alignedhb.PendingAnswerValue(req.Period), got.value(), msg)
	}

	valid := signedRequest(t, testPhaseSecret, peerKey, time.Minute)
	got := answer(valid)
	require.NotNil(t, got, "a phase Management signed for the peer must be accepted")
	require.NotNil(t, got.aligned, "a phase Management signed for the peer must be accepted")
	assert.Equal(t, alignedhb.Answer{Period: time.Minute, Phase: valid.Signed.Phase}, *got.aligned,
		"Signal must tick on the signed phase")
	assert.Equal(t, got.aligned.Value(), got.value(), "the header carries the phase")

	stockAnswer(alignedhb.StreamRequest{Period: time.Minute}, "no signed phase must stay stock")
	stockAnswer(signedRequest(t, "other-secret", peerKey, time.Minute), "wrong secret must stay stock")
	stockAnswer(signedRequest(t, testPhaseSecret, otherKey, time.Minute), "phase of another peer must stay stock")

	picked := valid
	sp := *valid.Signed
	sp.Phase = (sp.Phase + 7*time.Second) % time.Minute
	picked.Signed = &sp
	stockAnswer(picked, "a phase the client picked must stay stock")

	otherPeriod := valid
	otherPeriod.Period = 2 * time.Minute
	stockAnswer(otherPeriod, "a period other than the signed one must stay stock")

	noVerifier, err := NewServer(context.Background(), otel.Meter(""))
	require.NoError(t, err)
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(alignedhb.MetadataKey, valid.Value()))
	assert.Nil(t, noVerifier.alignedHeartbeatAnswer(ctx, peerKey), "a server without a secret must stay stock")
}

// The server clamps the requested period to its limits. The answer confirms
// the clamped period, the heartbeat ticks on it, and a signed phase is checked
// against it, because Management signs for the period it clamped to.
func TestAlignedHeartbeatAnswerClampsPeriod(t *testing.T) {
	const peerKey = "Zm9vYmFyZm9vYmFyZm9vYmFyZm9vYmFyZm9vYmFyMTM="
	s, err := NewServer(context.Background(), otel.Meter(""))
	require.NoError(t, err)
	v, err := phasesig.NewVerifier(testPhaseSecret)
	require.NoError(t, err)
	s.SetPhaseVerifier(v)
	answer := func(req alignedhb.StreamRequest) *streamAnswer {
		ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(alignedhb.MetadataKey, req.Value()))
		return s.alignedHeartbeatAnswer(ctx, peerKey)
	}

	for requested, want := range map[time.Duration]time.Duration{
		time.Second:        30 * time.Second,
		1000 * time.Second: 300 * time.Second,
		time.Minute:        time.Minute,
	} {
		pending := answer(alignedhb.StreamRequest{Period: requested})
		require.NotNil(t, pending, "requested %s", requested)
		assert.Equal(t, alignedhb.PendingAnswerValue(want), pending.value(), "requested %s: confirmed period", requested)

		// The client sends the requested period with the phase Management
		// signed for the clamped one. A phase past the requested period does
		// not parse, and that stream stays stock without an answer.
		signed := signedRequest(t, testPhaseSecret, peerKey, want)
		signed.Period = requested
		if !alignedhb.ValidPhase(signed.Signed.Phase, requested) {
			assert.Nil(t, answer(signed), "requested %s: phase past the requested period", requested)
			continue
		}
		got := answer(signed)
		require.NotNil(t, got, "requested %s", requested)
		require.NotNil(t, got.aligned, "requested %s: phase signed for the clamped period must be accepted", requested)
		assert.Equal(t, alignedhb.Answer{Period: want, Phase: signed.Signed.Phase}, *got.aligned,
			"requested %s: the answer confirms the period Signal ticks on", requested)
		sched, ok := newStreamPhase(peerKey, got, nil).schedule()
		require.True(t, ok, "requested %s", requested)
		assert.Equal(t, want, sched.Period, "requested %s: heartbeat period", requested)
	}

	// Signed for 1 s, which no server within the limits signs: never verifies.
	tooShort := signedRequest(t, testPhaseSecret, peerKey, time.Second)
	got := answer(tooShort)
	require.NotNil(t, got, "a phase signed for a period outside the limits keeps the answer")
	assert.Nil(t, got.aligned, "a phase signed for a period outside the limits must stay stock")
	assert.Equal(t, alignedhb.PendingAnswerValue(30*time.Second), got.value(), "confirmed period is clamped")
}

func TestServerSetPeriodLimits(t *testing.T) {
	s, err := NewServer(context.Background(), otel.Meter(""))
	require.NoError(t, err)
	assert.Equal(t, alignedhb.DefaultPeriodLimits(), s.loadPeriodLimits(), "defaults before any call")
	assert.Error(t, s.SetPeriodLimits(alignedhb.PeriodLimits{Min: time.Minute, Max: 45 * time.Second}), "max below min")
	assert.Error(t, s.SetPeriodLimits(alignedhb.PeriodLimits{Min: 10 * time.Second, Max: alignedhb.MaxPeriod}), "min below 30s")
	assert.Error(t, s.SetPeriodLimits(alignedhb.PeriodLimits{Min: alignedhb.MinPeriod, Max: 600 * time.Second}), "max above 300s")
	assert.Error(t, s.SetPeriodLimits(alignedhb.PeriodLimits{Min: 10 * time.Second, Max: 600 * time.Second}), "both outside")
	assert.Equal(t, alignedhb.DefaultPeriodLimits(), s.loadPeriodLimits(), "invalid limits leave the defaults")
	want := alignedhb.PeriodLimits{Min: 45 * time.Second, Max: 2 * time.Minute}
	require.NoError(t, s.SetPeriodLimits(want))
	assert.Equal(t, want, s.loadPeriodLimits(), "configured limits")
}

func TestConnectStreamStockWithBadSignature(t *testing.T) {
	const peerKey = "Zm9vYmFyZm9vYmFyZm9vYmFyZm9vYmFyZm9vYmFyMTI="
	s := newAlignedTestServer(t)
	stream := connectTestPeer(t, s, peerKey, alignedhb.MetadataKey,
		signedRequest(t, "other-secret", peerKey, time.Second).Value())

	time.Sleep(1500 * time.Millisecond)
	assert.Empty(t, stream.times(), "no heartbeats on a stream with a bad signature")
	assert.Equal(t, []string{alignedhb.PendingAnswerValue(time.Second)}, stream.answer(),
		"the answer carries only the period: the client may send a signed phase later")
	assert.True(t, stream.registered(), "a bad signature must not break the registration")
	assert.True(t, s.registry.IsPeerRegistered(peerKey), "a bad signature must not close the stream")
	stream.mu.Lock()
	assert.NotEmpty(t, stream.header.Get(proto.HeaderRegistered), "registration header")
	stream.mu.Unlock()
}

// phaseRequest returns the stream message that hands sp, signed for period,
// to Signal.
func phaseRequest(peerKey string, period time.Duration, sp alignedhb.SignedPhase) *proto.EncryptedMessage {
	return &proto.EncryptedMessage{Key: peerKey, RemoteKey: peerKey, PhaseRequest: &proto.PhaseRequest{
		PhaseMillis:    uint32(sp.Phase.Milliseconds()),
		PhaseDay:       sp.Day,
		PhaseSignature: sp.Signature,
		PeriodSeconds:  uint32(period / time.Second),
	}}
}

func correction(peerKey string, phase time.Duration) *proto.EncryptedMessage {
	return &proto.EncryptedMessage{Key: peerKey, RemoteKey: peerKey,
		PhaseRequest: &proto.PhaseRequest{PhaseMillis: uint32(phase.Milliseconds())}}
}

// assertHeartbeatsOn waits for two heartbeats after skip and checks that they
// carry phase and land on it.
func assertHeartbeatsOn(t *testing.T, stream *hbStream, skip int, phase time.Duration, msg string) {
	t.Helper()
	require.Eventually(t, func() bool { return len(stream.heartbeats()) >= skip+2 }, 4*time.Second, 20*time.Millisecond, msg)
	for i, hb := range stream.heartbeats()[skip:] {
		assert.Equal(t, uint32(phase.Milliseconds()), hb.GetServerHeartbeat().GetPhaseMillis(), "%s: heartbeat %d phase", msg, i)
	}
	for i, at := range stream.times()[skip:] {
		off := phaseOffset(at, phase, time.Second)
		assert.LessOrEqual(t, off, 100*time.Millisecond, "%s: heartbeat %d at %s, %s from phase %s", msg, i,
			at.Format("15:04:05.000"), off, phase)
	}
}

// phaseOffset returns the distance between at and the nearest tick of phase in
// a period, measured on the circle: a tick a few ms late at a phase near the end
// of the period lands just after the period boundary and is still close.
func phaseOffset(at time.Time, phase, period time.Duration) time.Duration {
	d := (time.Duration(at.UnixNano()) - phase) % period
	if d < 0 {
		d += period
	}
	return min(d, period-d)
}

// keyWithPhase returns a peer key whose phase for period today lies in
// [from, to), so a test can run on a phase near the period edges.
func keyWithPhase(t *testing.T, period, from, to time.Duration) string {
	t.Helper()
	signer, err := phasesig.NewSigner(testPhaseSecret)
	require.NoError(t, err)
	day := phasesig.Day(time.Now())
	raw := make([]byte, 32)
	for i := 0; i < 100000; i++ {
		binary.BigEndian.PutUint64(raw, uint64(i))
		key := base64.StdEncoding.EncodeToString(raw)
		if p := signer.Phase(messages.HashID(key), period, day); p >= from && p < to {
			return key
		}
	}
	t.Fatalf("no peer key with a phase in [%s, %s)", from, to)
	return ""
}

func TestPhaseOffsetWraps(t *testing.T) {
	at := func(ms int64) time.Time { return time.UnixMilli(1_700_000_000_000 + ms) }
	cases := []struct {
		name  string
		at    time.Time
		phase time.Duration
		want  time.Duration
	}{
		{"on the phase", at(250), 250 * time.Millisecond, 0},
		{"late inside the period", at(300), 250 * time.Millisecond, 50 * time.Millisecond},
		{"early inside the period", at(200), 250 * time.Millisecond, 50 * time.Millisecond},
		{"phase near the end, tick late past the boundary", at(1000), 997 * time.Millisecond, 3 * time.Millisecond},
		{"phase near 0, tick early before the boundary", at(998), 0, 2 * time.Millisecond},
		{"phase near 0, tick late", at(1005), 0, 5 * time.Millisecond},
		{"half a period away", at(500), 0, 500 * time.Millisecond},
	}
	for _, tc := range cases {
		assert.Equal(t, tc.want, phaseOffset(tc.at, tc.phase, time.Second), tc.name)
	}
}

// Heartbeats on a phase near 0 or near the end of the period land on it. A tick
// late by a few ms at a phase near the end crosses the period boundary.
func TestConnectStreamPhaseNearPeriodEdges(t *testing.T) {
	cases := []struct {
		name     string
		from, to time.Duration
	}{
		{"phase near 0", 0, 10 * time.Millisecond},
		{"phase near the period end", 990 * time.Millisecond, time.Second},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			peerKey := keyWithPhase(t, time.Second, tc.from, tc.to)
			s := newAlignedTestServer(t)
			req := signedRequest(t, testPhaseSecret, peerKey, time.Second)
			require.True(t, req.Signed.Phase >= tc.from && req.Signed.Phase < tc.to, "signed phase %s", req.Signed.Phase)
			stream := connectTestPeer(t, s, peerKey, alignedhb.MetadataKey, req.Value())
			assertHeartbeatsOn(t, stream, 0, req.Signed.Phase, tc.name)
		})
	}
}

// A stream that opened before the client had a signed phase turns aligned
// when the client sends one, without a reconnect.
func TestConnectStreamSignedPhaseAfterOpen(t *testing.T) {
	const peerKey = "Zm9vYmFyZm9vYmFyZm9vYmFyZm9vYmFyZm9vYmFyMjA="
	s := newAlignedTestServer(t)
	stream := connectTestPeer(t, s, peerKey, alignedhb.MetadataKey, alignedhb.StreamRequest{Period: time.Second}.Value())
	require.Eventually(t, func() bool { return len(stream.answer()) == 1 }, time.Second, 10*time.Millisecond)
	assert.Equal(t, []string{"period=1"}, stream.answer(), "answer without a phase")

	// A correction before the signed phase is ignored: the stream is stock.
	stream.write(t, correction(peerKey, 300*time.Millisecond))
	time.Sleep(1200 * time.Millisecond)
	require.Empty(t, stream.heartbeats(), "a stock stream sends no heartbeats")

	sp := signedRequest(t, testPhaseSecret, peerKey, time.Second).Signed
	stream.write(t, phaseRequest(peerKey, time.Second, *sp))
	assertHeartbeatsOn(t, stream, 0, sp.Phase, "signed phase after open")
	assert.True(t, s.registry.IsPeerRegistered(peerKey), "same stream, no reconnect")
}

// A correction moves the tick of an aligned stream. Invalid requests and a bad
// signature leave it where it is.
func TestConnectStreamPhaseCorrection(t *testing.T) {
	const peerKey = "Zm9vYmFyZm9vYmFyZm9vYmFyZm9vYmFyZm9vYmFyMjE="
	s := newAlignedTestServer(t)
	req := signedRequest(t, testPhaseSecret, peerKey, time.Second)
	stream := connectTestPeer(t, s, peerKey, alignedhb.MetadataKey, req.Value())
	assertHeartbeatsOn(t, stream, 0, req.Signed.Phase, "signed phase at open")

	wanted := (req.Signed.Phase + 500*time.Millisecond) % time.Second
	stream.write(t, correction(peerKey, wanted))
	// Out of the period and a phase signed with another secret: both ignored.
	stream.write(t, correction(peerKey, 5*time.Second))
	bad := signedRequest(t, "other-secret", peerKey, time.Second).Signed
	stream.write(t, phaseRequest(peerKey, time.Second, *bad))
	// The tick planned before the requests may still fire on the old phase.
	time.Sleep(1100 * time.Millisecond)
	assertHeartbeatsOn(t, stream, len(stream.heartbeats()), wanted, "corrected phase")
	assert.True(t, s.registry.IsPeerRegistered(peerKey), "same stream, no reconnect")
}

// The signed phase of the next day moves the stream to it, dropping the
// correction of the old day.
func TestConnectStreamNewDayPhase(t *testing.T) {
	const peerKey = "Zm9vYmFyZm9vYmFyZm9vYmFyZm9vYmFyZm9vYmFyMjI="
	s := newAlignedTestServer(t)
	req := signedRequest(t, testPhaseSecret, peerKey, time.Second)
	stream := connectTestPeer(t, s, peerKey, alignedhb.MetadataKey, req.Value())
	assertHeartbeatsOn(t, stream, 0, req.Signed.Phase, "signed phase at open")

	signer, err := phasesig.NewSigner(testPhaseSecret)
	require.NoError(t, err)
	next, err := signer.SignedPhase(messages.HashID(peerKey), time.Second, time.Now().Add(24*time.Hour))
	require.NoError(t, err)
	if next.Phase == req.Signed.Phase {
		t.Skip("the phase of the next day equals today's")
	}
	stream.write(t, correction(peerKey, (req.Signed.Phase+300*time.Millisecond)%time.Second))
	stream.write(t, phaseRequest(peerKey, time.Second, next))
	time.Sleep(1100 * time.Millisecond)
	assertHeartbeatsOn(t, stream, len(stream.heartbeats()), next.Phase, "phase of the new day")
}
