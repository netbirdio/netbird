package server

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/shared/alignedhb"
	"github.com/netbirdio/netbird/shared/alignedhb/phasesig"
	"github.com/netbirdio/netbird/shared/relay/healthcheck"
	"github.com/netbirdio/netbird/shared/relay/messages"
)

// heartbeatPhases returns the phase of every health check the server wrote
// after skip frames, -1 for one without a phase.
func heartbeatPhases(t *testing.T, conn *scriptedConn, skip int) []int64 {
	t.Helper()
	var out []int64
	frames := conn.frames()
	for _, f := range frames[min(skip, len(frames)):] {
		msgType, err := messages.DetermineServerMessageType(f)
		require.NoError(t, err)
		if msgType != messages.MsgTypeHealthCheck {
			continue
		}
		phase, ok, err := messages.UnmarshalHealthcheckPhase(f)
		require.NoError(t, err)
		if !ok {
			out = append(out, -1)
			continue
		}
		out = append(out, int64(phase))
	}
	return out
}

// waitHeartbeats waits until the server wrote n health checks after skip frames.
func waitHeartbeats(t *testing.T, conn *scriptedConn, skip, n int) []int64 {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		phases := heartbeatPhases(t, conn, skip)
		if len(phases) >= n {
			return phases
		}
		if time.Now().After(deadline) {
			t.Fatalf("expected %d heartbeats, got %d", n, len(phases))
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func echo(phaseMs uint32, ext []byte) []byte {
	return messages.NewEncoder(messages.ProtocolV2, messages.MaxMessageSize).HealthcheckEcho(phaseMs, ext)
}

// An aligned connection sends its phase in every health check and moves its
// tick to the phase the client asks for, without a reconnect.
func TestRelay_PhaseRequestMovesTick(t *testing.T) {
	peerID := messages.HashID("correcting-client")
	ext, sp := signedExtension(t, testPhaseSecret, peerID, time.Second)
	validator := &recordingValidator{}
	relay := newAlignedTestRelay(t, validator)
	p := acceptEnvelope(t, relay, validator, messages.ProtocolV2, peerID, ext)
	conn := p.conn.(*scriptedConn)

	phases := waitHeartbeats(t, conn, 1, 1)
	assert.Equal(t, sp.Phase.Milliseconds(), phases[0], "the heartbeat carries the signed phase")

	wanted := uint32((sp.Phase + 400*time.Millisecond).Milliseconds() % 1000)
	conn.deliver(t, echo(wanted, nil))
	require.Eventually(t, func() bool {
		s := scheduleOf(p)
		return s != nil && s.Phase == time.Duration(wanted)*time.Millisecond
	}, 2*time.Second, 10*time.Millisecond, "the server must follow the requested phase")

	skip := len(conn.frames())
	phases = waitHeartbeats(t, conn, skip, 2)
	assert.Equal(t, int64(wanted), phases[1], "later heartbeats carry the new phase")
	assert.False(t, conn.isClosed(), "a phase change must not close the connection")
}

// A v2 connection that opened without a signed phase keeps the stock health
// check until the echo carries one, then switches to the aligned heartbeat.
func TestRelay_SignedPhaseInEchoTurnsAlignedOn(t *testing.T) {
	peerID := messages.HashID("late-phase-client")
	period, err := messages.MarshalAuthExtension(messages.AuthExtension{PeriodSeconds: 1})
	require.NoError(t, err)
	validator := &recordingValidator{}
	relay := newAlignedTestRelay(t, validator)
	p := acceptEnvelope(t, relay, validator, messages.ProtocolV2, peerID, period)
	conn := p.conn.(*scriptedConn)
	require.Nil(t, scheduleOf(p), "stock until the signed phase arrives")

	ext, sp := signedExtension(t, testPhaseSecret, peerID, time.Second)
	conn.deliver(t, echo(uint32(sp.Phase.Milliseconds()), ext))
	require.Eventually(t, func() bool { return scheduleOf(p) != nil }, 2*time.Second, 10*time.Millisecond,
		"a valid signed phase in the echo must turn the aligned heartbeat on")
	assert.Equal(t, sp.Phase, scheduleOf(p).Phase, "the relay ticks on the signed phase")

	phases := waitHeartbeats(t, conn, 1, 2)
	assert.Equal(t, sp.Phase.Milliseconds(), phases[1], "aligned heartbeats carry the phase")
}

// A bad signature in a later echo keeps the connection stock and open, and a
// phase alone does nothing on a stock connection.
func TestRelay_BadSignedPhaseInEchoStaysStock(t *testing.T) {
	peerID := messages.HashID("bad-phase-client")
	period, err := messages.MarshalAuthExtension(messages.AuthExtension{PeriodSeconds: 1})
	require.NoError(t, err)
	validator := &recordingValidator{}
	relay := newAlignedTestRelay(t, validator)
	p := acceptEnvelope(t, relay, validator, messages.ProtocolV2, peerID, period)
	conn := p.conn.(*scriptedConn)

	ext, sp := signedExtension(t, "other-secret", peerID, time.Second)
	conn.deliver(t, echo(uint32(sp.Phase.Milliseconds()), ext))
	conn.deliver(t, echo(123, nil))
	conn.deliver(t, []byte{byte(messages.ProtocolV2), byte(messages.MsgTypeHealthCheck), 1})
	time.Sleep(1500 * time.Millisecond)

	assert.Nil(t, scheduleOf(p), "a bad signature must keep the stock health check")
	assert.Empty(t, heartbeatPhases(t, conn, 1), "no aligned heartbeat on a stock connection")
	assert.False(t, conn.isClosed(), "a bad signature must not close the connection")
}

// A v1 connection writes plain health checks and ignores any payload.
func TestRelay_V1HealthcheckHasNoPhase(t *testing.T) {
	p := NewPeer(nil, messages.HashID("v1-client"), messages.ProtocolV1, newScriptedConn(), nil, nil)
	assert.Equal(t, messages.NewEncoder(messages.ProtocolV1, messages.MaxMessageSize).Healthcheck(), healthcheckMsg(p), "v1 health check")
	p.handleHealthcheckEcho(echo(5, nil), nil)
	assert.Nil(t, scheduleOf(p), "v1 ignores phase requests")
}

// A v1 connection never takes an aligned schedule, so it always runs the stock
// health check from connect.
func TestRelay_V1IgnoresAlignedSchedule(t *testing.T) {
	p := NewPeer(nil, messages.HashID("stock-client"), messages.ProtocolV1, newScriptedConn(), nil, nil)
	p.setAlignedSchedule(&verifiedPhase{schedule: healthcheck.AlignedSchedule{Period: time.Minute, Phase: time.Second}, day: 1})
	assert.Nil(t, scheduleOf(p), "v1 must keep the stock health check")
	assert.Equal(t, messages.NewEncoder(messages.ProtocolV1, messages.MaxMessageSize).Healthcheck(), healthcheckMsg(p), "v1 health check")
}

// scheduleOf returns the aligned schedule of p, nil while it is stock.
func scheduleOf(p *Peer) *healthcheck.AlignedSchedule {
	s, ok := p.phase.Schedule()
	if !ok {
		return nil
	}
	hs := healthcheck.AlignedSchedule(s)
	return &hs
}

func relayPhase(t *testing.T, p *Peer) time.Duration {
	t.Helper()
	s := scheduleOf(p)
	require.NotNil(t, s, "the connection must be aligned")
	return s.Phase
}

// healthcheckMsg returns the health check frame the relay sends to p.
func healthcheckMsg(p *Peer) []byte {
	msg, _ := p.healthcheckFrame()
	return msg
}

func phaseEcho(phase time.Duration) []byte {
	return echo(uint32(phase.Milliseconds()), nil)
}

// A signed phase in an echo turns a stock connection aligned only when
// Management signed it for this peer.
func TestRelay_SignedPhaseInEchoVerifiesPeer(t *testing.T) {
	peerID := messages.HashID("signed-echo-client")
	verifier, err := phasesig.NewVerifier(testPhaseSecret)
	require.NoError(t, err)
	conn := &tunableConn{scriptedConn: newScriptedConn()}
	p := NewPeer(nil, peerID, messages.ProtocolV2, conn, nil, nil)
	p.setPhaseVerifier(verifier, alignedhb.PeriodLimits{})
	hc := healthcheck.NewSender(p.log)

	other, _ := signedExtension(t, testPhaseSecret, messages.HashID("other-client"), time.Minute)
	p.handleHealthcheckEcho(echo(0, other), hc)
	assert.Nil(t, scheduleOf(p), "a phase signed for another peer must keep the connection stock")
	assert.Zero(t, conn.tunedPeriod(), "a stock connection keeps the stock transport")

	ext, sp := signedExtension(t, testPhaseSecret, peerID, time.Minute)
	p.handleHealthcheckEcho(echo(uint32(sp.Phase.Milliseconds()), ext), hc)
	assert.Equal(t, sp.Phase, relayPhase(t, p), "a phase signed for the peer must turn the connection aligned")
	assert.Equal(t, time.Minute, conn.tunedPeriod(), "the transport follows the aligned period")
}

// signedExtensionAt returns the auth extension with the phase Management signs
// for peerID and period on the day of at, and that phase.
func signedExtensionAt(t *testing.T, peerID messages.PeerID, period time.Duration, at time.Time) ([]byte, time.Duration) {
	t.Helper()
	signer, err := phasesig.NewSigner(testPhaseSecret)
	require.NoError(t, err)
	sp, err := signer.SignedPhase(peerID, period, at)
	require.NoError(t, err)
	ext, err := messages.MarshalAuthExtension(messages.AuthExtension{
		PeriodSeconds: uint16(period / time.Second),
		SignedPhase: &messages.AuthSignedPhase{
			PhaseMs:   uint32(sp.Phase.Milliseconds()),
			Day:       sp.Day,
			Signature: sp.Signature,
		},
	})
	require.NoError(t, err)
	return ext, sp.Phase
}

// Signatures stay valid for a day around today. Once a connection has a
// verified signed phase, only a phase of a newer day replaces it, so a client
// cannot flip the tick between the phases of two days.
func TestRelay_SignedPhaseOnlyNewerDay(t *testing.T) {
	peerID := messages.HashID("two-day-client")
	verifier, err := phasesig.NewVerifier(testPhaseSecret)
	require.NoError(t, err)
	now := time.Now()
	yesterday, yesterdayPhase := signedExtensionAt(t, peerID, time.Minute, now.Add(-24*time.Hour))
	today, todayPhase := signedExtensionAt(t, peerID, time.Minute, now)
	tomorrow, tomorrowPhase := signedExtensionAt(t, peerID, time.Minute, now.Add(24*time.Hour))
	if yesterdayPhase == todayPhase || todayPhase == tomorrowPhase {
		t.Skip("two days share a phase")
	}
	p := NewPeer(nil, peerID, messages.ProtocolV2, newScriptedConn(), nil, nil)
	p.setPhaseVerifier(verifier, alignedhb.PeriodLimits{})
	hc := healthcheck.NewSender(p.log)
	send := func(ext []byte, phase time.Duration) {
		p.handleHealthcheckEcho(echo(uint32(phase.Milliseconds()), ext), hc)
	}

	send(today, todayPhase)
	assert.Equal(t, todayPhase, relayPhase(t, p), "the first signed phase must turn the connection aligned")

	send(yesterday, yesterdayPhase)
	assert.Equal(t, todayPhase, relayPhase(t, p), "a phase of an older day must be ignored")

	sameDay, sameDayPhase := signedExtensionAt(t, peerID, 2*time.Minute, now)
	send(sameDay, sameDayPhase)
	assert.Equal(t, healthcheck.AlignedSchedule{Period: time.Minute, Phase: todayPhase}, *scheduleOf(p),
		"another phase of the same day must be ignored")

	send(tomorrow, tomorrowPhase)
	assert.Equal(t, tomorrowPhase, relayPhase(t, p), "the phase of a newer day must apply")

	send(today, todayPhase)
	assert.Equal(t, tomorrowPhase, relayPhase(t, p), "the tick must not flip back to the older day")
}

// A connection that opened with a signed phase keeps its day: an older phase
// sent in an echo later is ignored.
func TestRelay_HandshakeSignedKeepsDay(t *testing.T) {
	peerID := messages.HashID("handshake-day-client")
	verifier, err := phasesig.NewVerifier(testPhaseSecret)
	require.NoError(t, err)
	now := time.Now()
	open, openPhase := signedExtensionAt(t, peerID, time.Minute, now)
	yesterday, yesterdayPhase := signedExtensionAt(t, peerID, time.Minute, now.Add(-24*time.Hour))
	if openPhase == yesterdayPhase {
		t.Skip("two days share a phase")
	}
	ext, err := messages.UnmarshalAuthExtension(open)
	require.NoError(t, err)
	p := NewPeer(nil, peerID, messages.ProtocolV2, newScriptedConn(), nil, nil)
	p.setPhaseVerifier(verifier, alignedhb.PeriodLimits{})
	p.setAlignedSchedule(verifySignedPhase(ext, peerID, verifier, alignedhb.PeriodLimits{}, nil, now))
	require.Equal(t, openPhase, relayPhase(t, p), "the connection must open aligned")

	// The echo asks for the current phase, so only the signed phase could move it.
	p.handleHealthcheckEcho(echo(uint32(openPhase.Milliseconds()), yesterday), healthcheck.NewSender(p.log))
	s := scheduleOf(p)
	assert.Equal(t, openPhase, s.Phase, "a phase of an older day must be ignored")
}

// clampedExtension returns the auth extension of a client that asks for
// requested with the phase Management signed for the clamped period signedFor.
func clampedExtension(t *testing.T, peerID messages.PeerID, requested, signedFor time.Duration) ([]byte, time.Duration) {
	t.Helper()
	signer, err := phasesig.NewSigner(testPhaseSecret)
	require.NoError(t, err)
	sp, err := signer.SignedPhase(peerID, signedFor, time.Now())
	require.NoError(t, err)
	ext, err := messages.MarshalAuthExtension(messages.AuthExtension{
		PeriodSeconds: uint16(requested / time.Second),
		SignedPhase: &messages.AuthSignedPhase{
			PhaseMs:   uint32(sp.Phase.Milliseconds()),
			Day:       sp.Day,
			Signature: sp.Signature,
		},
	})
	require.NoError(t, err)
	return ext, sp.Phase
}

// The relay clamps the requested period to its limits before it verifies the
// signed phase, so it accepts the phase Management signed for the clamped
// period, and the health check runs on that period.
func TestRelay_HandshakeClampsPeriod(t *testing.T) {
	for requested, want := range map[time.Duration]time.Duration{
		time.Second:        30 * time.Second,
		1000 * time.Second: 300 * time.Second,
		time.Minute:        time.Minute,
	} {
		peerID := messages.HashID("clamp-client-" + requested.String())
		ext, phase := clampedExtension(t, peerID, requested, want)
		validator := &recordingValidator{}
		relay := newAlignedTestRelayLimits(t, validator, alignedhb.PeriodLimits{})
		p := acceptEnvelope(t, relay, validator, messages.ProtocolV2, peerID, ext)

		s := scheduleOf(p)
		require.NotNil(t, s, "requested %s: the phase signed for the clamped period must be accepted", requested)
		assert.Equal(t, healthcheck.AlignedSchedule{Period: want, Phase: phase}, *s, "requested %s: schedule", requested)
	}
}

// A phase signed for a period outside the limits never verifies, in the
// handshake and in a later echo.
func TestRelay_SignedOutsideLimitsStaysStock(t *testing.T) {
	peerID := messages.HashID("outside-limits-client")
	verifier, err := phasesig.NewVerifier(testPhaseSecret)
	require.NoError(t, err)
	raw, phase := clampedExtension(t, peerID, time.Second, time.Second)
	ext, err := messages.UnmarshalAuthExtension(raw)
	require.NoError(t, err)
	assert.Nil(t, verifySignedPhase(ext, peerID, verifier, alignedhb.PeriodLimits{}, nil, time.Now()),
		"a phase signed for 1s must not verify with the default limits")

	p := NewPeer(nil, peerID, messages.ProtocolV2, newScriptedConn(), nil, nil)
	p.setPhaseVerifier(verifier, alignedhb.PeriodLimits{})
	p.handleHealthcheckEcho(echo(uint32(phase.Milliseconds()), raw), healthcheck.NewSender(p.log))
	assert.Nil(t, scheduleOf(p), "a phase signed for 1s in an echo must keep the connection stock")
}

// A signed phase in an echo has its period clamped the same way.
func TestRelay_SignedPhaseInEchoClampsPeriod(t *testing.T) {
	verifier, err := phasesig.NewVerifier(testPhaseSecret)
	require.NoError(t, err)
	for requested, want := range map[time.Duration]time.Duration{
		time.Second:        30 * time.Second,
		1000 * time.Second: 300 * time.Second,
		time.Minute:        time.Minute,
	} {
		peerID := messages.HashID("echo-clamp-client-" + requested.String())
		ext, phase := clampedExtension(t, peerID, requested, want)
		p := NewPeer(nil, peerID, messages.ProtocolV2, newScriptedConn(), nil, nil)
		p.setPhaseVerifier(verifier, alignedhb.PeriodLimits{})
		p.handleHealthcheckEcho(echo(uint32(phase.Milliseconds()), ext), healthcheck.NewSender(p.log))

		s := scheduleOf(p)
		require.NotNil(t, s, "requested %s: the phase signed for the clamped period must be accepted", requested)
		assert.Equal(t, healthcheck.AlignedSchedule{Period: want, Phase: phase}, *s, "requested %s: schedule", requested)
	}
}

// Config may only narrow the default range: limits outside it are rejected
// when the relay starts.
func TestRelay_ConfigRejectsBadPeriodLimits(t *testing.T) {
	for name, limits := range map[string]alignedhb.PeriodLimits{
		"max below min":  {Min: time.Minute, Max: 45 * time.Second},
		"min below 30s":  {Min: 10 * time.Second, Max: alignedhb.MaxPeriod},
		"max above 300s": {Min: alignedhb.MinPeriod, Max: 600 * time.Second},
		"both outside":   {Min: 10 * time.Second, Max: 600 * time.Second},
	} {
		_, err := NewRelay(Config{
			ExposedAddress: "rel://127.0.0.1:1234",
			AuthValidator:  &recordingValidator{},
			PeriodLimits:   limits,
		})
		assert.Error(t, err, "case %s must be rejected", name)
	}

	relay, err := NewRelay(Config{
		ExposedAddress: "rel://127.0.0.1:1234",
		AuthValidator:  &recordingValidator{},
		PeriodLimits:   alignedhb.PeriodLimits{Min: 45 * time.Second, Max: 120 * time.Second},
	})
	require.NoError(t, err, "a narrower range is accepted")
	relay.Shutdown(context.Background())
}
