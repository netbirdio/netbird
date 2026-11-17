package client

import (
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/hbwatch"
	"github.com/netbirdio/netbird/shared/alignedhb"
	"github.com/netbirdio/netbird/shared/relay/messages"
)

var v2 = messages.NewEncoder(messages.ProtocolV2, messages.MaxMessageSize)

func newTestEcho(t *testing.T, version messages.ProtocolVersion, peer messages.PeerID, authSeq uint64) *alignedEcho {
	t.Helper()
	return newAlignedEcho(messages.NewEncoder(version, messages.MaxMessageSize), peer, time.Minute, authSeq, log.WithField("test", t.Name()))
}

func parseEcho(t *testing.T, msg []byte) messages.HealthcheckEchoMsg {
	t.Helper()
	got, err := messages.UnmarshalHealthcheckEcho(msg)
	require.NoError(t, err)
	return got
}

// A v1 connection answers with the plain health check, whatever it got.
func TestAlignedEchoV1StaysPlain(t *testing.T) {
	e := newTestEcho(t, messages.ProtocolV1, messages.HashID("v1-peer"), 0)
	e.observe(messages.NewEncoder(messages.ProtocolV1, messages.MaxMessageSize).Healthcheck())
	e.correct(5 * time.Second)
	assert.Equal(t, messages.NewEncoder(messages.ProtocolV1, messages.MaxMessageSize).Healthcheck(), e.answer(), "v1 answer")
}

// An aligned connection echoes the server phase, and a correction goes out
// once, with the answer to the heartbeat that triggered it.
func TestAlignedEchoCarriesCorrectionOnce(t *testing.T) {
	e := newTestEcho(t, messages.ProtocolV2, messages.HashID("echo-peer"), 0)
	e.observe(v2.HealthcheckPhase(12345))
	assert.Equal(t, messages.HealthcheckEchoMsg{PhaseMs: 12345, HasPhase: true}, parseEcho(t, e.answer()),
		"no correction: the client wants the server phase")

	e.observe(v2.HealthcheckPhase(12345))
	e.correct(9 * time.Second)
	assert.Equal(t, messages.HealthcheckEchoMsg{PhaseMs: 9000, HasPhase: true}, parseEcho(t, e.answer()),
		"the correction rides on this answer")

	e.observe(v2.HealthcheckPhase(9000))
	assert.Equal(t, messages.HealthcheckEchoMsg{PhaseMs: 9000, HasPhase: true}, parseEcho(t, e.answer()),
		"after the move the client wants the new server phase")
}

// A stock v2 connection answers plain until the client has a signed phase
// newer than the one in its auth, then sends it once with the period.
func TestAlignedEchoSendsNewSignedPhaseOnce(t *testing.T) {
	peer := messages.HashID("late-signed-peer")
	t.Cleanup(func() { alignedhb.ClearSignedPhase(peer) })
	e := newTestEcho(t, messages.ProtocolV2, peer, 0)

	e.observe(v2.Healthcheck())
	assert.Equal(t, v2.Healthcheck(), e.answer(), "stock and no signed phase: plain answer")

	sp := alignedhb.SignedPhase{Phase: 4321 * time.Millisecond, Day: 20405, Signature: []byte{1, 2, 3}}
	alignedhb.StoreSignedPhase(peer, 90*time.Second, sp)
	e.observe(v2.Healthcheck())
	e.correct(time.Second)
	got := parseEcho(t, e.answer())
	assert.Equal(t, messages.HealthcheckEchoMsg{
		PhaseMs:  4321,
		HasPhase: true,
		Ext: messages.AuthExtension{
			PeriodSeconds: 90,
			SignedPhase:   &messages.AuthSignedPhase{PhaseMs: 4321, Day: 20405, Signature: []byte{1, 2, 3}},
		},
	}, got, "the signed phase replaces the pending correction")

	e.observe(v2.Healthcheck())
	assert.Equal(t, v2.Healthcheck(), e.answer(), "the signed phase is sent once")

	// The same phase stored again is not new.
	alignedhb.StoreSignedPhase(peer, 90*time.Second, sp)
	e.observe(v2.Healthcheck())
	assert.Equal(t, v2.Healthcheck(), e.answer(), "an unchanged phase is not sent again")
}

// A signed phase already sent in the auth is not sent again in the echo.
func TestAlignedEchoSkipsPhaseFromAuth(t *testing.T) {
	peer := messages.HashID("auth-signed-peer")
	t.Cleanup(func() { alignedhb.ClearSignedPhase(peer) })
	alignedhb.StoreSignedPhase(peer, time.Minute, alignedhb.SignedPhase{Phase: time.Second, Day: 1, Signature: []byte{1}})
	stored, ok := alignedhb.LoadStoredPhase(peer)
	require.True(t, ok)

	e := newTestEcho(t, messages.ProtocolV2, peer, stored.Seq)
	e.observe(v2.HealthcheckPhase(1000))
	assert.Equal(t, messages.HealthcheckEchoMsg{PhaseMs: 1000, HasPhase: true}, parseEcho(t, e.answer()),
		"no extension for the phase the auth carried")
}

// Only heartbeats with a phase reach the watcher as aligned heartbeats.
func TestAlignedEchoReportsOnlyPhasedHeartbeats(t *testing.T) {
	clk := &jumpClock{now: time.Now()}
	w := hbwatch.New(clk, time.Minute)
	t.Cleanup(hbwatch.SetDefault(w))
	var corrected []time.Duration
	e := newTestEcho(t, messages.ProtocolV2, messages.HashID("watched-peer"), 0)
	w.Register(hbwatch.Relay, hbwatch.Registration{Correct: func(p time.Duration) { corrected = append(corrected, p) }, Stream: e})

	// Two Management heartbeats one period apart make the reference.
	w.Seen(hbwatch.Management, hbwatch.Heartbeat{Period: time.Minute})
	for i := 0; i < 3; i++ {
		clk.jump(time.Minute)
		w.Seen(hbwatch.Management, hbwatch.Heartbeat{Period: time.Minute})
		clk.jump(3 * time.Second)
		e.observe(v2.Healthcheck())
		clk.jump(-3 * time.Second)
	}
	assert.Empty(t, corrected, "stock health checks are not judged")

	for i := 0; i < 2; i++ {
		clk.jump(time.Minute)
		w.Seen(hbwatch.Management, hbwatch.Heartbeat{Period: time.Minute})
		clk.jump(3 * time.Second)
		e.observe(v2.HealthcheckPhase(10000))
		clk.jump(-3 * time.Second)
	}
	assert.Equal(t, []time.Duration{7 * time.Second}, corrected, "aligned heartbeats 3 s late are corrected")
}

// A client can hold several relay connections, but only one is registered.
// Heartbeats of another connection never trigger a correction.
func TestAlignedEchoOtherConnectionNotCorrected(t *testing.T) {
	clk := &jumpClock{now: time.Now()}
	w := hbwatch.New(clk, time.Minute)
	t.Cleanup(hbwatch.SetDefault(w))
	var corrected []time.Duration
	home := newTestEcho(t, messages.ProtocolV2, messages.HashID("home-peer"), 0)
	foreign := newTestEcho(t, messages.ProtocolV2, messages.HashID("home-peer"), 0)
	w.Register(hbwatch.Relay, hbwatch.Registration{Correct: func(p time.Duration) { corrected = append(corrected, p) }, Stream: home})

	w.Seen(hbwatch.Management, hbwatch.Heartbeat{Period: time.Minute})
	for i := 0; i < 4; i++ {
		clk.jump(time.Minute)
		w.Seen(hbwatch.Management, hbwatch.Heartbeat{Period: time.Minute})
		clk.jump(3 * time.Second)
		foreign.observe(v2.HealthcheckPhase(10000))
		clk.jump(-3 * time.Second)
	}
	assert.Empty(t, corrected, "the foreign relay is not the registered connection")
}
