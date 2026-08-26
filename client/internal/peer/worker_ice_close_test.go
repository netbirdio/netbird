package peer

import (
	"context"
	"testing"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	icemaker "github.com/netbirdio/netbird/client/internal/peer/ice"
)

// TestWorkerICE_CloseDuringDial_ClearsConnectingFlag reproduces the teardown race
// between Close() and a blocked ICE dial goroutine.
//
// The real-world sequence this models:
//  1. OnNewOffer starts a negotiation: agent set, agentConnecting = true, go connect()
//  2. The network dies and connect() stays blocked inside agent.Dial
//  3. A WG handshake timeout calls Close(): agent = nil, but agentConnecting is NOT reset
//  4. The stale dial goroutine wakes with an error and runs its cleanup path
//     (closeAgent at worker_ice.go:262), where `w.agent == agent` is now false,
//     so the flag reset is skipped
//
// The result is agent == nil with agentConnecting == true forever: evalConnStatus
// counts InProgress() as iceUp, the guard believes the peer is connected and never
// retries, and same-session offers are dropped at OnNewOffer. Only a restart clears it.
func TestWorkerICE_CloseDuringDial_ClearsConnectingFlag(t *testing.T) {
	config := connConf
	stunTurn := &icemaker.StunTurn{}
	stunTurn.Store(nil)
	config.ICEConfig.StunTurn = stunTurn

	w, err := NewWorkerICE(context.Background(), log.WithField("test", t.Name()), config, nil, nil, nil, nil, false)
	require.NoError(t, err, "worker setup must succeed")

	sid := ICESessionID("test-session-id")
	w.OnNewOffer(&OfferAnswer{
		IceCredentials: IceCredentials{
			UFrag: "testufrag",
			Pwd:   "testpwdtestpwdtestpwd12",
		},
		SessionID: &sid,
	})
	require.True(t, w.InProgress(), "OnNewOffer must mark the negotiation as in progress")

	// The dial goroutine captured this agent when it started; capture it the same way.
	w.muxAgent.Lock()
	agent := w.agent
	w.muxAgent.Unlock()
	require.NotNil(t, agent, "OnNewOffer must have created an ICE agent")

	// Teardown wins the race while connect() is still blocked in Dial.
	w.Close()

	// The stale goroutine eventually observes the cancelled dial context and runs
	// its error-path cleanup, passing the agent it captured (not the field).
	w.closeAgent(agent, w.agentDialerCancel)

	assert.False(t, w.InProgress(),
		"after Close and the dial goroutine's cleanup, no negotiation can be in flight; "+
			"a stuck flag wedges the guard into reporting Connected")
}

// TestWorkerICE_CloseClearsResidualConnectingState covers Close on a worker whose
// agent is already gone but whose flag is stuck on true, e.g. after an aborted
// recreate in OnNewOffer or after a first Close raced a dial goroutine.
func TestWorkerICE_CloseClearsResidualConnectingState(t *testing.T) {
	w, err := NewWorkerICE(context.Background(), log.WithField("test", t.Name()), connConf, nil, nil, nil, nil, false)
	require.NoError(t, err, "worker setup must succeed")

	w.muxAgent.Lock()
	w.agentConnecting = true
	w.muxAgent.Unlock()

	w.Close()

	assert.False(t, w.InProgress(), "Close must drop residual connecting state even without a live agent")
}

// TestWorkerICE_StaleCloseAgentKeepsCurrentSession pins the ownership guard in
// closeAgent: a late-waking dial goroutine from an older session must not reset
// the state of a newer negotiation that reused the worker.
func TestWorkerICE_StaleCloseAgentKeepsCurrentSession(t *testing.T) {
	config := connConf
	stunTurn := &icemaker.StunTurn{}
	stunTurn.Store(nil)
	config.ICEConfig.StunTurn = stunTurn

	w, err := NewWorkerICE(context.Background(), log.WithField("test", t.Name()), config, nil, nil, nil, nil, false)
	require.NoError(t, err, "worker setup must succeed")

	sidA := ICESessionID("session-a")
	w.OnNewOffer(&OfferAnswer{
		IceCredentials: IceCredentials{UFrag: "ufragaaaa", Pwd: "pwdpwdpwdpwdpwdpwdpwdp1"},
		SessionID:      &sidA,
	})
	w.muxAgent.Lock()
	oldAgent := w.agent
	oldCancel := w.agentDialerCancel
	w.muxAgent.Unlock()

	w.Close()

	sidB := ICESessionID("session-b")
	w.OnNewOffer(&OfferAnswer{
		IceCredentials: IceCredentials{UFrag: "ufragbbbb", Pwd: "pwdpwdpwdpwdpwdpwdpwdp2"},
		SessionID:      &sidB,
	})
	require.True(t, w.InProgress(), "the second negotiation must be in flight")

	// The old dial goroutine finally wakes and cleans up its captured agent.
	w.closeAgent(oldAgent, oldCancel)

	assert.True(t, w.InProgress(),
		"a stale session's cleanup must not reset the current negotiation")
}
