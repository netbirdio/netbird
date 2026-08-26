package peer

import (
	"context"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	icemaker "github.com/netbirdio/netbird/client/internal/peer/ice"
	signal "github.com/netbirdio/netbird/shared/signal/client"
	sProto "github.com/netbirdio/netbird/shared/signal/proto"
)

// stubSignalClient satisfies signal.Client as a no-op so the candidate
// goroutine spawned by a real GatherCandidates never dereferences a nil
// signaler in tests.
type stubSignalClient struct{}

func (stubSignalClient) Close() error                                               { return nil }
func (stubSignalClient) StreamConnected() bool                                      { return false }
func (stubSignalClient) GetStatus() signal.Status                                   { return signal.StreamDisconnected }
func (stubSignalClient) Receive(context.Context, func(*sProto.Message) error) error { return nil }
func (stubSignalClient) Ready() bool                                                { return false }
func (stubSignalClient) IsHealthy() bool                                            { return false }
func (stubSignalClient) WaitStreamConnected(context.Context)                        {}
func (stubSignalClient) SendToStream(*sProto.EncryptedMessage) error                { return nil }
func (stubSignalClient) Send(*sProto.Message) error                                 { return nil }
func (stubSignalClient) SetOnReconnectedListener(func())                            {}

// newTestWorkerICE builds a worker with real pion plumbing and no-op signaling.
func newTestWorkerICE(t *testing.T) *WorkerICE {
	t.Helper()

	config := connConf
	stunTurn := &icemaker.StunTurn{}
	stunTurn.Store(nil)
	config.ICEConfig.StunTurn = stunTurn

	w, err := NewWorkerICE(context.Background(), log.WithField("test", t.Name()), config, nil,
		NewSignaler(stubSignalClient{}, wgtypes.Key{}), nil, nil, false)
	require.NoError(t, err, "worker setup must succeed")
	return w
}

// TestWorkerICE_CloseDuringDial_ClearsConnectingFlag drives the teardown race
// through the real dial goroutine instead of simulating its cleanup.
//
// The real-world sequence this models:
//  1. OnNewOffer starts a negotiation: agent set, agentConnecting = true,
//     go connect()
//  2. The network dies and connect() stays blocked inside GatherCandidates/Dial
//  3. A WG handshake timeout calls Close(): the agent is released and the dial
//     context cancelled, but agentConnecting is not reset
//  4. The real goroutine wakes with an error and runs its own cleanup
//     (closeAgent), where `w.agent == agent` is now false, so the flag reset
//     is skipped
//
// There is no remote responder, so Dial can never succeed: whatever point the
// goroutine is at, closing first forces it down the error path. Before the fix
// the flag stays true forever and the deadline below expires.
func TestWorkerICE_CloseDuringDial_ClearsConnectingFlag(t *testing.T) {
	w := newTestWorkerICE(t)

	sid := ICESessionID("test-session-id")
	w.OnNewOffer(&OfferAnswer{
		IceCredentials: IceCredentials{
			UFrag: "testufrag",
			Pwd:   "testpwdtestpwdtestpwd12",
		},
		SessionID: &sid,
	})
	require.True(t, w.InProgress(), "OnNewOffer must mark the negotiation as in progress")

	// Teardown wins the race while connect() is still running.
	w.Close()

	// The goroutine has no joinable handle; its terminal effect is the flag
	// state, so converge on it with a deadline. The goroutine observes the
	// cancelled context within milliseconds on both fixed and unfixed code;
	// only the resulting state differs.
	require.Eventually(t, func() bool {
		return !w.InProgress()
	}, 10*time.Second, 50*time.Millisecond,
		"the stale dial goroutine's cleanup must leave the negotiation idle")

	// abandonNegotiation owns these three fields together; the worker is idle
	// only when all of them are dropped.
	w.muxAgent.Lock()
	defer w.muxAgent.Unlock()
	assert.Nil(t, w.agent, "no agent may survive the teardown")
	assert.False(t, w.agentConnecting, "the connecting flag must match the nil agent")
	assert.Empty(t, w.remoteSessionID, "a dead session's remote ID must not linger")
}

// TestWorkerICE_CloseClearsResidualConnectingState covers Close on a worker whose
// agent is already gone but whose flag is stuck on true, e.g. after an aborted
// recreate in OnNewOffer or after a first Close raced a dial goroutine.
func TestWorkerICE_CloseClearsResidualConnectingState(t *testing.T) {
	w := newTestWorkerICE(t)

	w.muxAgent.Lock()
	w.agentConnecting = true
	w.muxAgent.Unlock()

	w.Close()

	assert.False(t, w.InProgress(), "Close must drop residual connecting state even without a live agent")

	w.muxAgent.Lock()
	defer w.muxAgent.Unlock()
	assert.Nil(t, w.agent)
	assert.False(t, w.agentConnecting)
	assert.Empty(t, w.remoteSessionID)
}

// TestWorkerICE_StaleCloseAgentKeepsCurrentSession pins the ownership guard in
// closeAgent: a late-waking dial goroutine from an older session must not reset
// the state of a newer negotiation that reused the worker. The newer session
// must survive wholesale - agent, flag and remote session identity alike.
func TestWorkerICE_StaleCloseAgentKeepsCurrentSession(t *testing.T) {
	w := newTestWorkerICE(t)

	sidA := ICESessionID("session-a")
	w.OnNewOffer(&OfferAnswer{
		IceCredentials: IceCredentials{UFrag: "ufragaaaa", Pwd: "pwdpwdpwdpwdpwdpwdpwdp1"},
		SessionID:      &sidA,
	})
	w.muxAgent.Lock()
	oldAgent := w.agent
	oldCancel := w.agentDialerCancel
	w.muxAgent.Unlock()
	require.NotNil(t, oldAgent, "OnNewOffer must have created an ICE agent")

	w.Close()

	sidB := ICESessionID("session-b")
	w.OnNewOffer(&OfferAnswer{
		IceCredentials: IceCredentials{UFrag: "ufragbbbb", Pwd: "pwdpwdpwdpwdpwdpwdpwdp2"},
		SessionID:      &sidB,
	})
	require.True(t, w.InProgress(), "the second negotiation must be in flight")

	w.muxAgent.Lock()
	newAgent := w.agent
	w.muxAgent.Unlock()

	// The old dial goroutine finally wakes and cleans up its captured agent.
	w.closeAgent(oldAgent, oldCancel)

	w.muxAgent.Lock()
	defer w.muxAgent.Unlock()
	assert.Same(t, newAgent, w.agent, "the current agent must be untouched by the stale cleanup")
	assert.True(t, w.agentConnecting, "the current negotiation must stay in flight")
	// Read live under the lock: a snapshot captured before the stale cleanup
	// would pass even if the cleanup wiped current state.
	assert.Equal(t, sidB, w.remoteSessionID, "the remote session identity must be preserved")
}
