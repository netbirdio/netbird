package peer

import (
	"context"
	"net"
	"sync/atomic"
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

	// Close drops the flags synchronously, so the assertion below does not
	// converge on the goroutine: the deadline only absorbs the dial goroutine
	// waking up in the background, proving nothing re-wedges it afterwards.
	require.Eventually(t, func() bool {
		return !w.InProgress()
	}, 10*time.Second, 50*time.Millisecond,
		"Close must leave the negotiation idle even while the dial goroutine is still winding down")

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
	t.Cleanup(w.Close)

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

// closeTrackConn records Close calls so a test can assert that a discarded
// connection was actually released.
type closeTrackConn struct {
	net.Conn
	closed atomic.Bool
}

func (c *closeTrackConn) Close() error {
	c.closed.Store(true)
	return c.Conn.Close()
}

// TestWorkerICE_StaleDialSuccessKeepsNewerNegotiation pins the ownership guard
// in connect()'s success path: a dial that came back after a newer negotiation
// replaced the agent must discard its connection and leave the newer session's
// state - agent, agentConnecting, remoteSessionID, lastSuccess - intact.
//
// The dial hook holds session A's goroutine open until session B is installed,
// then returns a live connection, mimicking the vendored pion dial which hands
// out a live *ice.Conn when a pair is selected without checking afterwards
// whether the agent was replaced meanwhile. Releasing A's dial therefore
// exercises the stale-success commit path deterministically instead of racing
// real ICE.
func TestWorkerICE_StaleDialSuccessKeepsNewerNegotiation(t *testing.T) {
	w := newTestWorkerICE(t)
	t.Cleanup(w.Close)

	dialStarted := make(chan struct{})
	releaseDial := make(chan struct{})
	staleConn := &closeTrackConn{}

	var calls atomic.Int32
	w.dialFunc = func(ctx context.Context, _ *icemaker.ThreadSafeAgent, _ *OfferAnswer) (net.Conn, error) {
		if calls.Add(1) == 1 {
			// Session A: hold the goroutine open until session B is installed,
			// then return a live connection, mimicking the vendored pion dial
			// which hands out a live *ice.Conn once a pair is selected without
			// re-checking whether the agent was replaced meanwhile. Releasing
			// the dial therefore exercises the stale-success commit path
			// deterministically instead of racing real ICE.
			close(dialStarted)
			<-releaseDial
			client, _ := net.Pipe()
			staleConn.Conn = client
			return staleConn, nil
		}
		// A newer negotiation parks on its dialer context, cancelled by the
		// t.Cleanup Close at test end.
		<-ctx.Done()
		return nil, ctx.Err()
	}

	sidA := ICESessionID("session-a")
	w.OnNewOffer(&OfferAnswer{
		IceCredentials: IceCredentials{UFrag: "ufragaaaa", Pwd: "pwdpwdpwdpwdpwdpwdpwdp1"},
		SessionID:      &sidA,
	})
	require.True(t, w.InProgress(), "session A must be in flight")

	// Session A's goroutine is now parked in the dial hook.
	<-dialStarted

	sidB := ICESessionID("session-b")
	w.OnNewOffer(&OfferAnswer{
		IceCredentials: IceCredentials{UFrag: "ufragbbbb", Pwd: "pwdpwdpwdpwdpwdpwdpwdp2"},
		SessionID:      &sidB,
	})

	w.muxAgent.Lock()
	agentB := w.agent
	w.lastSuccess = time.Time{}
	w.muxAgent.Unlock()
	require.NotNil(t, agentB, "session B must have created an ICE agent")
	require.True(t, w.InProgress(), "session B must be in flight")

	// Release session A's dial: it must be recognized as stale and discarded.
	close(releaseDial)
	require.Eventually(t, func() bool {
		return staleConn.closed.Load()
	}, 10*time.Second, 10*time.Millisecond,
		"the stale connection must be closed by the ownership guard")

	w.muxAgent.Lock()
	defer w.muxAgent.Unlock()
	assert.Same(t, agentB, w.agent, "session A must not uninstall session B's agent")
	assert.True(t, w.agentConnecting, "session A must not clear session B's connecting flag")
	assert.Equal(t, sidB, w.remoteSessionID, "session A must not clear session B's remote session identity")
	assert.True(t, w.lastSuccess.IsZero(), "session A must not record a success for session B")
	// The commit block guards agentConnecting, lastSuccess and
	// onICEConnectionIsReady together, so the state assertions above imply the
	// callback never ran for session A; the nil conn would have panicked the
	// stale goroutine on any invocation.
}
