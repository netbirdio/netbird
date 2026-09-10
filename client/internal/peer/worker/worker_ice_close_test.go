package worker

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pion/ice/v4"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	icemaker "github.com/netbirdio/netbird/client/internal/peer/ice"
	"github.com/netbirdio/netbird/client/internal/peer/signaling"
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

// newTestWorkerICE collects raw events without applying them. Tests drive the
// worker from their own goroutine, just as the Conn event loop does.
func newTestWorkerICE(t *testing.T) (*ICE, <-chan any) {
	t.Helper()
	stunTurn := &icemaker.StunTurn{}
	stunTurn.Store(nil)
	events := make(chan any, 256)
	post := func(e any) bool {
		select {
		case events <- e:
			return true
		default:
			t.Errorf("unexpected ICE event queue overflow")
			return false
		}
	}
	w, err := NewICE(log.WithField("test", t.Name()), "test-peer", icemaker.Config{StunTurn: stunTurn}, true, post,
		ICEDependencies{Signaler: signaling.NewSignaler(stubSignalClient{}, wgtypes.Key{})}, false)
	require.NoError(t, err)
	t.Cleanup(func() { w.Close() })
	return w, events
}

func testICEOffer(id icemaker.SessionID) *signaling.OfferAnswer {
	return &signaling.OfferAnswer{
		IceCredentials: signaling.IceCredentials{UFrag: "testufrag", Pwd: "testpwdtestpwdtestpwd12"},
		SessionID:      &id,
	}
}

func waitICEDialDone(t *testing.T, events <-chan any, agent *icemaker.ThreadSafeAgent) ICEDialDone {
	t.Helper()
	timer := time.NewTimer(10 * time.Second)
	defer timer.Stop()
	for {
		select {
		case ev := <-events:
			if e, ok := ev.(ICEDialDone); ok {
				if e.Agent == agent {
					return e
				}
				if e.Conn != nil {
					_ = e.Conn.Close()
				}
			}
		case <-timer.C:
			t.Fatal("dial must publish a result")
			return ICEDialDone{}
		}
	}
}

func TestWorkerICE_CloseDuringDial_ClearsConnectingFlag(t *testing.T) {
	w, events := newTestWorkerICE(t)
	w.OnNewOffer(t.Context(), testICEOffer("a"))
	agent := w.agent
	require.True(t, w.InProgress(), "the negotiation must be in progress")
	w.Close()

	// Close clears the state immediately; late dial completion is only data
	// until consumed by the loop, and must not restore the closed agent.
	assert.False(t, w.InProgress(), "Close must clear the connecting snapshot")
	e := waitICEDialDone(t, events, agent)
	_, _, ready := w.OnDialDone(e)
	assert.False(t, ready, "a closed agent's result must be rejected")
	assert.Nil(t, w.agent, "the agent must remain released")
	assert.Empty(t, w.remoteSessionID, "the remote session must remain cleared")
}

func TestWorkerICE_CloseClearsResidualConnectingState(t *testing.T) {
	w, _ := newTestWorkerICE(t)
	w.agentConnecting.Store(true)
	w.Close()
	w.Close()
	assert.False(t, w.InProgress(), "repeated Close must leave the worker idle")
	assert.Nil(t, w.agent, "no agent may survive Close")
}

// The existing ownership guard must still protect a newer negotiation when
// cleanup for an older agent is dispatched on the event loop.
func TestWorkerICE_StaleCloseAgentKeepsCurrentSession(t *testing.T) {
	w, _ := newTestWorkerICE(t)
	w.OnNewOffer(t.Context(), testICEOffer("a"))
	agentA := w.agent
	w.Close()
	w.OnNewOffer(t.Context(), testICEOffer("b"))
	agentB := w.agent
	credentialsB := w.Credentials()

	w.closeAgent(agentA)
	assert.Same(t, agentB, w.agent, "B must remain the current agent")
	assert.True(t, w.InProgress(), "B must remain in flight")
	assert.Equal(t, icemaker.SessionID("b"), w.remoteSessionID, "B's remote session must be preserved")
	assert.Equal(t, credentialsB, w.Credentials(), "old cleanup must not rotate B's credentials")
}

func TestWorkerICE_PionStateChangesWaitForEventLoop(t *testing.T) {
	w, events := newTestWorkerICE(t)
	w.OnNewOffer(t.Context(), testICEOffer("a"))
	agent := w.agent
	require.NoError(t, agent.Close())

	timer := time.NewTimer(10 * time.Second)
	defer timer.Stop()
	for {
		select {
		case ev := <-events:
			switch e := ev.(type) {
			case ICEStateChanged:
				if e.State != ice.ConnectionStateClosed {
					continue
				}
				assert.True(t, w.InProgress(), "Pion's callback must not change worker state")
				assert.Same(t, agent, w.agent, "the event loop still owns the agent")
				w.OnConnectionStateChange(e)
				assert.False(t, w.InProgress(), "consuming Closed must clear the connecting state")
				assert.Nil(t, w.agent, "consuming Closed must release the agent")
				return
			case ICEDialDone:
				if e.Conn != nil {
					_ = e.Conn.Close()
				}
			}
		case <-timer.C:
			t.Fatal("Pion must post Closed to the event queue")
		}
	}
}

type closeTrackConn struct {
	net.Conn
	closed atomic.Bool
}

func (c *closeTrackConn) Close() error {
	c.closed.Store(true)
	return c.Conn.Close()
}

func TestWorkerICE_StaleDialSuccessKeepsNewerNegotiation(t *testing.T) {
	w, events := newTestWorkerICE(t)
	dialStarted := make(chan struct{})
	releaseDial := make(chan struct{})
	client, server := net.Pipe()
	t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
	staleConn := &closeTrackConn{Conn: client}
	w.dialFunc = func(ctx context.Context, _ *icemaker.ThreadSafeAgent, _ *signaling.OfferAnswer) (net.Conn, error) {
		close(dialStarted)
		select {
		case <-releaseDial:
			return staleConn, nil
		case <-t.Context().Done():
			return nil, ctx.Err()
		}
	}
	w.OnNewOffer(t.Context(), testICEOffer("a"))
	agentA := w.agent
	select {
	case <-dialStarted:
	case <-time.After(10 * time.Second):
		t.Fatal("A's dial must start")
	}

	// OnNewOffer captures the dial function before spawning the goroutine.
	w.dialFunc = func(ctx context.Context, _ *icemaker.ThreadSafeAgent, _ *signaling.OfferAnswer) (net.Conn, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	w.OnNewOffer(t.Context(), testICEOffer("b"))
	agentB := w.agent
	close(releaseDial)
	e := waitICEDialDone(t, events, agentA)
	assert.False(t, staleConn.closed.Load(), "a successfully posted result is owned by the event loop")
	_, _, ready := w.OnDialDone(e)
	assert.False(t, ready, "A's late result must not be accepted")
	assert.True(t, staleConn.closed.Load(), "the consumer must release A's connection")
	assert.Same(t, agentB, w.agent, "A's result must leave B installed")
	assert.True(t, w.InProgress(), "B must remain in flight")
}

func TestWorkerICE_RejectedDialEventClosesConnection(t *testing.T) {
	w, _ := newTestWorkerICE(t)
	w.postEvent = func(any) bool { return false }
	client, server := net.Pipe()
	t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
	remote := &closeTrackConn{Conn: client}
	w.dialFunc = func(context.Context, *icemaker.ThreadSafeAgent, *signaling.OfferAnswer) (net.Conn, error) {
		return remote, nil
	}
	w.OnNewOffer(t.Context(), testICEOffer("a"))
	require.Eventually(t, remote.closed.Load, 10*time.Second, time.Millisecond,
		"when the mailbox rejects the result the producer must close its connection")
}
