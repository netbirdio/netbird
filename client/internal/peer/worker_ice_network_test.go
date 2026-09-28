package peer

import (
	"context"
	"testing"
	"time"

	"github.com/pion/ice/v4"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/internal/peer/conntype"
	"github.com/netbirdio/netbird/client/internal/peer/guard"
	icemaker "github.com/netbirdio/netbird/client/internal/peer/ice"
	"github.com/netbirdio/netbird/client/internal/peer/worker"
	"github.com/netbirdio/netbird/client/netevents"
)

type networkRecorderStub struct{}

func (networkRecorderStub) SetNetworkAvailable(bool) {}

// TestICEAgentSweptOnNetworkChange covers direct paths that must not wait for ICE timeouts.
func TestICEAgentSweptOnNetworkChange(t *testing.T) {
	for _, offline := range []bool{false, true} {
		name := "handover"
		if offline {
			name = "offline"
		}
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			manager := netevents.NewManager(networkRecorderStub{})
			worker := &WorkerICE{ctx: ctx, conn: &Conn{ctx: ctx}, log: log.NewEntry(log.New()), config: ConnConfig{
				NetMgr: manager, ICEConfig: icemaker.Config{StunTurn: &icemaker.StunTurn{}},
			}}
			agent, release, err := worker.reCreateAgent(cancel, []ice.CandidateType{ice.CandidateTypeHost})
			require.NoError(t, err)
			defer release()
			defer agent.Close()
			if offline {
				manager.SetNetworkAvailable(false)
			} else {
				manager.NotifyNetworkChange()
			}
			require.Eventually(t, func() bool {
				_, _, err := agent.GetLocalUserCredentials()
				return err != nil
			}, 2*time.Second, 10*time.Millisecond, "network changes must close ICE without waiting for peer timeouts")
		})
	}
}

// TestICEAgentCreatedAfterNetworkChangeSurvivesPendingSweep protects recovery on the new path.
func TestICEAgentCreatedAfterNetworkChangeSurvivesPendingSweep(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	manager := netevents.NewManager(networkRecorderStub{})
	manager.NotifyNetworkChange()
	worker := &WorkerICE{ctx: ctx, conn: &Conn{ctx: ctx}, log: log.NewEntry(log.New()), config: ConnConfig{
		NetMgr: manager, ICEConfig: icemaker.Config{StunTurn: &icemaker.StunTurn{}},
	}}
	agent, release, err := worker.reCreateAgent(cancel, []ice.CandidateType{ice.CandidateTypeHost})
	require.NoError(t, err)
	defer release()
	defer agent.Close()
	require.Never(t, func() bool {
		_, _, err := agent.GetLocalUserCredentials()
		return err != nil
	}, time.Second, 10*time.Millisecond, "a pending sweep must preserve ICE agents created on the new network")
}

// Normal teardown must release the sweep registration without an ICE callback.
func TestICEAgentTeardownWithoutStateCallback(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dialCtx, dialCancel := context.WithCancel(ctx)
	worker := &WorkerICE{ctx: ctx, conn: &Conn{ctx: ctx}, log: log.NewEntry(log.New()), config: ConnConfig{
		NetMgr:    netevents.NewManager(networkRecorderStub{}),
		ICEConfig: icemaker.Config{StunTurn: &icemaker.StunTurn{}},
	}}
	agent, release, err := worker.reCreateAgent(dialCancel, []ice.CandidateType{ice.CandidateTypeHost})
	require.NoError(t, err)
	defer release()
	defer agent.Close()
	// Remove the fallback callback: cancellation must own cleanup itself.
	require.NoError(t, agent.OnConnectionStateChange(func(ice.ConnectionState) {}))
	release()
	release() // Terminal callbacks and explicit teardown may race; release is idempotent.
	require.ErrorIs(t, dialCtx.Err(), context.Canceled)
	require.Eventually(t, func() bool {
		_, _, err := agent.GetLocalUserCredentials()
		return err != nil
	}, time.Second, time.Millisecond, "releasing the registration must close the agent without a network event")
}

// Retired callbacks must leave the replacement's state and session bookkeeping intact.
func TestRetiredICECallbacksPreserveReplacement(t *testing.T) {
	for _, state := range []ice.ConnectionState{ice.ConnectionStateConnected, ice.ConnectionStateFailed, ice.ConnectionStateDisconnected, ice.ConnectionStateClosed} {
		t.Run(state.String(), func(t *testing.T) {
			w := newTestWorkerICE(t)
			conn, endpoint := connectedCallbackTestConn()
			w.conn = conn
			old, release, err := w.reCreateAgent(func() {}, []ice.CandidateType{ice.CandidateTypeHost})
			require.NoError(t, err)
			t.Cleanup(release)
			t.Cleanup(func() { _ = old.Close() })
			require.NoError(t, old.OnConnectionStateChange(func(ice.ConnectionState) {}))
			replacement := &icemaker.ThreadSafeAgent{}
			w.agent = replacement
			w.remoteSessionChanged = true
			w.remoteSessionID = "replacement"
			w.lastKnownState = ice.ConnectionStateConnected
			if state == ice.ConnectionStateConnected {
				w.lastKnownState = ice.ConnectionStateChecking
			}
			before := w.lastKnownState
			w.onConnectionStateChange(old, release)(state)
			require.Equal(t, 0, endpoint.removals, "retired callback must not remove the replacement endpoint")
			require.Equal(t, conntype.ICEP2P, conn.currentConnPriority, "replacement priority must remain intact")
			require.Same(t, replacement, w.agent, "retired callback must preserve current agent")
			require.Equal(t, before, w.lastKnownState, "retired callback must not alter replacement state")
			require.True(t, w.remoteSessionChanged, "retired callback must not consume replacement bookkeeping")
			require.Equal(t, ICESessionID("replacement"), w.remoteSessionID, "replacement session must survive")
		})
	}
}

// A callback queued behind Conn's lock must recheck ownership after replacement.
func TestICECallbackRechecksOwnershipAfterWaitingForConn(t *testing.T) {
	w := newTestWorkerICE(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	w.conn = &Conn{ctx: ctx}
	old := &icemaker.ThreadSafeAgent{}
	replacement := &icemaker.ThreadSafeAgent{}
	w.agent = old
	w.lastKnownState = ice.ConnectionStateConnected
	w.conn.mu.Lock()
	entered := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		w.onConnectionStateChange(old, func() { close(entered) })(ice.ConnectionStateClosed)
	}()
	<-entered
	w.muxAgent.Lock()
	w.agent = replacement
	w.remoteSessionChanged = true
	w.muxAgent.Unlock()
	w.conn.mu.Unlock()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("retired callback did not finish")
	}
	require.Same(t, replacement, w.agent, "replacement must retain ownership")
	require.Equal(t, ice.ConnectionStateConnected, w.lastKnownState, "replacement must remain connected")
	require.True(t, w.remoteSessionChanged, "replacement bookkeeping must survive")
}

// Current-agent teardown still clears its own state, including duplicate terminal events.
func TestCurrentICECallbackRetiresAgent(t *testing.T) {
	w := newTestWorkerICE(t)
	conn, endpoint := connectedCallbackTestConn()
	w.conn = conn
	agent := &icemaker.ThreadSafeAgent{}
	w.agent = agent
	w.agentConnecting = true
	w.lastKnownState = ice.ConnectionStateConnected
	w.remoteSessionChanged = true
	callback := w.onConnectionStateChange(agent, func() {})
	callback(ice.ConnectionStateDisconnected)
	callback(ice.ConnectionStateClosed)
	require.Equal(t, 1, endpoint.removals, "duplicate terminal events must remove the endpoint only once")
	require.Nil(t, w.agent, "current agent must be retired")
	require.False(t, w.agentConnecting, "current dial must be released")
	require.False(t, w.remoteSessionChanged, "current teardown consumes its bookkeeping")
	require.Equal(t, ice.ConnectionStateDisconnected, w.lastKnownState, "terminal events must clear current state")
}

// Record endpoint removal while retaining the real peer disconnect transition.
type endpointRemovalRecorder struct {
	WGIface
	removals int
}

func (r *endpointRemovalRecorder) RemoveEndpointAddress(string) error {
	r.removals++
	return nil
}

func connectedCallbackTestConn() (*Conn, *endpointRemovalRecorder) {
	endpoint := &endpointRemovalRecorder{}
	conn := &Conn{
		ctx: context.Background(), Log: log.NewEntry(log.New()),
		config:    ConnConfig{WgConfig: WgConfig{WgInterface: endpoint}},
		statusICE: worker.NewAtomicStatus(), statusRelay: worker.NewAtomicStatus(),
		guard: &guard.Guard{}, metricsStages: &MetricsStages{},
		statusRecorder:      NewRecorder("https://management.test"),
		currentConnPriority: conntype.ICEP2P,
	}
	conn.statusICE.SetConnected()
	return conn, endpoint
}

// Replacing an agent must retire its endpoint synchronously, since its late callback is ignored.
func TestICEReplacementRetiresOldEndpointBeforeNewAgent(t *testing.T) {
	w := newTestWorkerICE(t)
	conn, endpoint := connectedCallbackTestConn()
	w.conn = conn
	w.agent = &icemaker.ThreadSafeAgent{}
	w.agentDialerCancel = func() {}
	w.lastKnownState = ice.ConnectionStateConnected
	w.remoteSessionID = "old"
	sid := ICESessionID("new")
	w.OnNewOffer(&OfferAnswer{
		IceCredentials: IceCredentials{UFrag: "testufrag", Pwd: "testpwdtestpwdtestpwd12"},
		SessionID:      &sid,
	})
	t.Cleanup(w.Close)
	conn.mu.Lock()
	defer conn.mu.Unlock()
	require.Equal(t, 1, endpoint.removals, "old endpoint must retire before a new agent takes ownership")
	require.Equal(t, conntype.None, conn.currentConnPriority, "dead direct path must not block relay fallback")
}
