package peer

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/pion/ice/v4"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/netbirdio/netbird/client/internal/peer/conntype"
	icemaker "github.com/netbirdio/netbird/client/internal/peer/ice"
	"github.com/netbirdio/netbird/client/internal/peer/worker"
)

// A dial result already past connect's ownership check must not revive a retired path.
func TestICEPublicationRejectsRetiredAgent(t *testing.T) {
	for _, replacement := range []bool{false, true} {
		name := "expired_without_replacement"
		if replacement {
			name = "replaced"
		}
		t.Run(name, func(t *testing.T) {
			w := newTestWorkerICE(t)
			conn, endpoint := publicationTestConn()
			w.conn = conn
			conn.workerICE = w
			old := &icemaker.ThreadSafeAgent{}
			w.agent = old
			w.lastKnownState = ice.ConnectionStateConnected
			w.closeAgent(old, func() {})
			conn.wgWatcher = &WGWatcher{}
			require.Equal(t, 1, endpoint.removals)
			if replacement {
				w.agent = &icemaker.ThreadSafeAgent{}
				w.agentConnecting = true
				w.remoteSessionID = "replacement"
			}
			current := w.agent
			// Model the late dial result after expiry has already retired its endpoint.
			client, server := net.Pipe()
			t.Cleanup(func() { require.NoError(t, client.Close()); require.NoError(t, server.Close()) })
			late := &publicationTestConnSocket{closeTrackConn: closeTrackConn{Conn: client}}
			conn.onICEConnectionIsReady(w, old, conntype.ICEP2P, ICEConnInfo{RemoteConn: late})
			require.Zero(t, endpoint.updates, "retired result must not reinstall an endpoint")
			require.True(t, late.closed.Load(), "discarded dial result must be closed")
			require.Equal(t, worker.StatusDisconnected, conn.statusICE.Get())
			require.Equal(t, conntype.None, conn.currentConnPriority)
			require.Same(t, current, w.agent)
			require.Equal(t, replacement, w.agentConnecting)
			require.True(t, w.lastSuccess.IsZero(), "retired result must not record success")
		})
	}
}

// Teardown can win while publication is queued for the connection lock.
func TestICEPublicationRechecksAfterWaitingForConn(t *testing.T) {
	w := newTestWorkerICE(t)
	conn, endpoint := publicationTestConn()
	w.conn = conn
	conn.workerICE = w
	old := &icemaker.ThreadSafeAgent{}
	w.agent = old
	client, server := net.Pipe()
	t.Cleanup(func() { require.NoError(t, client.Close()); require.NoError(t, server.Close()) })
	late := &publicationTestConnSocket{closeTrackConn: closeTrackConn{Conn: client}}
	conn.mu.Lock()
	started, done := make(chan struct{}), make(chan struct{})
	go func() {
		close(started)
		conn.onICEConnectionIsReady(w, old, conntype.ICEP2P, ICEConnInfo{RemoteConn: late})
		close(done)
	}()
	<-started
	w.muxAgent.Lock()
	w.abandonNegotiation()
	w.muxAgent.Unlock()
	conn.mu.Unlock()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("publication did not finish")
	}
	require.Zero(t, endpoint.updates)
	require.True(t, late.closed.Load())
}

// A canceled worker must not publish into a live peer reopened with a new worker.
func TestICEPublicationRejectsCanceledWorker(t *testing.T) {
	w := newTestWorkerICE(t)
	conn, endpoint := publicationTestConn()
	w.conn = conn
	ctx, cancel := context.WithCancel(w.ctx)
	cancel()
	w.ctx = ctx
	conn.workerICE = w
	agent := &icemaker.ThreadSafeAgent{}
	w.agent = agent
	client, server := net.Pipe()
	t.Cleanup(func() { require.NoError(t, client.Close()); require.NoError(t, server.Close()) })
	late := &publicationTestConnSocket{closeTrackConn: closeTrackConn{Conn: client}}
	conn.onICEConnectionIsReady(w, agent, conntype.ICEP2P, ICEConnInfo{RemoteConn: late})
	require.Zero(t, endpoint.updates)
	require.True(t, late.closed.Load())
}

// Record actual endpoint installation without changing host networking.
type publicationEndpoint struct {
	*endpointRemovalRecorder
	updates int
}

func (e *publicationEndpoint) UpdatePeer(string, []netip.Prefix, time.Duration, *net.UDPAddr, *wgtypes.Key) error {
	e.updates++
	return nil
}

type publicationTestConnSocket struct{ closeTrackConn }

func (*publicationTestConnSocket) RemoteAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 51820}
}

func publicationTestConn() (*Conn, *publicationEndpoint) {
	conn, removals := connectedCallbackTestConn()
	endpoint := &publicationEndpoint{endpointRemovalRecorder: removals}
	conn.config.WgConfig.WgInterface = endpoint
	conn.endpointUpdater = NewEndpointUpdater(conn.Log, conn.config.WgConfig, true)
	conn.dumpState = &stateDump{}
	conn.wgWatcher = &WGWatcher{} // No watcher goroutine is needed for endpoint publication.
	conn.wgWatcherCancel = func() {}
	return conn, endpoint
}

// The current agent still installs its endpoint and commits its negotiation state.
func TestICEPublicationAcceptsCurrentAgent(t *testing.T) {
	w := newTestWorkerICE(t)
	conn, endpoint := publicationTestConn()
	w.conn = conn
	conn.workerICE = w
	agent := &icemaker.ThreadSafeAgent{}
	w.agent = agent
	w.agentConnecting = true
	client, server := net.Pipe()
	t.Cleanup(func() { require.NoError(t, client.Close()); require.NoError(t, server.Close()) })
	current := &publicationTestConnSocket{closeTrackConn: closeTrackConn{Conn: client}}
	conn.onICEConnectionIsReady(w, agent, conntype.ICEP2P, ICEConnInfo{RemoteConn: current})
	require.Equal(t, 1, endpoint.updates)
	require.Equal(t, worker.StatusConnected, conn.statusICE.Get())
	require.Equal(t, conntype.ICEP2P, conn.currentConnPriority)
	require.False(t, w.agentConnecting)
	require.False(t, w.lastSuccess.IsZero())
	require.False(t, current.closed.Load())
}
