package peer

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"sync/atomic"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/netbirdio/netbird/client/iface"
	"github.com/netbirdio/netbird/client/iface/configurer"
	"github.com/netbirdio/netbird/client/iface/wgaddr"
	"github.com/netbirdio/netbird/client/iface/wgproxy"
	"github.com/netbirdio/netbird/client/internal/peer/conntype"
	"github.com/netbirdio/netbird/client/internal/peer/dispatcher"
	"github.com/netbirdio/netbird/client/internal/peer/guard"
	"github.com/netbirdio/netbird/client/internal/peer/ice"
	"github.com/netbirdio/netbird/client/internal/peer/worker"
	"github.com/netbirdio/netbird/client/internal/stdnet"
	"github.com/netbirdio/netbird/util"
)

var testDispatcher = dispatcher.NewConnectionDispatcher()

var connConf = ConnConfig{
	Key:         "LLHf3Ma6z6mdLbriAJbqhX7+nM/B71lgw2+91q3LfhU=",
	LocalKey:    "RRHf3Ma6z6mdLbriAJbqhX7+nM/B71lgw2+91q3LfhU=",
	Timeout:     time.Second,
	LocalWgPort: 51820,
	ICEConfig: ice.Config{
		InterfaceBlackList: nil,
	},
}

func TestMain(m *testing.M) {
	_ = util.InitLog("trace", util.LogConsole)
	code := m.Run()
	os.Exit(code)
}

func TestNewConn_interfaceFilter(t *testing.T) {
	ignore := []string{iface.WgInterfaceDefault, "tun0", "zt", "ZeroTier", "utun", "wg", "ts",
		"Tailscale", "tailscale"}

	filter := stdnet.InterfaceFilter(ignore)

	for _, s := range ignore {
		assert.Equal(t, filter(s), false)
	}

}

func TestConn_GetKey(t *testing.T) {
	swWatcher := guard.NewSRWatcher(nil, nil, nil, connConf.ICEConfig)

	sd := ServiceDependencies{
		SrWatcher:          swWatcher,
		PeerConnDispatcher: testDispatcher,
	}
	conn, err := NewConn(connConf, sd)
	if err != nil {
		return
	}

	got := conn.GetKey()

	assert.Equal(t, got, connConf.Key, "they should be equal")
}

func TestConn_OnRemoteOffer(t *testing.T) {
	swWatcher := guard.NewSRWatcher(nil, nil, nil, connConf.ICEConfig)
	sd := ServiceDependencies{
		StatusRecorder:     NewRecorder("https://mgm"),
		SrWatcher:          swWatcher,
		PeerConnDispatcher: testDispatcher,
	}
	conn, err := NewConn(connConf, sd)
	if err != nil {
		return
	}

	onNewOfferChan := make(chan struct{})

	conn.handshaker.AddRelayListener(func(remoteOfferAnswer *OfferAnswer) {
		onNewOfferChan <- struct{}{}
	})

	conn.OnRemoteOffer(OfferAnswer{
		IceCredentials: IceCredentials{
			UFrag: "test",
			Pwd:   "test",
		},
		WgListenPort: 0,
		Version:      "",
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	select {
	case <-onNewOfferChan:
		// success
	case <-ctx.Done():
		t.Error("expected to receive a new offer notification, but timed out")
	}
}

func TestConn_OnRemoteAnswer(t *testing.T) {
	swWatcher := guard.NewSRWatcher(nil, nil, nil, connConf.ICEConfig)
	sd := ServiceDependencies{
		StatusRecorder:     NewRecorder("https://mgm"),
		SrWatcher:          swWatcher,
		PeerConnDispatcher: testDispatcher,
	}
	conn, err := NewConn(connConf, sd)
	if err != nil {
		return
	}

	onNewOfferChan := make(chan struct{})

	conn.handshaker.AddRelayListener(func(remoteOfferAnswer *OfferAnswer) {
		onNewOfferChan <- struct{}{}
	})

	conn.OnRemoteAnswer(OfferAnswer{
		IceCredentials: IceCredentials{
			UFrag: "test",
			Pwd:   "test",
		},
		WgListenPort: 0,
		Version:      "",
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	select {
	case <-onNewOfferChan:
		// success
	case <-ctx.Done():
		t.Error("expected to receive a new offer notification, but timed out")
	}
}

func TestConn_presharedKey(t *testing.T) {
	conn1 := Conn{
		config: ConnConfig{
			Key:             "LLHf3Ma6z6mdLbriAJbqhX7+nM/B71lgw2+91q3LfhU=",
			LocalKey:        "RRHf3Ma6z6mdLbriAJbqhX7+nM/B71lgw2+91q3LfhU=",
			RosenpassConfig: RosenpassConfig{},
		},
	}
	conn2 := Conn{
		config: ConnConfig{
			Key:             "RRHf3Ma6z6mdLbriAJbqhX7+nM/B71lgw2+91q3LfhU=",
			LocalKey:        "LLHf3Ma6z6mdLbriAJbqhX7+nM/B71lgw2+91q3LfhU=",
			RosenpassConfig: RosenpassConfig{},
		},
	}

	tests := []struct {
		conn1Permissive         bool
		conn1RosenpassEnabled   bool
		conn2Permissive         bool
		conn2RosenpassEnabled   bool
		conn1ExpectedInitialKey bool
		conn2ExpectedInitialKey bool
	}{
		{
			conn1Permissive:         false,
			conn1RosenpassEnabled:   false,
			conn2Permissive:         false,
			conn2RosenpassEnabled:   false,
			conn1ExpectedInitialKey: false,
			conn2ExpectedInitialKey: false,
		},
		{
			conn1Permissive:         false,
			conn1RosenpassEnabled:   true,
			conn2Permissive:         false,
			conn2RosenpassEnabled:   true,
			conn1ExpectedInitialKey: true,
			conn2ExpectedInitialKey: true,
		},
		{
			conn1Permissive:         false,
			conn1RosenpassEnabled:   true,
			conn2Permissive:         false,
			conn2RosenpassEnabled:   false,
			conn1ExpectedInitialKey: true,
			conn2ExpectedInitialKey: false,
		},
		{
			conn1Permissive:         false,
			conn1RosenpassEnabled:   false,
			conn2Permissive:         false,
			conn2RosenpassEnabled:   true,
			conn1ExpectedInitialKey: false,
			conn2ExpectedInitialKey: true,
		},
		{
			conn1Permissive:         true,
			conn1RosenpassEnabled:   true,
			conn2Permissive:         false,
			conn2RosenpassEnabled:   false,
			conn1ExpectedInitialKey: false,
			conn2ExpectedInitialKey: false,
		},
		{
			conn1Permissive:         false,
			conn1RosenpassEnabled:   false,
			conn2Permissive:         true,
			conn2RosenpassEnabled:   true,
			conn1ExpectedInitialKey: false,
			conn2ExpectedInitialKey: false,
		},
		{
			conn1Permissive:         true,
			conn1RosenpassEnabled:   true,
			conn2Permissive:         true,
			conn2RosenpassEnabled:   true,
			conn1ExpectedInitialKey: true,
			conn2ExpectedInitialKey: true,
		},
		{
			conn1Permissive:         false,
			conn1RosenpassEnabled:   false,
			conn2Permissive:         false,
			conn2RosenpassEnabled:   true,
			conn1ExpectedInitialKey: false,
			conn2ExpectedInitialKey: true,
		},
		{
			conn1Permissive:         false,
			conn1RosenpassEnabled:   true,
			conn2Permissive:         true,
			conn2RosenpassEnabled:   true,
			conn1ExpectedInitialKey: true,
			conn2ExpectedInitialKey: true,
		},
	}

	conn1.config.RosenpassConfig.PermissiveMode = true
	for i, test := range tests {
		tcase := i + 1
		t.Run(fmt.Sprintf("Rosenpass test case %d", tcase), func(t *testing.T) {
			conn1.config.RosenpassConfig = RosenpassConfig{}
			conn2.config.RosenpassConfig = RosenpassConfig{}

			if test.conn1RosenpassEnabled {
				conn1.config.RosenpassConfig.PubKey = []byte("dummykey")
			}
			conn1.config.RosenpassConfig.PermissiveMode = test.conn1Permissive

			if test.conn2RosenpassEnabled {
				conn2.config.RosenpassConfig.PubKey = []byte("dummykey")
			}
			conn2.config.RosenpassConfig.PermissiveMode = test.conn2Permissive

			conn1PresharedKey := conn1.presharedKey(conn2.config.RosenpassConfig.PubKey)
			conn2PresharedKey := conn2.presharedKey(conn1.config.RosenpassConfig.PubKey)

			if test.conn1ExpectedInitialKey {
				if conn1PresharedKey == nil {
					t.Errorf("Case %d: Expected conn1 to have a non-nil key, but got nil", tcase)
				}
			} else {
				if conn1PresharedKey != nil {
					t.Errorf("Case %d: Expected conn1 to have a nil key, but got %v", tcase, conn1PresharedKey)
				}
			}

			// Assert conn2's key expectation
			if test.conn2ExpectedInitialKey {
				if conn2PresharedKey == nil {
					t.Errorf("Case %d: Expected conn2 to have a non-nil key, but got nil", tcase)
				}
			} else {
				if conn2PresharedKey != nil {
					t.Errorf("Case %d: Expected conn2 to have a nil key, but got %v", tcase, conn2PresharedKey)
				}
			}
		})
	}
}

func TestConn_presharedKey_RosenpassManaged(t *testing.T) {
	conn := Conn{
		config: ConnConfig{
			Key:             "LLHf3Ma6z6mdLbriAJbqhX7+nM/B71lgw2+91q3LfhU=",
			LocalKey:        "RRHf3Ma6z6mdLbriAJbqhX7+nM/B71lgw2+91q3LfhU=",
			RosenpassConfig: RosenpassConfig{PubKey: []byte("dummykey")},
		},
	}

	// When Rosenpass has already initialized the PSK for this peer,
	// presharedKey must return nil to avoid UpdatePeer overwriting it.
	conn.rosenpassInitializedPresharedKeyValidator = func(peerKey string) bool { return true }
	if k := conn.presharedKey([]byte("remote")); k != nil {
		t.Fatalf("expected nil presharedKey when Rosenpass manages PSK, got %v", k)
	}

	// When Rosenpass hasn't taken over yet, presharedKey should provide
	// a non-nil initial key (deterministic or from NetBird PSK).
	conn.rosenpassInitializedPresharedKeyValidator = func(peerKey string) bool { return false }
	if k := conn.presharedKey([]byte("remote")); k == nil {
		t.Fatalf("expected non-nil presharedKey before Rosenpass manages PSK")
	}
}

func newWGTimeoutTestConn(rosenpassEnabled bool, disconnected *[]string) *Conn {
	cfg := ConnConfig{
		Key:      "LLHf3Ma6z6mdLbriAJbqhX7+nM/B71lgw2+91q3LfhU=",
		LocalKey: "RRHf3Ma6z6mdLbriAJbqhX7+nM/B71lgw2+91q3LfhU=",
		WgConfig: WgConfig{RemoteKey: "LLHf3Ma6z6mdLbriAJbqhX7+nM/B71lgw2+91q3LfhU="},
	}
	if rosenpassEnabled {
		cfg.RosenpassConfig = RosenpassConfig{PubKey: []byte("dummykey")}
	}

	conn := &Conn{
		ctx:           context.Background(),
		config:        cfg,
		Log:           log.WithField("peer", cfg.Key),
		metricsStages: &MetricsStages{},
	}
	conn.SetOnDisconnected(func(remotePeer string) {
		*disconnected = append(*disconnected, remotePeer)
	})
	return conn
}

// TestConn_onWGDisconnected_EscalatesToRosenpassReset: repeated handshake
// timeouts with rosenpass enabled mean the preshared keys have desynced. The
// renewal exchange runs over the dead tunnel and cannot resync them, so after
// wgTimeoutEscalationThreshold consecutive timeouts the conn must report the
// peer disconnected, dropping its rosenpass state so the next configuration
// programs the rendezvous key.
func TestConn_onWGDisconnected_EscalatesToRosenpassReset(t *testing.T) {
	var disconnected []string
	conn := newWGTimeoutTestConn(true, &disconnected)

	for i := 0; i < wgTimeoutEscalationThreshold-1; i++ {
		conn.onWGDisconnected(conn.ctx)
	}
	assert.Empty(t, disconnected, "escalation must not fire below the threshold")

	conn.onWGDisconnected(conn.ctx)
	assert.Equal(t, []string{conn.config.WgConfig.RemoteKey}, disconnected,
		"reaching the threshold must report the peer disconnected once")

	for i := 0; i < wgTimeoutEscalationThreshold-1; i++ {
		conn.onWGDisconnected(conn.ctx)
	}
	assert.Len(t, disconnected, 1, "escalation must restart counting after firing")

	conn.onWGDisconnected(conn.ctx)
	assert.Len(t, disconnected, 2, "continued timeouts must escalate again")
}

// TestConn_onWGDisconnected_CheckSuccessResetsEscalation: a successful
// handshake between timeouts means the tunnel recovered; the counter must
// start over.
func TestConn_onWGDisconnected_CheckSuccessResetsEscalation(t *testing.T) {
	var disconnected []string
	conn := newWGTimeoutTestConn(true, &disconnected)

	for i := 0; i < wgTimeoutEscalationThreshold-1; i++ {
		conn.onWGDisconnected(conn.ctx)
	}
	conn.onWGCheckSuccess()

	for i := 0; i < wgTimeoutEscalationThreshold-1; i++ {
		conn.onWGDisconnected(conn.ctx)
	}
	assert.Empty(t, disconnected, "handshake success must reset the timeout count")
}

// TestConn_onWGDisconnected_NoEscalationWithoutRosenpass: without rosenpass
// there is no per-peer key state to reset; repeated timeouts must not report
// disconnects.
func TestConn_onWGDisconnected_NoEscalationWithoutRosenpass(t *testing.T) {
	var disconnected []string
	conn := newWGTimeoutTestConn(false, &disconnected)

	for i := 0; i < wgTimeoutEscalationThreshold*3; i++ {
		conn.onWGDisconnected(conn.ctx)
	}
	assert.Empty(t, disconnected, "escalation must be limited to rosenpass connections")
}

type mockCycleWGIface struct {
	updatePeerCalls     atomic.Int32
	removeEndpointCalls atomic.Int32
}

func (m *mockCycleWGIface) UpdatePeer(string, []netip.Prefix, time.Duration, *net.UDPAddr, *wgtypes.Key) error {
	m.updatePeerCalls.Add(1)
	return nil
}
func (m *mockCycleWGIface) RemovePeer(string) error { return nil }
func (m *mockCycleWGIface) GetStats() (map[string]configurer.WGStats, error) {
	return map[string]configurer.WGStats{}, nil
}
func (m *mockCycleWGIface) GetProxy() wgproxy.Proxy { return nil }
func (m *mockCycleWGIface) Address() wgaddr.Address { return wgaddr.Address{} }
func (m *mockCycleWGIface) RemoveEndpointAddress(string) error {
	m.removeEndpointCalls.Add(1)
	return nil
}

// fakeRemoteConn is a minimal net.Conn with UDP-shaped addresses so the
// non-relayed ICE-ready path can resolve an endpoint.
type fakeRemoteConn struct{}

func (fakeRemoteConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (fakeRemoteConn) Write(b []byte) (int, error)      { return len(b), nil }
func (fakeRemoteConn) Close() error                     { return nil }
func (fakeRemoteConn) LocalAddr() net.Addr              { return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1} }
func (fakeRemoteConn) RemoteAddr() net.Addr             { return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 2} }
func (fakeRemoteConn) SetDeadline(time.Time) error      { return nil }
func (fakeRemoteConn) SetReadDeadline(time.Time) error  { return nil }
func (fakeRemoteConn) SetWriteDeadline(time.Time) error { return nil }

// newCycleTestConn builds a Conn the way the callback-level tests need it:
// liveCtx plays the role of the CURRENT cycle's conn.ctx.
func newCycleTestConn(t *testing.T, liveCtx context.Context, iface WGIface) *Conn {
	t.Helper()
	cfg := ConnConfig{
		Key:      "LLHf3Ma6z6mdLbriAJbqhX7+nM/B71lgw2+91q3LfhU=",
		LocalKey: "RRHf3Ma6z6mdLbriAJbqhX7+nM/B71lgw2+91q3LfhU=",
		WgConfig: WgConfig{
			RemoteKey:   "LLHf3Ma6z6mdLbriAJbqhX7+nM/B71lgw2+91q3LfhU=",
			WgInterface: iface,
		},
	}
	logEntry := log.WithField("peer", cfg.Key)
	statusRecorder := NewRecorder("https://mgm")
	return &Conn{
		ctx:             liveCtx,
		config:          cfg,
		Log:             logEntry,
		statusICE:       worker.NewAtomicStatus(),
		statusRelay:     worker.NewAtomicStatus(),
		statusRecorder:  statusRecorder,
		metricsStages:   &MetricsStages{},
		dumpState:       newStateDump(cfg.Key, logEntry, statusRecorder),
		endpointUpdater: NewEndpointUpdater(logEntry, cfg.WgConfig, isController(cfg)),
		guard: guard.NewGuard(logEntry, func() guard.ConnStatus { return guard.ConnStatusConnected },
			time.Second, guard.NewSRWatcher(nil, nil, nil, connConf.ICEConfig)),
	}
}

// staleCycleCtx returns a cancelled context standing in for a closed
// previous connection cycle.
func staleCycleCtx() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

// TestConn_onICEStateDisconnected_IgnoresStaleCycle: a disconnect callback
// from a previous connection cycle (its cycle context is cancelled) must not
// tear down the state of the current cycle, while the same callback from the
// live cycle still must.
func TestConn_onICEStateDisconnected_IgnoresStaleCycle(t *testing.T) {
	liveCtx, liveCancel := context.WithCancel(context.Background())
	defer liveCancel()

	iface := &mockCycleWGIface{}
	conn := newCycleTestConn(t, liveCtx, iface)
	conn.statusICE.SetConnected()
	conn.currentConnPriority = conntype.ICEP2P

	conn.onICEStateDisconnected(staleCycleCtx(), false)

	assert.Equal(t, worker.StatusConnected, conn.statusICE.Get(), "stale callback must not touch live ICE status")
	assert.Equal(t, conntype.ICEP2P, conn.currentConnPriority, "stale callback must not reset live priority")
	assert.EqualValues(t, 0, iface.removeEndpointCalls.Load(), "stale callback must not remove the live endpoint")

	// Control: the same callback from the live cycle must still tear down.
	conn.onICEStateDisconnected(liveCtx, false)
	assert.Equal(t, worker.StatusDisconnected, conn.statusICE.Get())
	assert.Equal(t, conntype.None, conn.currentConnPriority)
	assert.EqualValues(t, 1, iface.removeEndpointCalls.Load())
}

// TestConn_onICEConnectionIsReady_IgnoresStaleCycle: a success callback from
// a previous cycle must not configure the WireGuard endpoint of the current
// cycle to a dead connection.
func TestConn_onICEConnectionIsReady_IgnoresStaleCycle(t *testing.T) {
	liveCtx, liveCancel := context.WithCancel(context.Background())
	defer liveCancel()

	iface := &mockCycleWGIface{}
	conn := newCycleTestConn(t, liveCtx, iface)

	conn.onICEConnectionIsReady(staleCycleCtx(), conntype.ICEP2P, ICEConnInfo{RemoteConn: fakeRemoteConn{}})

	assert.NotEqual(t, worker.StatusConnected, conn.statusICE.Get(), "stale ready callback must not mark ICE connected")
	assert.Equal(t, conntype.None, conn.currentConnPriority, "stale ready callback must not raise the priority")
	assert.EqualValues(t, 0, iface.updatePeerCalls.Load(), "stale ready callback must not configure the WG endpoint")
	assert.Nil(t, conn.wgWatcher, "stale ready callback must not start a watcher")
}

// TestConn_onRelayDisconnected_IgnoresStaleCycle mirrors the ICE disconnect
// test for the relay path (relay-manager close listeners outlive the cycle).
func TestConn_onRelayDisconnected_IgnoresStaleCycle(t *testing.T) {
	liveCtx, liveCancel := context.WithCancel(context.Background())
	defer liveCancel()

	iface := &mockCycleWGIface{}
	conn := newCycleTestConn(t, liveCtx, iface)
	conn.statusRelay.SetConnected()
	conn.currentConnPriority = conntype.Relay

	conn.onRelayDisconnected(staleCycleCtx())

	assert.Equal(t, worker.StatusConnected, conn.statusRelay.Get(), "stale callback must not touch live relay status")
	assert.Equal(t, conntype.Relay, conn.currentConnPriority)
	assert.EqualValues(t, 0, iface.removeEndpointCalls.Load())

	// Control: live cycle still tears down.
	conn.onRelayDisconnected(liveCtx)
	assert.Equal(t, worker.StatusDisconnected, conn.statusRelay.Get())
	assert.Equal(t, conntype.None, conn.currentConnPriority)
	assert.EqualValues(t, 1, iface.removeEndpointCalls.Load())
}

// TestConn_onRelayConnectionIsReady_IgnoresStaleCycle: a stale relay-ready
// callback must close the relayed connection and leave the state untouched.
func TestConn_onRelayConnectionIsReady_IgnoresStaleCycle(t *testing.T) {
	liveCtx, liveCancel := context.WithCancel(context.Background())
	defer liveCancel()

	iface := &mockCycleWGIface{}
	conn := newCycleTestConn(t, liveCtx, iface)

	c1, c2 := net.Pipe()
	defer c2.Close()

	conn.onRelayConnectionIsReady(staleCycleCtx(), RelayConnInfo{relayedConn: c1})

	assert.NotEqual(t, worker.StatusConnected, conn.statusRelay.Get(), "stale relay-ready must not mark relay connected")
	_, err := c2.Write([]byte{0x1})
	assert.ErrorIs(t, err, io.ErrClosedPipe, "stale relay conn must be closed")
}
