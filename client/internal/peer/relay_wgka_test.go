package peer

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/netbirdio/netbird/client/iface/configurer"
	"github.com/netbirdio/netbird/client/iface/wgaddr"
	"github.com/netbirdio/netbird/client/iface/wgproxy"
	"github.com/netbirdio/netbird/client/internal/peer/conntype"
)

type peerUpdate struct {
	allowedIPs []netip.Prefix
	keepAlive  time.Duration
	endpoint   *net.UDPAddr
	psk        *wgtypes.Key
}

// recordingWGIface records every UpdatePeer call.
type recordingWGIface struct {
	mu      sync.Mutex
	updates []peerUpdate
}

func (r *recordingWGIface) UpdatePeer(_ string, allowedIps []netip.Prefix, keepAlive time.Duration, endpoint *net.UDPAddr, preSharedKey *wgtypes.Key) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.updates = append(r.updates, peerUpdate{allowedIPs: allowedIps, keepAlive: keepAlive, endpoint: endpoint, psk: preSharedKey})
	return nil
}

func (r *recordingWGIface) RemovePeer(string) error { return nil }
func (r *recordingWGIface) GetStats() (map[string]configurer.WGStats, error) {
	return map[string]configurer.WGStats{}, nil
}
func (r *recordingWGIface) GetProxy() wgproxy.Proxy            { return nil }
func (r *recordingWGIface) Address() wgaddr.Address            { return wgaddr.Address{} }
func (r *recordingWGIface) RemoveEndpointAddress(string) error { return nil }

func (r *recordingWGIface) all() []peerUpdate {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]peerUpdate(nil), r.updates...)
}

func (r *recordingWGIface) last(t *testing.T) peerUpdate {
	t.Helper()
	u := r.all()
	require.NotEmpty(t, u, "expected an UpdatePeer call")
	return u[len(u)-1]
}

func newTestEndpointUpdater(initiator bool) (*EndpointUpdater, *recordingWGIface) {
	iface := &recordingWGIface{}
	cfg := WgConfig{
		RemoteKey:   "LLHf3Ma6z6mdLbriAJbqhX7+nM/B71lgw2+91q3LfhU=",
		WgInterface: iface,
		AllowedIps:  []netip.Prefix{netip.MustParsePrefix("100.64.0.2/32")},
	}
	return NewEndpointUpdater(log.WithField("peer", "test"), cfg, initiator), iface
}

var (
	testRelayEp = &net.UDPAddr{IP: net.IPv4(127, 2, 0, 1), Port: 51820}
	testICEEp   = &net.UDPAddr{IP: net.IPv4(192, 0, 2, 10), Port: 51820}
)

// Relay keeps the default keepalive until DisableRelayKeepalive (called once the
// watcher saw a handshake), then 0 without touching endpoint, allowed IPs or key.
func TestEndpointUpdater_RelayKeepaliveDisable(t *testing.T) {
	e, iface := newTestEndpointUpdater(true)

	require.NoError(t, e.ConfigureWGEndpoint(testRelayEp, nil, wgPathRelay))
	assert.Equal(t, defaultWgKeepAlive, iface.last(t).keepAlive, "relay configure must start with the default keepalive")

	require.NoError(t, e.DisableRelayKeepalive())
	u := iface.last(t)
	assert.Equal(t, time.Duration(0), u.keepAlive, "relay keepalive after disable")
	assert.Nil(t, u.endpoint, "disable must not set the endpoint")
	assert.Empty(t, u.allowedIPs, "disable must not touch allowed IPs")
	assert.Nil(t, u.psk, "disable must not touch the preshared key")

	n := len(iface.all())
	require.NoError(t, e.DisableRelayKeepalive())
	assert.Len(t, iface.all(), n, "second disable must be a no-op")
}

// ICE keeps 25 s; disable is a no-op on the ICE path.
func TestEndpointUpdater_ICEKeepsKeepalive(t *testing.T) {
	e, iface := newTestEndpointUpdater(true)

	require.NoError(t, e.ConfigureWGEndpoint(testICEEp, nil, wgPathICE))
	require.NoError(t, e.DisableRelayKeepalive())

	u := iface.all()
	require.Len(t, u, 1, "disable on ICE must not update the peer")
	assert.Equal(t, defaultWgKeepAlive, u[0].keepAlive, "ICE keepalive")
}

// The value follows the path: relay (idle, 0) to ICE restores 25, ICE to relay
// starts at 25 again and can drop to 0.
func TestEndpointUpdater_KeepaliveFollowsPath(t *testing.T) {
	e, iface := newTestEndpointUpdater(true)

	require.NoError(t, e.ConfigureWGEndpoint(testRelayEp, nil, wgPathRelay))
	require.NoError(t, e.DisableRelayKeepalive())
	require.Equal(t, time.Duration(0), iface.last(t).keepAlive)

	require.NoError(t, e.ConfigureWGEndpoint(testICEEp, nil, wgPathICE))
	assert.Equal(t, defaultWgKeepAlive, iface.last(t).keepAlive, "relay to ICE must restore the keepalive")
	assert.Equal(t, testICEEp, iface.last(t).endpoint)

	require.NoError(t, e.SwitchWGEndpoint(testRelayEp, nil, wgPathRelay))
	assert.Equal(t, defaultWgKeepAlive, iface.last(t).keepAlive, "ICE to relay starts with the keepalive until a handshake")

	require.NoError(t, e.DisableRelayKeepalive())
	assert.Equal(t, time.Duration(0), iface.last(t).keepAlive, "relay after fallback drops to 0")
}

// Responder on relay: the delayed endpoint update carries the current keepalive.
func TestEndpointUpdater_ResponderDelayedUpdateOnRelay(t *testing.T) {
	e, iface := newTestEndpointUpdater(false)

	require.NoError(t, e.ConfigureWGEndpoint(testRelayEp, nil, wgPathRelay))
	first := iface.last(t)
	assert.Nil(t, first.endpoint, "responder first update has no endpoint")
	assert.Equal(t, defaultWgKeepAlive, first.keepAlive)

	require.Eventually(t, func() bool { return len(iface.all()) == 2 }, fallbackDelay+2*time.Second, 50*time.Millisecond, "delayed update")
	delayed := iface.last(t)
	assert.Equal(t, testRelayEp, delayed.endpoint, "delayed update sets the endpoint")
	assert.Equal(t, defaultWgKeepAlive, delayed.keepAlive)

	require.NoError(t, e.DisableRelayKeepalive())
	assert.Equal(t, time.Duration(0), iface.last(t).keepAlive, "responder relay keepalive after disable")
	require.NoError(t, e.RemoveWgPeer())
}

func setShortWatcherPeriods(t *testing.T) {
	t.Helper()
	oldOver, oldCheck := wgHandshakeOvertime, checkPeriod
	wgHandshakeOvertime = 200 * time.Millisecond
	checkPeriod = 1 * time.Second
	t.Cleanup(func() {
		wgHandshakeOvertime, checkPeriod = oldOver, oldCheck
	})
}

type watcherEvents struct {
	disconnected chan struct{}
	first        chan struct{}
	idle         chan struct{}
}

func startTestWatcher(t *testing.T, stats WGInterfaceStater, relayIdle, relay bool) (*WGWatcher, watcherEvents) {
	t.Helper()
	mlog := log.WithField("peer", "wgka")
	w := NewWGWatcher(mlog, stats, "", newStateDump("peer", mlog, &Status{}))
	ev := watcherEvents{
		disconnected: make(chan struct{}, 4),
		first:        make(chan struct{}, 4),
		idle:         make(chan struct{}, 4),
	}
	if relayIdle {
		w.EnableRelayIdle(func() { ev.idle <- struct{}{} })
	}
	w.PrepareInitialHandshake()
	w.SetRelayPath(relay)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	t.Cleanup(func() {
		cancel()
		<-done
	})
	go func() {
		defer close(done)
		w.EnableWgWatcher(ctx, time.Now(), func() { ev.disconnected <- struct{}{} }, func(time.Time) { ev.first <- struct{}{} }, nil)
	}()
	return w, ev
}

func waitEvent(t *testing.T, ch chan struct{}, d time.Duration, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(d):
		t.Fatalf("timed out waiting for %s", what)
	}
}

func noEvent(t *testing.T, ch chan struct{}, d time.Duration, what string) {
	t.Helper()
	select {
	case <-ch:
		t.Fatalf("unexpected %s", what)
	case <-time.After(d):
	}
}

// On relay with the knob, the first handshake is still reported, then the periodic
// check stops: no disconnect long after checkPeriod with no new handshakes.
func TestWGWatcher_RelayIdleNoDisconnect(t *testing.T) {
	setShortWatcherPeriods(t)
	stats := &mockHandshakeStats{}
	_, ev := startTestWatcher(t, stats, true, true)
	stats.advance()

	waitEvent(t, ev.first, 2*time.Second, "first handshake")
	waitEvent(t, ev.idle, time.Second, "relay idle")
	noEvent(t, ev.disconnected, 5*checkPeriod, "disconnect on idle relay")
	noEvent(t, ev.idle, 0, "second idle call")
}

// Leaving relay restarts the periodic check, so a missing handshake on ICE
// disconnects as today.
func TestWGWatcher_RelayIdleThenICE(t *testing.T) {
	setShortWatcherPeriods(t)
	stats := &mockHandshakeStats{}
	w, ev := startTestWatcher(t, stats, true, true)
	stats.advance()

	waitEvent(t, ev.idle, 2*time.Second, "relay idle")
	w.SetRelayPath(false)
	waitEvent(t, ev.disconnected, 3*checkPeriod, "disconnect on ICE without handshakes")
}

// ICE with the knob on keeps the full watcher.
func TestWGWatcher_ICEWithKnobDisconnects(t *testing.T) {
	setShortWatcherPeriods(t)
	stats := &mockHandshakeStats{}
	_, ev := startTestWatcher(t, stats, true, false)
	stats.advance()

	waitEvent(t, ev.first, 2*time.Second, "first handshake")
	waitEvent(t, ev.disconnected, 3*checkPeriod, "disconnect on ICE without handshakes")
	noEvent(t, ev.idle, 0, "idle on ICE")
}

// Knob off: relay keeps the full watcher.
func TestWGWatcher_RelayKnobOffDisconnects(t *testing.T) {
	setShortWatcherPeriods(t)
	stats := &mockHandshakeStats{}
	_, ev := startTestWatcher(t, stats, false, true)
	stats.advance()

	waitEvent(t, ev.first, 2*time.Second, "first handshake")
	waitEvent(t, ev.disconnected, 3*checkPeriod, "disconnect with knob off")
}

// A peer reset while idle expects a new handshake; once seen the watcher goes idle again.
func TestWGWatcher_RelayIdleReset(t *testing.T) {
	setShortWatcherPeriods(t)
	stats := &mockHandshakeStats{}
	w, ev := startTestWatcher(t, stats, true, true)
	stats.advance()
	waitEvent(t, ev.idle, 2*time.Second, "relay idle")

	w.Reset()
	time.Sleep(20 * time.Millisecond)
	stats.advance()
	waitEvent(t, ev.idle, 2*time.Second, "relay idle after reset")
	noEvent(t, ev.disconnected, 3*checkPeriod, "disconnect after reset")
}

// No handshake on relay: first check still disconnects (no idle without a handshake).
func TestWGWatcher_RelayNoHandshakeDisconnects(t *testing.T) {
	setShortWatcherPeriods(t)
	stats := &mockHandshakeStats{}
	_, ev := startTestWatcher(t, stats, true, true)

	waitEvent(t, ev.disconnected, 2*time.Second, "disconnect without first handshake")
	noEvent(t, ev.idle, 0, "idle without handshake")
}

func newRelayIdleTestConn(priority conntype.ConnPriority) (*Conn, *recordingWGIface) {
	e, iface := newTestEndpointUpdater(true)
	conn := &Conn{
		ctx:                 context.Background(),
		Log:                 log.WithField("peer", "wgka"),
		endpointUpdater:     e,
		currentConnPriority: priority,
		relayWgKaOff:        true,
	}
	return conn, iface
}

// The conn callback drops the keepalive only while the active path is relay.
func TestConn_onWGRelayIdle(t *testing.T) {
	conn, iface := newRelayIdleTestConn(conntype.Relay)
	require.NoError(t, conn.endpointUpdater.ConfigureWGEndpoint(testRelayEp, nil, wgPathRelay))
	conn.onWGRelayIdle(context.Background())
	assert.Equal(t, time.Duration(0), iface.last(t).keepAlive, "relay idle must drop the keepalive")

	conn, iface = newRelayIdleTestConn(conntype.ICEP2P)
	require.NoError(t, conn.endpointUpdater.ConfigureWGEndpoint(testICEEp, nil, wgPathICE))
	conn.onWGRelayIdle(context.Background())
	assert.Len(t, iface.all(), 1, "no update when ICE is active")

	conn, iface = newRelayIdleTestConn(conntype.Relay)
	require.NoError(t, conn.endpointUpdater.ConfigureWGEndpoint(testRelayEp, nil, wgPathRelay))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	conn.onWGRelayIdle(ctx)
	assert.Len(t, iface.all(), 1, "no update from a superseded watcher")
}
