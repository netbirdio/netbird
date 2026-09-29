package peer

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/netbirdio/netbird/client/iface"
	"github.com/netbirdio/netbird/client/iface/configurer"
	"github.com/netbirdio/netbird/client/iface/wgaddr"
	"github.com/netbirdio/netbird/client/iface/wgproxy"
	"github.com/netbirdio/netbird/client/internal/peer/dispatcher"
	"github.com/netbirdio/netbird/client/internal/peer/guard"
	icemaker "github.com/netbirdio/netbird/client/internal/peer/ice"
	"github.com/netbirdio/netbird/client/internal/peer/worker"
	"github.com/netbirdio/netbird/relay/server"
	"github.com/netbirdio/netbird/shared/relay/auth/allow"
	relayClient "github.com/netbirdio/netbird/shared/relay/client"
)

var errProxyTableFull = errors.New("reached maximum relayed connection numbers")

// relayTestProxy stands in for the local WireGuard proxy. With failAdd set it
// refuses the relayed connection, as the eBPF proxy does once its port table
// is exhausted.
type relayTestProxy struct {
	failAdd bool
	added   atomic.Int32

	mu         sync.Mutex
	remoteConn net.Conn
}

func (p *relayTestProxy) AddRelayedConn(_ context.Context, _ *net.UDPAddr, remoteConn net.Conn) error {
	p.added.Add(1)
	if p.failAdd {
		return errProxyTableFull
	}
	p.mu.Lock()
	p.remoteConn = remoteConn
	p.mu.Unlock()
	return nil
}

func (p *relayTestProxy) EndpointAddr() *net.UDPAddr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000}
}

func (p *relayTestProxy) Work()                        {}
func (p *relayTestProxy) Pause()                       {}
func (p *relayTestProxy) RedirectAs(*net.UDPAddr)      {}
func (p *relayTestProxy) SetDisconnectListener(func()) {}
func (p *relayTestProxy) InjectPacket(b []byte) error  { return nil }
func (p *relayTestProxy) CloseConn() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.remoteConn == nil {
		return nil
	}
	return p.remoteConn.Close()
}

// relayTestWGIface hands out the queued proxies in order and accepts any peer
// configuration.
type relayTestWGIface struct {
	mu      sync.Mutex
	proxies []*relayTestProxy
}

func (i *relayTestWGIface) GetProxy() wgproxy.Proxy {
	i.mu.Lock()
	defer i.mu.Unlock()
	p := i.proxies[0]
	if len(i.proxies) > 1 {
		i.proxies = i.proxies[1:]
	}
	return p
}

func (i *relayTestWGIface) UpdatePeer(string, []netip.Prefix, time.Duration, *net.UDPAddr, *wgtypes.Key) error {
	return nil
}
func (i *relayTestWGIface) RemovePeer(string) error { return nil }
func (i *relayTestWGIface) GetStats() (map[string]configurer.WGStats, error) {
	return map[string]configurer.WGStats{}, nil
}
func (i *relayTestWGIface) Address() wgaddr.Address            { return wgaddr.Address{} }
func (i *relayTestWGIface) RemoveEndpointAddress(string) error { return nil }

// startTestRelayServer runs an in-process relay server and returns its URL.
func startTestRelayServer(t *testing.T) string {
	t.Helper()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	address := l.Addr().String()
	require.NoError(t, l.Close())

	srv, err := server.NewServer(server.Config{
		Meter:          otel.Meter(""),
		ExposedAddress: address,
		AuthValidator:  &allow.Auth{},
	})
	require.NoError(t, err)

	errChan := make(chan error, 1)
	go func() {
		errChan <- srv.Listen(server.ListenerConfig{Address: address})
	}()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})

	select {
	case err := <-errChan:
		require.NoError(t, err, "relay server must start")
	case <-time.After(300 * time.Millisecond):
	}
	return "rel://" + address
}

func newServedRelayManager(t *testing.T, ctx context.Context, url, peerKey string) *relayClient.Manager {
	t.Helper()
	mgr := relayClient.NewManager(ctx, []string{url}, peerKey, iface.DefaultMTU)
	require.NoError(t, mgr.Serve(), "relay manager for %s must connect", peerKey)
	return mgr
}

// newRelayOnlyConn opens a Conn that can only use the relay, so the test
// drives the relay handoff without ICE running alongside it.
func newRelayOnlyConn(t *testing.T, ctx context.Context, relayMgr *relayClient.Manager, wgIface WGIface) *Conn {
	t.Helper()
	t.Setenv(EnvKeyNBForceRelay, "true")

	statusRecorder := NewRecorder("https://mgm")
	require.NoError(t, statusRecorder.AddPeer(connConf.Key, "remote.netbird", "100.64.0.2", ""))

	config := connConf
	config.WgConfig = WgConfig{
		WgListenPort: 51820,
		RemoteKey:    connConf.Key,
		WgInterface:  wgIface,
		AllowedIps:   []netip.Prefix{netip.MustParsePrefix("100.64.0.2/32")},
	}

	conn, err := NewConn(config, ServiceDependencies{
		StatusRecorder:     statusRecorder,
		Signaler:           NewSignaler(stubSignalClient{}, wgtypes.Key{}),
		RelayManager:       relayMgr,
		SrWatcher:          guard.NewSRWatcher(nil, nil, nil, icemaker.Config{}),
		PeerConnDispatcher: dispatcher.NewConnectionDispatcher(),
	})
	require.NoError(t, err)
	require.NoError(t, conn.Open(ctx))
	t.Cleanup(func() { conn.Close(false) })
	return conn
}

// TestConn_RelayRecoversAfterProxyAttachFailure covers a relayed connection
// that opens while the local proxy cannot take it, as with a full eBPF port
// table. The relay transport must be released so a later offer opens a fresh
// one; left open, every later offer is treated as reusing it and the peer never
// gets a working relay path.
func TestConn_RelayRecoversAfterProxyAttachFailure(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	relayURL := startTestRelayServer(t)
	localRelay := newServedRelayManager(t, ctx, relayURL, connConf.LocalKey)
	remoteRelay := newServedRelayManager(t, ctx, relayURL, connConf.Key)
	remoteRelayAddr, _, err := remoteRelay.RelayInstanceAddress()
	require.NoError(t, err)

	refusing := &relayTestProxy{failAdd: true}
	working := &relayTestProxy{}
	conn := newRelayOnlyConn(t, ctx, localRelay, &relayTestWGIface{proxies: []*relayTestProxy{refusing, working}})

	offer := OfferAnswer{RelaySrvAddress: remoteRelayAddr}
	conn.OnRemoteOffer(offer)
	require.Eventually(t, func() bool { return refusing.added.Load() == 1 }, 10*time.Second, 10*time.Millisecond,
		"the first relayed connection must reach the local proxy")

	// Later offers stand in for the guard's retries.
	assert.Eventually(t, func() bool {
		conn.OnRemoteOffer(offer)
		return conn.statusRelay.Get() == worker.StatusConnected
	}, 10*time.Second, 100*time.Millisecond, "a later offer must bring up the relay path")
	assert.Equal(t, int32(1), working.added.Load(), "the retry must hand a fresh relayed connection to the proxy")
}

// TestWorkerRelay_CloseConnIfCurrentKeepsNewerConn covers a failed handoff that
// is only cleaned up after the relay connection it belongs to was replaced.
// Releasing the stale handle must leave the newer connection open and tracked.
func TestWorkerRelay_CloseConnIfCurrentKeepsNewerConn(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	relayURL := startTestRelayServer(t)
	localRelay := newServedRelayManager(t, ctx, relayURL, connConf.LocalKey)
	remoteRelay := newServedRelayManager(t, ctx, relayURL, connConf.Key)
	relayAddr, _, err := remoteRelay.RelayInstanceAddress()
	require.NoError(t, err)

	w := NewWorkerRelay(ctx, log.WithField("test", t.Name()), true, connConf, nil, localRelay)

	stale, err := localRelay.OpenConn(ctx, relayAddr, connConf.Key, netip.Addr{})
	require.NoError(t, err)
	require.NoError(t, stale.Close())

	current, err := localRelay.OpenConn(ctx, relayAddr, connConf.Key, netip.Addr{})
	require.NoError(t, err)
	w.relayLock.Lock()
	w.relayedConn = current
	w.relayLock.Unlock()

	w.closeConnIfCurrent(stale)

	assert.NoError(t, current.Context().Err(), "the newer relay connection must stay open")
	w.relayLock.Lock()
	defer w.relayLock.Unlock()
	assert.Same(t, current, w.relayedConn, "the newer relay connection must stay tracked")
}
