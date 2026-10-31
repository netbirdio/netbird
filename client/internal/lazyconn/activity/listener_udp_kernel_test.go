//go:build privileged && linux && !android

package activity

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/netbirdio/netbird/client/iface"
	"github.com/netbirdio/netbird/client/iface/device"
	"github.com/netbirdio/netbird/client/iface/wgaddr"
	"github.com/netbirdio/netbird/client/internal/lazyconn"
	"github.com/netbirdio/netbird/client/internal/stdnet"
)

func newKernelIface(t *testing.T, name string, port int) *iface.WGIface {
	t.Helper()

	if !device.WireGuardModuleIsLoaded() {
		t.Skip("kernel WireGuard is not available here")
	}

	priv, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)
	w, err := iface.NewWGIFace(iface.WGIFaceOpts{
		IFaceName:    name,
		Address:      wgaddr.MustParseWGAddress("100.64.0.1/16"),
		WGPort:       port,
		WGPrivKey:    priv.String(),
		MTU:          iface.DefaultMTU,
		TransportNet: stdnet.NewNet(context.Background(), []string{"wt", "utun", "tun0"}, nil),
	})
	require.NoError(t, err)
	require.NoError(t, w.Create())
	t.Cleanup(func() { _ = w.Close() })
	_, err = w.Up()
	require.NoError(t, err)
	return w
}

func peerKeys(t *testing.T, name string) []string {
	t.Helper()

	client, err := wgctrl.New()
	require.NoError(t, err)
	defer client.Close()
	dev, err := client.Device(name)
	require.NoError(t, err)

	var keys []string
	for _, p := range dev.Peers {
		keys = append(keys, p.PublicKey.String())
	}
	return keys
}

func sendTo(t *testing.T, addr string) {
	t.Helper()

	conn, err := net.Dial("udp", addr)
	require.NoError(t, err)
	defer conn.Close()
	// a few attempts, the first packet only starts the handshake
	for i := 0; i < 3; i++ {
		_, _ = conn.Write([]byte("wake"))
		time.Sleep(100 * time.Millisecond)
	}
}

func listenForActivity(t *testing.T, w *iface.WGIface, peerKey string, ips ...string) (*UDPListener, chan struct{}) {
	t.Helper()

	var prefixes []netip.Prefix
	for _, ip := range ips {
		prefixes = append(prefixes, netip.MustParsePrefix(ip))
	}
	l, err := NewUDPListener(w, lazyconn.PeerConfig{
		PublicKey:  peerKey,
		AllowedIPs: prefixes,
		Log:        log.WithField("peer", peerKey),
	})
	require.NoError(t, err)

	done := make(chan struct{})
	go func() {
		l.ReadPackets()
		close(done)
	}()
	return l, done
}

// TestUDPListener_KernelWakeWithOverlayPlaceholder checks lazy connections against a real kernel
// interface that has the overlay range reserved for a placeholder peer: a lazy peer's own address is
// more specific than the range, so traffic to it must still reach the activity listener, also after
// the peer was removed (idle) and a listener was set up again.
func TestUDPListener_KernelWakeWithOverlayPlaceholder(t *testing.T) {
	w := newKernelIface(t, "utun2040", 33240)

	peer, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)
	peerKey := peer.PublicKey().String()

	t.Run("wake through the lazy peer entry", func(t *testing.T) {
		l, done := listenForActivity(t, w, peerKey, "100.64.0.7/32")
		defer l.Close()

		assert.Len(t, peerKeys(t, "utun2040"), 2, "the placeholder and the lazy peer are both on the device")

		sendTo(t, "100.64.0.7:9999")
		select {
		case <-done:
			assert.NotEmpty(t, l.CapturedPacket(), "the packet that woke the peer is captured")
		case <-time.After(5 * time.Second):
			t.Fatal("traffic to a lazy peer did not reach its activity listener")
		}
	})

	t.Run("address of a removed peer is not reachable until a listener exists again", func(t *testing.T) {
		// an exit node that has seen no traffic, so a leak to it would show at once
		exitNode, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
		require.NoError(t, err)
		defer exitNode.Close()
		exitKey, err := wgtypes.GeneratePrivateKey()
		require.NoError(t, err)
		require.NoError(t, w.UpdatePeer(exitKey.PublicKey().String(), []netip.Prefix{
			netip.MustParsePrefix("100.64.0.2/32"),
			netip.MustParsePrefix("0.0.0.0/0"),
		}, 0, exitNode.LocalAddr().(*net.UDPAddr), nil))

		require.NoError(t, w.RemovePeer(peerKey))
		assert.NotContains(t, peerKeys(t, "utun2040"), peerKey)

		// the idle gap: nothing may leak to the exit node, and nothing wakes a listener that does not exist
		sendTo(t, "100.64.0.7:9999")
		require.NoError(t, exitNode.SetReadDeadline(time.Now().Add(1500*time.Millisecond)))
		_, _, readErr := exitNode.ReadFromUDP(make([]byte, 2048))
		assert.Error(t, readErr, "traffic to a removed peer's address must not reach the exit node")

		l, done := listenForActivity(t, w, peerKey, "100.64.0.7/32")
		defer l.Close()
		sendTo(t, "100.64.0.7:9999")
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("a new listener after an idle cycle did not see activity")
		}
	})

	t.Run("the placeholder survives the whole cycle", func(t *testing.T) {
		assert.Contains(t, peerKeys(t, "utun2040"), peerKey)
		assert.Len(t, peerKeys(t, "utun2040"), 3, "the placeholder, the exit node and the lazy peer")
	})
}
