//go:build privileged && linux && !android

package iface

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/netbirdio/netbird/client/iface/device"
	"github.com/netbirdio/netbird/client/iface/wgaddr"
	"github.com/netbirdio/netbird/client/internal/stdnet"
)

func deviceAllowedIPs(t *testing.T, ifaceName string) map[string][]string {
	t.Helper()

	client, err := wgctrl.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })

	dev, err := client.Device(ifaceName)
	require.NoError(t, err)

	out := map[string][]string{}
	for _, p := range dev.Peers {
		var ips []string
		for _, ipn := range p.AllowedIPs {
			ips = append(ips, ipn.String())
		}
		sort.Strings(ips)
		out[p.PublicKey.String()] = ips
	}
	return out
}

func devicePeer(t *testing.T, ifaceName, peerKey string) wgtypes.Peer {
	t.Helper()

	client, err := wgctrl.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })

	dev, err := client.Device(ifaceName)
	require.NoError(t, err)
	for _, p := range dev.Peers {
		if p.PublicKey.String() == peerKey {
			return p
		}
	}
	t.Fatalf("peer %s not found on %s", peerKey, ifaceName)
	return wgtypes.Peer{}
}

func newOverlayTestPeerKey(t *testing.T) string {
	t.Helper()

	k, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)
	return k.PublicKey().String()
}

func TestWGIface_OverlayReservation_RealDevice(t *testing.T) {
	modes := []struct {
		name     string
		env      map[string]string
		skip     func() bool
		recreate bool
	}{
		{name: "kernel", skip: func() bool { return !device.WireGuardModuleIsLoaded() }, recreate: true},
		{name: "userspace", env: map[string]string{"NB_WG_KERNEL_DISABLED": "true"}, skip: func() bool { return !device.ModuleTunIsLoaded() }},
	}

	for i, mode := range modes {
		t.Run(mode.name, func(t *testing.T) {
			if mode.skip() {
				t.Skipf("%s WireGuard is not available here", mode.name)
			}
			for k, v := range mode.env {
				t.Setenv(k, v)
			}

			ifaceName := fmt.Sprintf("utun%d", WgIntNumber+20+i)
			w, err := NewWGIFace(WGIFaceOpts{
				IFaceName:    ifaceName,
				Address:      wgaddr.MustParseWGAddress("100.64.0.1/16"),
				WGPort:       33200 + i,
				WGPrivKey:    key,
				MTU:          DefaultMTU,
				TransportNet: stdnet.NewNet(context.Background(), testIFaceBlackList, nil),
			})
			require.NoError(t, err)
			require.NoError(t, w.Create())
			closed := false
			t.Cleanup(func() {
				if !closed {
					_ = w.Close()
				}
			})
			_, err = w.Up()
			require.NoError(t, err)

			// the interface must never run without the overlay range reserved
			peers := deviceAllowedIPs(t, ifaceName)
			require.Len(t, peers, 1, "only the placeholder is on a fresh interface")
			placeholderKey := w.overlayPeerKey
			require.Equal(t, []string{"100.64.0.0/16"}, peers[placeholderKey])
			p := devicePeer(t, ifaceName, placeholderKey)
			assert.Nil(t, p.Endpoint, "the placeholder has no endpoint")
			assert.Zero(t, p.PersistentKeepaliveInterval, "the placeholder never sends keepalives")
			assert.True(t, p.LastHandshakeTime.IsZero(), "the placeholder never handshakes")

			// real peers come and go next to it: a peer's own address wins over the range
			connected := newOverlayTestPeerKey(t)
			exitNode := newOverlayTestPeerKey(t)
			require.NoError(t, w.UpdatePeer(connected, []netip.Prefix{netip.MustParsePrefix("100.64.0.41/32")}, 0, nil, nil))
			require.NoError(t, w.UpdatePeer(exitNode, []netip.Prefix{
				netip.MustParsePrefix("100.64.0.2/32"),
				netip.MustParsePrefix("0.0.0.0/0"),
			}, 0, nil, nil))
			peers = deviceAllowedIPs(t, ifaceName)
			require.Len(t, peers, 3)
			assert.Equal(t, []string{"100.64.0.0/16"}, peers[placeholderKey], "adding peers must leave the placeholder alone")
			assert.Equal(t, []string{"100.64.0.41/32"}, peers[connected])
			assert.Equal(t, []string{"0.0.0.0/0", "100.64.0.2/32"}, peers[exitNode])

			// removing a peer returns its address to the placeholder, not to the exit node
			require.NoError(t, w.RemovePeer(connected))
			peers = deviceAllowedIPs(t, ifaceName)
			assert.NotContains(t, peers, connected)
			assert.Equal(t, []string{"100.64.0.0/16"}, peers[placeholderKey])

			// everything that touches a peer's allowed IPs, endpoint or key leaves the placeholder alone
			require.NoError(t, w.UpdatePeer(exitNode, []netip.Prefix{netip.MustParsePrefix("100.64.0.2/32")}, 0,
				&net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 51820}, nil))
			require.NoError(t, w.AddAllowedIP(exitNode, netip.MustParsePrefix("10.20.0.0/24")))
			require.NoError(t, w.RemoveAllowedIP(exitNode, netip.MustParsePrefix("10.20.0.0/24")))
			require.NoError(t, w.RemoveEndpointAddress(exitNode))
			psk, err := wgtypes.GenerateKey()
			require.NoError(t, err)
			require.NoError(t, w.SetPresharedKey(exitNode, psk, true))
			peers = deviceAllowedIPs(t, ifaceName)
			assert.Equal(t, []string{"100.64.0.0/16"}, peers[placeholderKey], "peer operations must not disturb the placeholder")
			assert.Equal(t, []string{"0.0.0.0/0", "100.64.0.2/32"}, peers[exitNode])

			// no peer can be handed the overlay range itself, WireGuard would move it off the placeholder
			overlayRange := netip.MustParsePrefix("100.64.0.0/16")
			assert.ErrorIs(t, w.UpdatePeer(exitNode, []netip.Prefix{overlayRange}, 0, nil, nil), ErrOverlayRangeReserved)
			assert.ErrorIs(t, w.AddAllowedIP(exitNode, overlayRange), ErrOverlayRangeReserved)
			peers = deviceAllowedIPs(t, ifaceName)
			assert.Equal(t, []string{"100.64.0.0/16"}, peers[placeholderKey], "the placeholder still owns the range")
			assert.Equal(t, []string{"0.0.0.0/0", "100.64.0.2/32"}, peers[exitNode])

			// a new overlay range replaces the old one
			require.NoError(t, w.UpdateAddr(wgaddr.MustParseWGAddress("100.65.0.1/16")))
			peers = deviceAllowedIPs(t, ifaceName)
			assert.Equal(t, []string{"100.65.0.0/16"}, peers[placeholderKey], "the old range must not stay reserved")
			assert.Contains(t, peers, exitNode, "the other peers are untouched by the address change")

			if mode.recreate {
				// configuring the device again drops all peers, the reservation is made again
				require.NoError(t, w.Create())
				peers = deviceAllowedIPs(t, ifaceName)
				require.Len(t, peers, 1)
				assert.Equal(t, []string{"100.65.0.0/16"}, peers[placeholderKey])
			}

			closed = true
			require.NoError(t, w.Close())
			_, err = net.InterfaceByName(ifaceName)
			assert.Error(t, err, "the interface and its placeholder are gone after Close")
		})
	}
}

func TestWGIface_OverlayReservation_DualStack(t *testing.T) {
	if !device.WireGuardModuleIsLoaded() {
		t.Skip("kernel WireGuard is not available here")
	}
	// only a host without IPv6 may skip, any other failure to create the interface is a failure
	if disabled, err := os.ReadFile("/proc/sys/net/ipv6/conf/all/disable_ipv6"); err != nil || strings.TrimSpace(string(disabled)) == "1" {
		t.Skip("IPv6 is not enabled here")
	}

	ifaceName := fmt.Sprintf("utun%d", WgIntNumber+22)
	w, err := NewWGIFace(WGIFaceOpts{
		IFaceName: ifaceName,
		Address: wgaddr.Address{
			IP:      netip.MustParseAddr("100.64.0.1"),
			Network: netip.MustParsePrefix("100.64.0.0/16"),
			IPv6:    netip.MustParseAddr("fd00:64::1"),
			IPv6Net: netip.MustParsePrefix("fd00:64::/64"),
		},
		WGPort:       33202,
		WGPrivKey:    key,
		MTU:          DefaultMTU,
		TransportNet: stdnet.NewNet(context.Background(), testIFaceBlackList, nil),
	})
	require.NoError(t, err)
	require.NoError(t, w.Create())
	t.Cleanup(func() { _ = w.Close() })

	peers := deviceAllowedIPs(t, ifaceName)
	require.Len(t, peers, 1)
	assert.Equal(t, []string{"100.64.0.0/16", "fd00:64::/64"}, peers[w.overlayPeerKey],
		"the v6 overlay range has to be reserved as well, an exit node carries ::/0")
}

func newOverlayTestIface(t *testing.T, name string, port int, env map[string]string) *WGIface {
	t.Helper()

	for k, v := range env {
		t.Setenv(k, v)
	}
	w, err := NewWGIFace(WGIFaceOpts{
		IFaceName:    name,
		Address:      wgaddr.MustParseWGAddress("100.64.0.1/16"),
		WGPort:       port,
		WGPrivKey:    key,
		MTU:          DefaultMTU,
		TransportNet: stdnet.NewNet(context.Background(), testIFaceBlackList, nil),
	})
	require.NoError(t, err)
	require.NoError(t, w.Create())
	t.Cleanup(func() { _ = w.Close() })
	_, err = w.Up()
	require.NoError(t, err)
	return w
}

// endpointListener stands in for a remote peer: it reports whether WireGuard sent it anything.
type endpointListener struct {
	conn *net.UDPConn
}

func newEndpointListener(t *testing.T) *endpointListener {
	t.Helper()

	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	return &endpointListener{conn: conn}
}

func (l *endpointListener) addr() *net.UDPAddr { return l.conn.LocalAddr().(*net.UDPAddr) }

// received reports whether a packet arrives within the wait.
func (l *endpointListener) received(wait time.Duration) bool {
	_ = l.conn.SetReadDeadline(time.Now().Add(wait))
	buf := make([]byte, 2048)
	_, _, err := l.conn.ReadFromUDP(buf)
	return err == nil
}

func sendOverlayPackets(t *testing.T, dst string) {
	t.Helper()

	conn, err := net.Dial("udp", dst)
	require.NoError(t, err)
	defer conn.Close()
	for i := 0; i < 3; i++ {
		// the device may refuse the send, which is part of what is checked elsewhere
		_, _ = conn.Write([]byte("probe"))
		time.Sleep(100 * time.Millisecond)
	}
}

// TestWGIface_OverlayReservation_NothingLeaksToTheExitNode is the regression guard for the reason the
// range is reserved: an address without a peer of its own, because the peer has not connected yet or
// was just removed, must not follow an exit node's default route to the exit node.
//
// WireGuard sends a handshake initiation to a peer at most once per REKEY_TIMEOUT, and that initiation is
// what shows traffic reached an endpoint. Every probe therefore uses an exit node of its own that has not
// seen any traffic yet; a listener that already received one would stay silent for the next probe and hide
// a leak.
func TestWGIface_OverlayReservation_NothingLeaksToTheExitNode(t *testing.T) {
	modes := []struct {
		name string
		env  map[string]string
		skip func() bool
	}{
		{name: "kernel", skip: func() bool { return !device.WireGuardModuleIsLoaded() }},
		{name: "userspace", env: map[string]string{"NB_WG_KERNEL_DISABLED": "true"}, skip: func() bool { return !device.ModuleTunIsLoaded() }},
	}

	for i, mode := range modes {
		t.Run(mode.name, func(t *testing.T) {
			if mode.skip() {
				t.Skipf("%s WireGuard is not available here", mode.name)
			}
			w := newOverlayTestIface(t, fmt.Sprintf("utun%d", WgIntNumber+30+i), 33230+i, mode.env)

			// the newest exit node owns 0.0.0.0/0, so it is the one a leak would reach
			exitNodes := 0
			newExitNode := func() *endpointListener {
				exitNodes++
				l := newEndpointListener(t)
				own := netip.MustParsePrefix(fmt.Sprintf("100.64.0.%d/32", 1+exitNodes))
				require.NoError(t, w.UpdatePeer(newOverlayTestPeerKey(t), []netip.Prefix{own, netip.MustParsePrefix("0.0.0.0/0")}, 0, l.addr(), nil))
				return l
			}

			// control: traffic to an exit node's own address reaches its endpoint, so silence below means something
			control := newExitNode()
			sendOverlayPackets(t, "100.64.0.2:5053")
			require.True(t, control.received(3*time.Second), "traffic addressed to the exit node must reach it")

			// a peer that has not connected yet has no entry
			exitNode := newExitNode()
			sendOverlayPackets(t, "100.64.0.77:5053")
			assert.False(t, exitNode.received(1500*time.Millisecond),
				"traffic to an unconnected peer's address must not reach the exit node")

			// a peer that was connected and is removed again, the gap a closing connection leaves
			colleague := newEndpointListener(t)
			colleagueKey := newOverlayTestPeerKey(t)
			require.NoError(t, w.UpdatePeer(colleagueKey, []netip.Prefix{netip.MustParsePrefix("100.64.0.41/32")}, 0, colleague.addr(), nil))
			sendOverlayPackets(t, "100.64.0.41:5053")
			require.True(t, colleague.received(3*time.Second), "a connected peer receives traffic addressed to it")

			exitNode = newExitNode()
			require.NoError(t, w.RemovePeer(colleagueKey))
			sendOverlayPackets(t, "100.64.0.41:5053")
			assert.False(t, exitNode.received(1500*time.Millisecond),
				"traffic to a removed peer's address must not reach the exit node")
			assert.False(t, colleague.received(500*time.Millisecond),
				"nor the endpoint the removed peer had")
		})
	}
}

// TestWGIface_OverlayReservation_UnconnectedPeerFailsFast pins how kernel WireGuard answers traffic to
// an overlay address that has no peer yet: with an error at once, not by holding the packet. Callers
// that retry or time out on offline peers, such as DNS upstreams, rely on this.
func TestWGIface_OverlayReservation_UnconnectedPeerFailsFast(t *testing.T) {
	if !device.WireGuardModuleIsLoaded() {
		t.Skip("kernel WireGuard is not available here")
	}
	w := newOverlayTestIface(t, fmt.Sprintf("utun%d", WgIntNumber+33), 33233, nil)

	// with an exit node on the device, only the reserved range keeps this address from following its
	// default route to an endpoint, where the packet would be held instead of refused
	exitNode := newEndpointListener(t)
	require.NoError(t, w.UpdatePeer(newOverlayTestPeerKey(t), []netip.Prefix{
		netip.MustParsePrefix("100.64.0.2/32"),
		netip.MustParsePrefix("0.0.0.0/0"),
	}, 0, exitNode.addr(), nil))

	conn, err := net.Dial("udp", "100.64.0.77:5053")
	require.NoError(t, err)
	defer conn.Close()

	start := time.Now()
	var sendErr error
	for i := 0; i < 3 && sendErr == nil; i++ {
		_, sendErr = conn.Write([]byte("probe"))
		time.Sleep(100 * time.Millisecond)
	}

	require.Error(t, sendErr, "the device must refuse traffic for an address without a connected peer")
	assert.Less(t, time.Since(start), 2*time.Second, "and do so at once")
	t.Logf("kernel answers with: %v", sendErr)
}
