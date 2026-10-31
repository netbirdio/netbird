//go:build privileged && linux && !android

package iface

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"testing"

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
	if err := w.Create(); err != nil {
		t.Skipf("IPv6 is not usable here: %v", err)
	}
	t.Cleanup(func() { _ = w.Close() })

	peers := deviceAllowedIPs(t, ifaceName)
	require.Len(t, peers, 1)
	assert.Equal(t, []string{"100.64.0.0/16", "fd00:64::/64"}, peers[w.overlayPeerKey],
		"the v6 overlay range has to be reserved as well, an exit node carries ::/0")
}
