package configurer

import (
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	wgconn "golang.zx2c4.com/wireguard/conn"
	wgdevice "golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/tuntest"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/netbirdio/netbird/client/iface/bind"
)

// newTestUSPConfigurer builds a configurer over a real wireguard-go device backed by an
// in-memory TUN. The device stays down, so no socket is opened and no privileges are needed.
func newTestUSPConfigurer(t *testing.T) *WGUSPConfigurer {
	t.Helper()

	tun := tuntest.NewChannelTUN()
	dev := wgdevice.NewDevice(tun.TUN(), wgconn.NewDefaultBind(), wgdevice.NewLogger(wgdevice.LogLevelSilent, ""))
	t.Cleanup(dev.Close)

	c := NewUSPConfigurerNoUAPI(dev, "wgtest0", bind.NewActivityRecorder())

	key, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err, "generate device private key")
	require.NoError(t, c.ConfigureInterface(key.String(), 0), "configure test device")

	return c
}

// seedPeers adds count peers, each with a /32 overlay address, and returns their public keys.
func seedPeers(t *testing.T, c *WGUSPConfigurer, count int) []string {
	t.Helper()

	keys := make([]string, 0, count)
	for i := 0; i < count; i++ {
		priv, err := wgtypes.GeneratePrivateKey()
		require.NoError(t, err, "generate peer private key")
		pub := priv.PublicKey().String()

		addr := netip.PrefixFrom(netip.AddrFrom4([4]byte{100, 64, byte(i >> 8), byte(i)}), 32)
		require.NoError(t, c.UpdatePeer(pub, []netip.Prefix{addr}, 25*time.Second, nil, nil), "add peer")
		keys = append(keys, pub)
	}
	return keys
}

func peerAllowedIPs(t *testing.T, c *WGUSPConfigurer, peerKey string) []string {
	t.Helper()

	stats, err := c.FullStats()
	require.NoError(t, err, "read device stats")

	for _, p := range stats.Peers {
		if p.PublicKey != peerKey {
			continue
		}
		got := make([]string, 0, len(p.AllowedIPs))
		for _, ipNet := range p.AllowedIPs {
			got = append(got, ipNet.String())
		}
		return got
	}
	t.Fatalf("peer %s not found on device", peerKey)
	return nil
}

// TestRemoveEndpointAddressPreservesRoutedAllowedIPs covers the prefixes the route manager
// attaches to a routing peer through AddAllowedIP. Those are not known to the peer.Conn that
// triggers the endpoint removal, so dropping them here would silently blackhole every route
// behind that peer on each relay or ICE disconnect.
func TestRemoveEndpointAddressPreservesRoutedAllowedIPs(t *testing.T) {
	c := newTestUSPConfigurer(t)
	peerKey := seedPeers(t, c, 3)[1]

	routed := []netip.Prefix{
		netip.MustParsePrefix("10.20.0.0/16"),
		netip.MustParsePrefix("192.168.7.0/24"),
	}
	for _, prefix := range routed {
		require.NoError(t, c.AddAllowedIP(peerKey, prefix), "add routed prefix")
	}

	before := peerAllowedIPs(t, c, peerKey)
	require.Len(t, before, 3, "peer should hold its overlay address plus both routed prefixes")

	require.NoError(t, c.RemoveEndpointAddress(peerKey), "remove endpoint address")

	assert.ElementsMatch(t, before, peerAllowedIPs(t, c, peerKey),
		"allowed IPs must survive the endpoint removal unchanged")
}

// TestRemoveEndpointAddressDoesNotScaleWithPeerCount is the regression guard for the actual
// defect: clearing one peer's endpoint used to dump and parse the whole device, so its cost
// grew with the size of the network map. On a routing peer with thousands of peers that dump
// runs on every relay and ICE transition, under the interface lock.
func TestRemoveEndpointAddressDoesNotScaleWithPeerCount(t *testing.T) {
	measure := func(peerCount int) float64 {
		c := newTestUSPConfigurer(t)
		peerKey := seedPeers(t, c, peerCount)[peerCount/2]

		return testing.AllocsPerRun(5, func() {
			require.NoError(t, c.RemoveEndpointAddress(peerKey), "remove endpoint address")
		})
	}

	small := measure(64)
	large := measure(1024)

	assert.Less(t, large, small*2,
		"clearing one endpoint allocated %.0f objects with 1024 peers against %.0f with 64: the cost still scales with the peer count",
		large, small)
}

// TestRemoveEndpointAddressFallsBackToDevice covers a peer the store never saw, which is what
// an out-of-band reconfiguration of the device leaves behind. The device stays the source of
// truth in that case, so the allowed IPs must still be preserved.
func TestRemoveEndpointAddressFallsBackToDevice(t *testing.T) {
	c := newTestUSPConfigurer(t)
	peerKey := seedPeers(t, c, 3)[1]
	require.NoError(t, c.AddAllowedIP(peerKey, netip.MustParsePrefix("10.20.0.0/16")), "add routed prefix")

	before := peerAllowedIPs(t, c, peerKey)
	c.allowedIPs.reset()

	require.NoError(t, c.RemoveEndpointAddress(peerKey), "remove endpoint address")

	assert.ElementsMatch(t, before, peerAllowedIPs(t, c, peerKey),
		"allowed IPs recovered from the device must be preserved")

	recovered, ok := c.allowedIPs.get(peerKey)
	assert.True(t, ok, "the fallback must seed the store so the next call skips the device dump")
	assert.Len(t, recovered, 2, "seeded prefixes")
}

func TestRemoveAllowedIPKeepsTheOtherPrefixes(t *testing.T) {
	c := newTestUSPConfigurer(t)
	peerKey := seedPeers(t, c, 3)[0]
	routed := netip.MustParsePrefix("10.20.0.0/16")
	require.NoError(t, c.AddAllowedIP(peerKey, routed), "add routed prefix")
	require.NoError(t, c.AddAllowedIP(peerKey, netip.MustParsePrefix("192.168.7.0/24")), "add routed prefix")

	require.NoError(t, c.RemoveAllowedIP(peerKey, routed), "remove routed prefix")

	assert.ElementsMatch(t, []string{"100.64.0.0/32", "192.168.7.0/24"}, peerAllowedIPs(t, c, peerKey),
		"only the removed prefix should be gone")

	assert.ErrorIs(t, c.RemoveAllowedIP(peerKey, routed), ErrAllowedIPNotFound,
		"removing a prefix that is no longer configured must be reported")
}
