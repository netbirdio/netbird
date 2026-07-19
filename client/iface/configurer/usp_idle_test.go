package configurer

import (
	"encoding/hex"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	wgconn "golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/netbirdio/netbird/client/iface/bind"
)

// newTestConfigurer creates a configurer backed by an in-memory wireguard-go device.
func newTestConfigurer(t *testing.T) *WGUSPConfigurer {
	t.Helper()

	tunDev, _, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr("100.64.0.1")}, []netip.Addr{}, 1280)
	require.NoError(t, err)

	wgDev := device.NewDevice(tunDev, wgconn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, "[test] "))
	t.Cleanup(wgDev.Close)

	c := NewUSPConfigurerNoUAPI(wgDev, "utun-test", bind.NewActivityRecorder())

	key, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)
	require.NoError(t, c.ConfigureInterface(key.String(), 0))

	return c
}

// peerAllowedIPs returns the allowed IPs currently installed for the given peer.
func peerAllowedIPs(t *testing.T, c *WGUSPConfigurer, pubKey string) []string {
	t.Helper()

	var ips []string
	for _, line := range peerIpcLines(t, c, pubKey) {
		if strings.HasPrefix(line, "allowed_ip=") {
			ips = append(ips, strings.TrimPrefix(line, "allowed_ip="))
		}
	}
	return ips
}

// peerEndpoint returns the endpoint currently installed for the given peer.
func peerEndpoint(t *testing.T, c *WGUSPConfigurer, pubKey string) string {
	t.Helper()

	for _, line := range peerIpcLines(t, c, pubKey) {
		if strings.HasPrefix(line, "endpoint=") {
			return strings.TrimPrefix(line, "endpoint=")
		}
	}
	return ""
}

// peerIpcLines returns the uapi config lines belonging to the given peer.
func peerIpcLines(t *testing.T, c *WGUSPConfigurer, pubKey string) []string {
	t.Helper()

	key, err := wgtypes.ParseKey(pubKey)
	require.NoError(t, err)
	hexKey := hex.EncodeToString(key[:])

	ipc, err := c.device.IpcGet()
	require.NoError(t, err)

	var lines []string
	inPeer := false
	for _, line := range strings.Split(ipc, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "public_key=") {
			inPeer = line == "public_key="+hexKey
			continue
		}
		if inPeer && line != "" {
			lines = append(lines, line)
		}
	}
	return lines
}

// TestUSPConfigurer_IdlePeerEndpointPreservesAllowedIPs verifies the invariant the lazy idle
// transition relies on: IdlePeerEndpoint re-creates the peer (dropping handshake state via the
// remove+add transaction) while keeping every installed allowed IP, including routed
// prefixes added later by the route manager, and points the endpoint at the wake listener.
func TestUSPConfigurer_IdlePeerEndpointPreservesAllowedIPs(t *testing.T) {
	c := newTestConfigurer(t)

	peerKey, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)
	pubKey := peerKey.PublicKey().String()

	overlay := netip.MustParsePrefix("100.64.0.5/32")
	routed := netip.MustParsePrefix("10.99.0.0/24")

	realEndpoint := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 51821}
	require.NoError(t, c.UpdatePeer(pubKey, []netip.Prefix{overlay}, 25*time.Second, realEndpoint, nil))
	require.NoError(t, c.AddAllowedIP(pubKey, routed))

	ips := peerAllowedIPs(t, c, pubKey)
	require.Contains(t, ips, overlay.String(), "overlay prefix must be installed before the idle endpoint swap")
	require.Contains(t, ips, routed.String(), "routed prefix must be installed before the idle endpoint swap")

	wakeEndpoint := &net.UDPAddr{IP: net.ParseIP("127.2.0.5"), Port: 17473}
	require.NoError(t, c.IdlePeerEndpoint(pubKey, []netip.Prefix{overlay}, wakeEndpoint))

	ips = peerAllowedIPs(t, c, pubKey)
	assert.Contains(t, ips, routed.String(), "routed prefix must survive the idle endpoint swap")
	assert.Contains(t, ips, overlay.String(), "overlay prefix must survive the idle endpoint swap")
	assert.Equal(t, "127.2.0.5:17473", peerEndpoint(t, c, pubKey), "endpoint must point at the wake listener after the idle endpoint swap")
}

// TestUSPConfigurer_IdlePeerEndpointCreatesMissingPeer verifies the cold-start arm path: when the
// peer does not exist yet (never connected), IdlePeerEndpoint creates it with the given base
// allowed IPs and the wake endpoint.
func TestUSPConfigurer_IdlePeerEndpointCreatesMissingPeer(t *testing.T) {
	c := newTestConfigurer(t)

	peerKey, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)
	pubKey := peerKey.PublicKey().String()

	overlay := netip.MustParsePrefix("100.64.0.5/32")
	wakeEndpoint := &net.UDPAddr{IP: net.ParseIP("127.2.0.5"), Port: 17473}

	require.NoError(t, c.IdlePeerEndpoint(pubKey, []netip.Prefix{overlay}, wakeEndpoint))

	assert.Equal(t, []string{overlay.String()}, peerAllowedIPs(t, c, pubKey), "missing peer must be created with the base allowed IPs")
	assert.Equal(t, "127.2.0.5:17473", peerEndpoint(t, c, pubKey), "missing peer must be created with the wake endpoint")
}

// TestUSPConfigurer_AddAllowedIPOnMissingPeerIsSilentNoOp documents the wireguard-go
// behavior the removed-peer idle flow raced against: AddAllowedIP uses update_only,
// which is a silent no-op when the peer does not exist. The idle transition must
// therefore keep the WireGuard peer (Conn.Idle + IdlePeerEndpoint) instead of leaving a
// window where the peer is absent.
func TestUSPConfigurer_AddAllowedIPOnMissingPeerIsSilentNoOp(t *testing.T) {
	c := newTestConfigurer(t)

	peerKey, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)
	pubKey := peerKey.PublicKey().String()

	routed := netip.MustParsePrefix("10.99.0.0/24")

	require.NoError(t, c.AddAllowedIP(pubKey, routed), "update-only on a missing peer must not return an error")

	assert.Empty(t, peerIpcLines(t, c, pubKey), "update-only call must not create the peer")
}
