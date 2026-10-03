package configurer

import (
	"encoding/hex"
	"net"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	wgdevice "golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// idleTUN never reports an up event, so the wireguard-go device stays down: no socket is
// opened, no peer goroutine starts, and the configuration state is all the tests observe.
type idleTUN struct {
	events chan tun.Event
	closed chan struct{}
}

func newIdleTUN() *idleTUN {
	return &idleTUN{events: make(chan tun.Event), closed: make(chan struct{})}
}

func (t *idleTUN) File() *os.File { return nil }

func (t *idleTUN) Read([][]byte, []int, int) (int, error) {
	<-t.closed
	return 0, os.ErrClosed
}

func (t *idleTUN) Write(bufs [][]byte, _ int) (int, error) { return len(bufs), nil }

func (t *idleTUN) MTU() (int, error) { return 1420, nil }

func (t *idleTUN) Name() (string, error) { return "idle", nil }

func (t *idleTUN) Events() <-chan tun.Event { return t.events }

func (t *idleTUN) Close() error {
	close(t.closed)
	close(t.events)
	return nil
}

func (t *idleTUN) BatchSize() int { return 1 }

func TestConfigureInterfaceAppliesKeyAndPortAndReplacesPeers(t *testing.T) {
	c := newTestUSPConfigurer(t)
	seedPeers(t, c, 2)

	key, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err, "generate device private key")
	require.NoError(t, c.ConfigureInterface(key.String(), 51820), "reconfigure the interface")

	stats, err := c.FullStats()
	require.NoError(t, err, "read device stats")
	assert.Equal(t, key.PublicKey().String(), stats.PublicKey, "device public key")
	assert.Equal(t, 51820, stats.ListenPort, "listen port")
	assert.Empty(t, stats.Peers, "configuring the interface replaces every peer")
}

func TestConfigureInterfaceRejectsAnInvalidPort(t *testing.T) {
	c := newTestUSPConfigurer(t)

	key, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err, "generate device private key")
	assert.Error(t, c.ConfigureInterface(key.String(), 70000), "a port above 65535 must be rejected")
}

func TestGetStatsIsKeyedByPeerKey(t *testing.T) {
	c := newTestUSPConfigurer(t)
	keys := seedPeers(t, c, 3)

	stats, err := c.GetStats()
	require.NoError(t, err, "read stats")
	require.Len(t, stats, 3, "one entry per peer")
	for _, key := range keys {
		entry, ok := stats[key]
		require.True(t, ok, "peer %s must be reported", key)
		assert.Zero(t, entry.TxBytes, "no traffic was sent")
		assert.Zero(t, entry.RxBytes, "no traffic was received")
		assert.True(t, entry.LastHandshake.IsZero(), "no handshake happened")
	}
}

func TestFullStatsMatchesTheDeviceDump(t *testing.T) {
	c := newTestUSPConfigurer(t)

	priv, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err, "generate peer private key")
	peerKey := priv.PublicKey().String()
	psk, err := wgtypes.GenerateKey()
	require.NoError(t, err, "generate preshared key")
	endpoint := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 10), Port: 51820}
	prefixes := []netip.Prefix{netip.MustParsePrefix("100.64.0.1/32"), netip.MustParsePrefix("10.20.0.0/16")}
	require.NoError(t, c.UpdatePeer(peerKey, prefixes, 25*time.Second, endpoint, &psk), "add peer")

	stats, err := c.FullStats()
	require.NoError(t, err, "read device stats")
	require.Len(t, stats.Peers, 1, "one peer on the device")
	peer := stats.Peers[0]
	assert.Equal(t, peerKey, peer.PublicKey, "peer key")
	assert.Equal(t, "192.0.2.10:51820", peer.Endpoint.String(), "endpoint")
	assert.Equal(t, [32]byte(psk), peer.PresharedKey, "preshared key")
	assert.Equal(t, []string{"100.64.0.1/32", "10.20.0.0/16"}, ipNetStrings(peer.AllowedIPs), "allowed IPs")

	block := uapiPeerBlock(t, c, peerKey)
	assert.Contains(t, block, "endpoint=192.0.2.10:51820", "the dump must show the endpoint")
	assert.Contains(t, block, "preshared_key="+hex.EncodeToString(psk[:]), "the dump must show the preshared key")
	assert.Contains(t, block, "persistent_keepalive_interval=25", "the dump must show the keepalive")
	assert.Contains(t, block, "allowed_ip=100.64.0.1/32", "the dump must show the first prefix")
	assert.Contains(t, block, "allowed_ip=10.20.0.0/16", "the dump must show the second prefix")
}

func TestRemoveEndpointAddressKeepsThePeerAndStopsTheKeepalive(t *testing.T) {
	c := newTestUSPConfigurer(t)

	priv, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err, "generate peer private key")
	peerKey := priv.PublicKey().String()
	endpoint := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 10), Port: 51820}
	prefixes := []netip.Prefix{netip.MustParsePrefix("100.64.0.1/32")}
	require.NoError(t, c.UpdatePeer(peerKey, prefixes, 25*time.Second, endpoint, nil), "add peer")
	before := c.device.LookupPeer(wgdevice.NoisePublicKey(priv.PublicKey()))
	require.NotNil(t, before, "the peer must be on the device")

	require.NoError(t, c.RemoveEndpointAddress(peerKey), "remove endpoint address")

	assert.Same(t, before, c.device.LookupPeer(wgdevice.NoisePublicKey(priv.PublicKey())),
		"the peer object must survive the endpoint removal")
	stats, err := c.FullStats()
	require.NoError(t, err, "read device stats")
	require.Len(t, stats.Peers, 1, "the peer stays configured")
	assert.Nil(t, stats.Peers[0].Endpoint.IP, "the endpoint must be gone")
	assert.Equal(t, []string{"100.64.0.1/32"}, ipNetStrings(stats.Peers[0].AllowedIPs), "allowed IPs survive")
	assert.Contains(t, uapiPeerBlock(t, c, peerKey), "persistent_keepalive_interval=0",
		"an endpoint-less peer must not keep sending keepalives")

	require.NoError(t, c.UpdatePeer(peerKey, prefixes, 25*time.Second, endpoint, nil), "restore the endpoint")
	block := uapiPeerBlock(t, c, peerKey)
	assert.Contains(t, block, "endpoint=192.0.2.10:51820", "the endpoint must be back")
	assert.Contains(t, block, "persistent_keepalive_interval=25", "the keepalive must be back")
}

func TestUpdatePeerRejectsAnInvalidPrefix(t *testing.T) {
	c := newTestUSPConfigurer(t)

	priv, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err, "generate peer private key")
	peerKey := priv.PublicKey().String()

	require.Error(t, c.UpdatePeer(peerKey, []netip.Prefix{{}}, 25*time.Second, nil, nil), "an invalid prefix must be rejected")

	stats, err := c.FullStats()
	require.NoError(t, err, "read device stats")
	assert.Empty(t, stats.Peers, "the peer must not have reached the device")
}

func TestRemoveAllowedIPOnAbsentPeerReportsThePeer(t *testing.T) {
	c := newTestUSPConfigurer(t)

	priv, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err, "generate peer private key")

	assert.ErrorIs(t, c.RemoveAllowedIP(priv.PublicKey().String(), netip.MustParsePrefix("10.20.0.0/16")), ErrPeerNotFound,
		"removing a prefix from a peer the device does not have must report the peer")
}

func ipNetStrings(ipNets []net.IPNet) []string {
	out := make([]string, 0, len(ipNets))
	for _, ipNet := range ipNets {
		out = append(out, ipNet.String())
	}
	return out
}

// uapiPeerBlock reads the device back through the UAPI dump, the path this package no
// longer uses, so a typed write is checked against an independent view of the device.
func uapiPeerBlock(t *testing.T, c *WGUSPConfigurer, peerKey string) []string {
	t.Helper()

	parsed, err := wgtypes.ParseKey(peerKey)
	require.NoError(t, err, "parse peer key")
	wanted := "public_key=" + hex.EncodeToString(parsed[:])

	dump, err := c.device.IpcGet()
	require.NoError(t, err, "dump device")

	var block []string
	inBlock := false
	for _, line := range strings.Split(strings.TrimSpace(dump), "\n") {
		if strings.HasPrefix(line, "public_key=") {
			inBlock = line == wanted
			continue
		}
		if inBlock {
			block = append(block, line)
		}
	}
	require.NotEmpty(t, block, "peer %s must appear in the dump", peerKey)
	return block
}
