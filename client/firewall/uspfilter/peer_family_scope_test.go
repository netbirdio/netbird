package uspfilter

import (
	"net"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	fw "github.com/netbirdio/netbird/client/firewall/manager"
)

// peerACLCheck decodes the packet and runs it through the peer ACLs,
// returning the attributed management rule id and the drop verdict.
func peerACLCheck(t *testing.T, m *Manager, packet []byte) ([]byte, bool) {
	t.Helper()
	d := m.decoders.Get().(*decoder)
	defer m.decoders.Put(d)
	require.NoError(t, d.decodePacket(packet))
	src, _ := m.extractIPs(d)
	return m.peerACLsBlock(src, d, packet)
}

// TestPeerACL_MultiValuePortMatchesEachListedPort guards the multi-value
// port path: a rule listing several discrete destination ports must
// match a packet to each listed port and drop one that is not listed.
// Management currently splits a multi-port policy into one rule per port
// (and the wire format carries a single port), so this list shape is not
// emitted today; the test locks correct matching in case that changes.
func TestPeerACL_MultiValuePortMatchesEachListedPort(t *testing.T) {
	m := newTestManager(t)

	src := net.ParseIP("192.168.1.1")
	ports := &fw.Port{Values: []uint16{80, 443}}
	_, err := m.AddFilterRule(nil, pfx(src), fw.Network{}, fw.ProtocolTCP, nil, ports, fw.ActionAccept)
	require.NoError(t, err, "add multi-value port rule")

	for _, p := range []uint16{80, 443} {
		_, blocked := peerACLCheck(t, m, createTestPacket(t, "192.168.1.1", "10.0.0.2", fw.ProtocolTCP, 12345, p))
		assert.False(t, blocked, "packet to listed port %d must match the rule", p)
	}

	_, blocked := peerACLCheck(t, m, createTestPacket(t, "192.168.1.1", "10.0.0.2", fw.ProtocolTCP, 12345, 8080))
	assert.True(t, blocked, "packet to a port not in the list must not match the rule")
}

// TestPeerACL_MatchAnyIsFamilyScoped verifies that a /0 source matches
// only packets of its own family: 0.0.0.0/0 must not match IPv6 packets
// and ::/0 must not match IPv4 packets, matching kernel backend
// semantics.
func TestPeerACL_MatchAnyIsFamilyScoped(t *testing.T) {
	m := newTestManager(t)

	v4Packet := createTestPacket(t, "10.0.0.1", "10.0.0.2", fw.ProtocolUDP, 12345, 53)
	v6Packet := v6UDPPacket(t, "fd00::1", "fd00::100", 53)

	v4Any := []netip.Prefix{netip.PrefixFrom(netip.IPv4Unspecified(), 0)}
	rule, err := m.AddFilterRule(nil, v4Any, fw.Network{}, fw.ProtocolALL, nil, nil, fw.ActionAccept)
	require.NoError(t, err, "add v4 /0 rule")

	_, blocked := peerACLCheck(t, m, v4Packet)
	assert.False(t, blocked, "0.0.0.0/0 must match IPv4 packets")
	_, blocked = peerACLCheck(t, m, v6Packet)
	assert.True(t, blocked, "0.0.0.0/0 must not match IPv6 packets")

	require.NoError(t, m.DeleteFilterRule(rule))

	v6Any := []netip.Prefix{netip.PrefixFrom(netip.IPv6Unspecified(), 0)}
	_, err = m.AddFilterRule(nil, v6Any, fw.Network{}, fw.ProtocolALL, nil, nil, fw.ActionAccept)
	require.NoError(t, err, "add v6 /0 rule")

	_, blocked = peerACLCheck(t, m, v6Packet)
	assert.False(t, blocked, "::/0 must match IPv6 packets")
	_, blocked = peerACLCheck(t, m, v4Packet)
	assert.True(t, blocked, "::/0 must not match IPv4 packets")
}

// TestRouteACL_MixedFamilyZeroSourcesStayFamilySafe verifies the route
// path keeps per-prefix family matching when a single rule carries both
// 0.0.0.0/0 and ::/0 sources, as blockInvalidRouted does.
func TestRouteACL_MixedFamilyZeroSourcesStayFamilySafe(t *testing.T) {
	m := newTestManager(t)

	sources := []netip.Prefix{
		netip.PrefixFrom(netip.IPv4Unspecified(), 0),
		netip.PrefixFrom(netip.IPv6Unspecified(), 0),
	}

	_, err := m.AddFilterRule(nil, sources, fw.Network{Prefix: netip.MustParsePrefix("10.0.0.0/24")},
		fw.ProtocolALL, nil, nil, fw.ActionAccept)
	require.NoError(t, err)
	_, err = m.AddFilterRule(nil, sources, fw.Network{Prefix: netip.MustParsePrefix("fd00:1::/64")},
		fw.ProtocolALL, nil, nil, fw.ActionAccept)
	require.NoError(t, err)

	v4Src := netip.MustParseAddr("192.168.1.1")
	v6Src := netip.MustParseAddr("fd00::1")

	_, pass := m.routeACLsPass(v4Src, netip.MustParseAddr("10.0.0.5"), 255, 0, 0)
	assert.True(t, pass, "v4 source must match the v4 destination rule via 0.0.0.0/0")
	_, pass = m.routeACLsPass(v6Src, netip.MustParseAddr("fd00:1::5"), 255, 0, 0)
	assert.True(t, pass, "v6 source must match the v6 destination rule via ::/0")
	_, pass = m.routeACLsPass(v6Src, netip.MustParseAddr("10.0.0.5"), 255, 0, 0)
	assert.True(t, pass, "v6 source still passes the v4 destination rule via ::/0 in the same source list")
}
