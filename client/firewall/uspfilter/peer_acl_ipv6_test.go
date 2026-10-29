package uspfilter

import (
	"net"
	"net/netip"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	fw "github.com/netbirdio/netbird/client/firewall/manager"
	nbiface "github.com/netbirdio/netbird/client/iface"
	"github.com/netbirdio/netbird/client/iface/device"
	"github.com/netbirdio/netbird/client/iface/wgaddr"
)

func newV6TestManager(t *testing.T, localV6 string) *Manager {
	t.Helper()
	ifaceMock := &IFaceMock{
		SetFilterFunc: func(device.PacketFilter) error { return nil },
		AddressFunc: func() wgaddr.Address {
			return wgaddr.Address{
				IP:      netip.MustParseAddr("100.10.0.100"),
				Network: netip.MustParsePrefix("100.10.0.0/16"),
				IPv6:    netip.MustParseAddr(localV6),
				IPv6Net: netip.MustParsePrefix("fd00::/64"),
			}
		},
	}
	m, err := Create(Config{IFace: ifaceMock, FlowLogger: flowLogger, MTU: nbiface.DefaultMTU})
	require.NoError(t, err, "create manager")
	t.Cleanup(func() { require.NoError(t, m.Close(nil)) })
	return m
}

func v6UDPPacket(t *testing.T, src, dst string, dstPort uint16) []byte {
	t.Helper()
	ip6 := &layers.IPv6{
		Version:    6,
		HopLimit:   64,
		NextHeader: layers.IPProtocolUDP,
		SrcIP:      net.ParseIP(src),
		DstIP:      net.ParseIP(dst),
	}
	udp := &layers.UDP{SrcPort: 51334, DstPort: layers.UDPPort(dstPort)}
	require.NoError(t, udp.SetNetworkLayerForChecksum(ip6))

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}
	require.NoError(t, gopacket.SerializeLayers(buf, opts, ip6, udp, gopacket.Payload("test")))
	return buf.Bytes()
}

// TestPeerACL_IPv6HostRule verifies the source index resolves /128 v6
// rules: a matching v6 source is accepted, a non-matching one is
// denied by the default. This is the end-to-end proof that the index
// is not v4-only.
func TestPeerACL_IPv6HostRule(t *testing.T) {
	m := newV6TestManager(t, "fd00::100")

	src := net.ParseIP("fd00::1")
	_, err := m.AddFilterRule(nil, pfx(src), fw.Network{}, fw.ProtocolUDP, nil, &fw.Port{Values: []uint16{53}}, fw.ActionAccept)
	require.NoError(t, err, "add v6 accept rule")

	require.False(t, m.filterInbound(v6UDPPacket(t, "fd00::1", "fd00::100", 53), 0),
		"v6 packet from the allowed /128 source must be accepted")
	require.True(t, m.filterInbound(v6UDPPacket(t, "fd00::2", "fd00::100", 53), 0),
		"v6 packet from an unlisted source must be denied by default")
}

// TestPeerACL_IPv6IndexBuckets verifies that v6 sources land in the
// right index bucket: a /128 in bySource keyed by its address, and
// coarser prefixes (including ::/0) in the nonHost slice.
func TestPeerACL_IPv6IndexBuckets(t *testing.T) {
	m := newV6TestManager(t, "fd00::100")
	port := &fw.Port{Values: []uint16{53}}

	host := netip.MustParseAddr("fd00::1")
	_, err := m.AddFilterRule(nil, []netip.Prefix{netip.PrefixFrom(host, 128)}, fw.Network{}, fw.ProtocolUDP, nil, port, fw.ActionAccept)
	require.NoError(t, err)
	assert.Contains(t, m.incomingAcceptIndex.bySource, host, "/128 v6 source must be indexed by address")

	_, err = m.AddFilterRule(nil, []netip.Prefix{netip.MustParsePrefix("fd00:dead::/64")}, fw.Network{}, fw.ProtocolUDP, nil, port, fw.ActionAccept)
	require.NoError(t, err)
	require.Len(t, m.incomingAcceptIndex.nonHost, 1, "coarser v6 prefix must land in nonHost")

	_, err = m.AddFilterRule(nil, []netip.Prefix{netip.MustParsePrefix("::/0")}, fw.Network{}, fw.ProtocolUDP, nil, port, fw.ActionAccept)
	require.NoError(t, err)
	require.Len(t, m.incomingAcceptIndex.nonHost, 2, "::/0 source must also land in nonHost")
}

// TestPeerACL_IPv4MappedSourceNormalized verifies a v4-mapped v6
// source prefix is normalized to v4 so a plain v4 packet matches it.
func TestPeerACL_IPv4MappedSourceNormalized(t *testing.T) {
	m := newTestManager(t)

	mapped := netip.MustParseAddr("::ffff:192.168.1.1")
	_, err := m.AddFilterRule(nil, []netip.Prefix{netip.PrefixFrom(mapped, mapped.BitLen())}, fw.Network{}, fw.ProtocolUDP, nil, &fw.Port{Values: []uint16{53}}, fw.ActionAccept)
	require.NoError(t, err)

	v4 := netip.MustParseAddr("192.168.1.1")
	assert.Contains(t, m.incomingAcceptIndex.bySource, v4, "v4-mapped v6 source must be indexed as plain v4")
}
