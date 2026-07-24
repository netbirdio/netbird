package uspfilter

import (
	"encoding/binary"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/require"

	fw "github.com/netbirdio/netbird/client/firewall/manager"
	nbiface "github.com/netbirdio/netbird/client/iface"
	"github.com/netbirdio/netbird/client/iface/device"
	"github.com/netbirdio/netbird/client/iface/wgaddr"
)

const (
	fragTestSrc   = "100.10.0.1"
	fragTestDst   = "100.10.0.100"
	fragTestSrcV6 = "fd00::1"
	fragTestDstV6 = "fd00::100"
)

func newFragmentTestManager(tb testing.TB) *Manager {
	tb.Helper()

	ifaceMock := &IFaceMock{
		SetFilterFunc: func(device.PacketFilter) error { return nil },
		AddressFunc: func() wgaddr.Address {
			return wgaddr.Address{
				IP:      netip.MustParseAddr(fragTestDst),
				Network: netip.MustParsePrefix("100.10.0.0/16"),
				IPv6:    netip.MustParseAddr(fragTestDstV6),
				IPv6Net: netip.MustParsePrefix("fd00::/64"),
			}
		},
	}

	m, err := Create(ifaceMock, false, flowLogger, nbiface.DefaultMTU)
	require.NoError(tb, err)
	require.NoError(tb, m.UpdateLocalIPs())
	tb.Cleanup(func() { require.NoError(tb, m.Close(nil)) })
	return m
}

// firstFragmentUDPTo builds the first fragment of a fragmented UDP datagram to
// the given destination: it carries the full UDP header plus payloadLen bytes
// of data, with the More Fragments flag set and offset zero.
func firstFragmentUDPTo(tb testing.TB, dst string, id uint16, dstPort uint16, payloadLen int) []byte {
	tb.Helper()

	ip := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Id:       id,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    net.ParseIP(fragTestSrc),
		DstIP:    net.ParseIP(dst),
		Flags:    layers.IPv4MoreFragments,
	}
	udp := &layers.UDP{SrcPort: 40000, DstPort: layers.UDPPort(dstPort)}
	require.NoError(tb, udp.SetNetworkLayerForChecksum(ip))

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}
	require.NoError(tb, gopacket.SerializeLayers(buf, opts, ip, udp, gopacket.Payload(make([]byte, payloadLen))))
	return buf.Bytes()
}

func firstFragmentUDP(tb testing.TB, id uint16, dstPort uint16, payloadLen int) []byte {
	tb.Helper()
	return firstFragmentUDPTo(tb, fragTestDst, id, dstPort, payloadLen)
}

// firstFragmentTCP builds the first fragment of a fragmented TCP datagram: the
// full 20-byte TCP header plus 12 bytes of data, with the More Fragments flag
// set and offset zero.
func firstFragmentTCP(tb testing.TB, id uint16, dstPort uint16) []byte {
	tb.Helper()

	ip := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Id:       id,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    net.ParseIP(fragTestSrc),
		DstIP:    net.ParseIP(fragTestDst),
		Flags:    layers.IPv4MoreFragments,
	}
	tcp := &layers.TCP{SrcPort: 40000, DstPort: layers.TCPPort(dstPort), SYN: true, Window: 64240}
	require.NoError(tb, tcp.SetNetworkLayerForChecksum(ip))

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}
	require.NoError(tb, gopacket.SerializeLayers(buf, opts, ip, tcp, gopacket.Payload(make([]byte, 12))))
	return buf.Bytes()
}

// trailingFragmentTo builds a non-first fragment to the given destination: an
// IPv4 header at the given fragment offset (in 8-byte units) carrying raw
// payload and no L4 header.
func trailingFragmentTo(tb testing.TB, dst string, proto layers.IPProtocol, id uint16, fragOffsetOctets uint16, moreFragments bool, payloadLen int) []byte {
	tb.Helper()

	ip := &layers.IPv4{
		Version:    4,
		TTL:        64,
		Id:         id,
		Protocol:   proto,
		SrcIP:      net.ParseIP(fragTestSrc),
		DstIP:      net.ParseIP(dst),
		FragOffset: fragOffsetOctets,
	}
	if moreFragments {
		ip.Flags = layers.IPv4MoreFragments
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true}
	require.NoError(tb, gopacket.SerializeLayers(buf, opts, ip, gopacket.Payload(make([]byte, payloadLen))))
	return buf.Bytes()
}

func trailingFragment(tb testing.TB, id uint16, fragOffsetOctets uint16, moreFragments bool, payloadLen int) []byte {
	tb.Helper()
	return trailingFragmentTo(tb, fragTestDst, layers.IPProtocolUDP, id, fragOffsetOctets, moreFragments, payloadLen)
}

// outboundUDPPacket builds a complete outbound UDP packet from the local
// address, used to establish conntrack state for reply-direction tests.
func outboundUDPPacket(tb testing.TB, srcPort, dstPort uint16) []byte {
	tb.Helper()

	ip := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Id:       1,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    net.ParseIP(fragTestDst),
		DstIP:    net.ParseIP(fragTestSrc),
	}
	udp := &layers.UDP{SrcPort: layers.UDPPort(srcPort), DstPort: layers.UDPPort(dstPort)}
	require.NoError(tb, udp.SetNetworkLayerForChecksum(ip))

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}
	require.NoError(tb, gopacket.SerializeLayers(buf, opts, ip, udp, gopacket.Payload(make([]byte, 16))))
	return buf.Bytes()
}

// normalUDPPacket builds a complete, non-fragmented UDP packet for baseline
// comparisons against the fragment paths.
func normalUDPPacket(tb testing.TB, dstPort uint16, payloadLen int) []byte {
	tb.Helper()

	ip := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Id:       1,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    net.ParseIP(fragTestSrc),
		DstIP:    net.ParseIP(fragTestDst),
	}
	udp := &layers.UDP{SrcPort: 40000, DstPort: layers.UDPPort(dstPort)}
	require.NoError(tb, udp.SetNetworkLayerForChecksum(ip))

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}
	require.NoError(tb, gopacket.SerializeLayers(buf, opts, ip, udp, gopacket.Payload(make([]byte, payloadLen))))
	return buf.Bytes()
}

func allowUDP(tb testing.TB, m *Manager, dstPort uint16) {
	tb.Helper()
	_, err := m.AddPeerFiltering(nil, net.ParseIP(fragTestSrc), fw.ProtocolUDP, nil,
		&fw.Port{Values: []uint16{dstPort}}, fw.ActionAccept, "")
	require.NoError(tb, err)
}

// TestFragment_TrailingWithoutFirstDropped is the core bypass repro: a trailing
// fragment with no allowed first fragment on record must be dropped. Before the
// fix, filterInbound returned false (allow) for any fragment.
func TestFragment_TrailingWithoutFirstDropped(t *testing.T) {
	m := newFragmentTestManager(t)

	frag := trailingFragment(t, 0x1234, 185, false, 40)
	require.True(t, m.filterInbound(frag, len(frag)),
		"trailing fragment without an allowed first fragment must be dropped")
}

// TestFragment_AllowedFirstPassesTrailing verifies that once a first fragment
// passes the ACL, its trailing fragments inherit the allow verdict.
func TestFragment_AllowedFirstPassesTrailing(t *testing.T) {
	m := newFragmentTestManager(t)
	allowUDP(t, m, 8080)

	// First fragment: UDP header (8) + 32 payload = 40 octets -> headerEnd = 5.
	first := firstFragmentUDP(t, 0x2222, 8080, 32)
	require.False(t, m.filterInbound(first, len(first)),
		"allowed first fragment should pass and be recorded")

	trailing := trailingFragment(t, 0x2222, 5, false, 24)
	require.False(t, m.filterInbound(trailing, len(trailing)),
		"trailing fragment of an allowed datagram should pass")
}

// TestFragment_DeniedFirstDropsTrailing verifies that a first fragment blocked
// by the ACL leaves no verdict, so its trailing fragments are dropped.
func TestFragment_DeniedFirstDropsTrailing(t *testing.T) {
	m := newFragmentTestManager(t)
	// No accept rule: local traffic defaults to deny.

	first := firstFragmentUDP(t, 0x3333, 9999, 32)
	require.True(t, m.filterInbound(first, len(first)),
		"first fragment to a blocked port should be dropped by the ACL")

	trailing := trailingFragment(t, 0x3333, 5, false, 24)
	require.True(t, m.filterInbound(trailing, len(trailing)),
		"trailing fragment of a denied datagram must be dropped")
}

// TestFragment_OverlappingHeaderDropped covers the RFC 1858 §4 / RFC 3128
// overlapping-fragment rewrite: a trailing fragment starting inside the range
// the ACL already inspected is dropped and poisons the datagram. TCP is used so
// the overlap lands on real header bytes (the flags at byte 13).
func TestFragment_OverlappingHeaderDropped(t *testing.T) {
	m := newFragmentTestManager(t)
	_, err := m.AddPeerFiltering(nil, net.ParseIP(fragTestSrc), fw.ProtocolTCP, nil,
		&fw.Port{Values: []uint16{8080}}, fw.ActionAccept, "")
	require.NoError(t, err)

	// First fragment: TCP header (20) + 12 data = 32 bytes -> headerEnd = 4 octets.
	first := firstFragmentTCP(t, 0x4444, 8080)
	require.False(t, m.filterInbound(first, len(first)))

	// Overlapping fragment at offset 1 (byte 8) falls inside the inspected TCP
	// header, so it could rewrite the flags or port on reassembly.
	overlap := trailingFragmentTo(t, fragTestDst, layers.IPProtocolTCP, 0x4444, 1, true, 32)
	require.True(t, m.filterInbound(overlap, len(overlap)),
		"fragment overlapping the inspected header must be dropped")

	// The datagram is now poisoned: a later, non-overlapping fragment is also
	// dropped because the verdict was removed.
	later := trailingFragmentTo(t, fragTestDst, layers.IPProtocolTCP, 0x4444, 4, false, 24)
	require.True(t, m.filterInbound(later, len(later)),
		"fragments after an overlap must be dropped (datagram poisoned)")
}

// TestFragment_OffsetZeroOverlapPoisons covers the RFC 3128 offset-zero rewrite:
// an allowed first fragment followed by a denied offset-zero fragment for the
// same datagram must not leave the earlier allow verdict in place.
func TestFragment_OffsetZeroOverlapPoisons(t *testing.T) {
	m := newFragmentTestManager(t)
	allowUDP(t, m, 8080)

	allowed := firstFragmentUDP(t, 0x5A5A, 8080, 32)
	require.False(t, m.filterInbound(allowed, len(allowed)),
		"allowed first fragment should pass and be recorded")

	// A second offset-zero fragment to a denied port supersedes the datagram's
	// verdict; it is dropped and must not leave the allow in place.
	denied := firstFragmentUDP(t, 0x5A5A, 9999, 32)
	require.True(t, m.filterInbound(denied, len(denied)),
		"denied offset-zero fragment must be dropped")

	trailing := trailingFragment(t, 0x5A5A, 5, false, 24)
	require.True(t, m.filterInbound(trailing, len(trailing)),
		"trailing fragment must be denied after the datagram was poisoned")
}

// TestFragment_TinyFirstDropped covers the tiny-fragment attack: a first
// fragment too small to contain the full transport header can't be
// ACL-evaluated and must be dropped.
func TestFragment_TinyFirstDropped(t *testing.T) {
	m := newFragmentTestManager(t)
	allowUDP(t, m, 8080)

	// IPv4 header + 4 raw bytes, MF set, offset 0: too small for the 8-byte UDP
	// header, so it decodes to L3 only.
	tiny := trailingFragment(t, 0x5555, 0, true, 4)
	require.True(t, m.filterInbound(tiny, len(tiny)),
		"tiny first fragment without a full L4 header must be dropped")
}

// TestFragment_TCPFirstFragment verifies the TCP arm of the transport decode: a
// first fragment carrying the full 20-byte TCP header is ACL-evaluated and its
// trailing fragments inherit the verdict.
func TestFragment_TCPFirstFragment(t *testing.T) {
	m := newFragmentTestManager(t)
	_, err := m.AddPeerFiltering(nil, net.ParseIP(fragTestSrc), fw.ProtocolTCP, nil,
		&fw.Port{Values: []uint16{8080}}, fw.ActionAccept, "")
	require.NoError(t, err)

	// TCP header (20) + 12 data = 32 bytes -> headerEnd = 4 octets.
	first := firstFragmentTCP(t, 0x6666, 8080)
	require.False(t, m.filterInbound(first, len(first)),
		"allowed TCP first fragment should pass and be recorded")

	trailing := trailingFragmentTo(t, fragTestDst, layers.IPProtocolTCP, 0x6666, 4, false, 24)
	require.False(t, m.filterInbound(trailing, len(trailing)),
		"trailing fragment of an allowed TCP datagram should pass")
}

// TestFragment_TCPTinyFirstDropped verifies the TCP minimum header length: 12
// bytes would satisfy a UDP header but falls short of the 20-byte TCP header.
func TestFragment_TCPTinyFirstDropped(t *testing.T) {
	m := newFragmentTestManager(t)
	_, err := m.AddPeerFiltering(nil, net.ParseIP(fragTestSrc), fw.ProtocolTCP, nil,
		&fw.Port{Values: []uint16{8080}}, fw.ActionAccept, "")
	require.NoError(t, err)

	tiny := trailingFragmentTo(t, fragTestDst, layers.IPProtocolTCP, 0x7777, 0, true, 12)
	require.True(t, m.filterInbound(tiny, len(tiny)),
		"first fragment shorter than the TCP header must be dropped")
}

// TestFragment_ConntrackAllowsFirstFragment verifies the conntrack branch: reply
// fragments of an outbound-established UDP flow pass without any inbound rule.
func TestFragment_ConntrackAllowsFirstFragment(t *testing.T) {
	m := newFragmentTestManager(t)

	out := outboundUDPPacket(t, 12345, 40000)
	require.False(t, m.filterOutbound(out, len(out)))

	first := firstFragmentUDP(t, 0x8888, 12345, 32)
	require.False(t, m.filterInbound(first, len(first)),
		"reply first fragment should pass via conntrack")

	trailing := trailingFragment(t, 0x8888, 5, false, 24)
	require.False(t, m.filterInbound(trailing, len(trailing)),
		"trailing fragment of a tracked flow should pass")
}

// TestFragment_RoutingDisabledDropsFragment verifies routed first fragments are
// dropped when routing is disabled.
func TestFragment_RoutingDisabledDropsFragment(t *testing.T) {
	m := newFragmentTestManager(t)
	m.routingEnabled.Store(false)

	first := firstFragmentUDPTo(t, "198.51.100.10", 0x9999, 8080, 32)
	require.True(t, m.filterInbound(first, len(first)),
		"routed first fragment must be dropped when routing is disabled")
}

// TestFragment_RouteACL verifies the route-ACL branch: fragments to a non-local
// destination follow the route rules, allowed datagrams pass their trailing
// fragments and denied ones don't.
func TestFragment_RouteACL(t *testing.T) {
	m := newFragmentTestManager(t)
	m.routingEnabled.Store(true)
	m.nativeRouter.Store(false)

	_, err := m.AddRouteFiltering(
		[]byte("rt-1"),
		[]netip.Prefix{netip.MustParsePrefix("100.10.0.0/16")},
		fw.Network{Prefix: netip.MustParsePrefix("198.51.100.0/24")},
		fw.ProtocolUDP,
		nil,
		&fw.Port{Values: []uint16{8080}},
		fw.ActionAccept,
	)
	require.NoError(t, err)

	first := firstFragmentUDPTo(t, "198.51.100.10", 0xAAAA, 8080, 32)
	require.False(t, m.filterInbound(first, len(first)),
		"route-ACL-allowed first fragment should pass")
	trailing := trailingFragmentTo(t, "198.51.100.10", layers.IPProtocolUDP, 0xAAAA, 5, false, 24)
	require.False(t, m.filterInbound(trailing, len(trailing)),
		"trailing fragment of an allowed routed datagram should pass")

	denied := firstFragmentUDPTo(t, "198.51.100.10", 0xBBBB, 9999, 32)
	require.True(t, m.filterInbound(denied, len(denied)),
		"route-ACL-denied first fragment must be dropped")
	deniedTrailing := trailingFragmentTo(t, "198.51.100.10", layers.IPProtocolUDP, 0xBBBB, 5, false, 24)
	require.True(t, m.filterInbound(deniedTrailing, len(deniedTrailing)),
		"trailing fragment of a denied routed datagram must be dropped")
}

// TestFragment_ExpiredVerdictDropsTrailing verifies a verdict older than the
// tracker timeout no longer admits trailing fragments.
func TestFragment_ExpiredVerdictDropsTrailing(t *testing.T) {
	m := newFragmentTestManager(t)
	allowUDP(t, m, 8080)

	first := firstFragmentUDP(t, 0xCCCC, 8080, 32)
	require.False(t, m.filterInbound(first, len(first)))

	m.fragments.mutex.Lock()
	for key, entry := range m.fragments.entries {
		entry.recordedAt = time.Now().Add(-defaultFragmentTimeout - time.Second)
		m.fragments.entries[key] = entry
	}
	m.fragments.mutex.Unlock()

	trailing := trailingFragment(t, 0xCCCC, 5, false, 24)
	require.True(t, m.filterInbound(trailing, len(trailing)),
		"trailing fragment after verdict expiry must be dropped")
}

// TestFragment_CapacityFailsClosed verifies the table cap: at capacity, new
// datagram verdicts are not recorded (their trailing fragments are dropped)
// while already-recorded datagrams keep working.
func TestFragment_CapacityFailsClosed(t *testing.T) {
	m := newFragmentTestManager(t)
	allowUDP(t, m, 8080)

	m.fragments.mutex.Lock()
	m.fragments.maxEntries = 1
	m.fragments.mutex.Unlock()

	first1 := firstFragmentUDP(t, 0x0101, 8080, 32)
	require.False(t, m.filterInbound(first1, len(first1)))

	first2 := firstFragmentUDP(t, 0x0202, 8080, 32)
	require.False(t, m.filterInbound(first2, len(first2)),
		"first fragment itself still passes at capacity")

	trailing2 := trailingFragment(t, 0x0202, 5, false, 24)
	require.True(t, m.filterInbound(trailing2, len(trailing2)),
		"trailing fragment of an unrecorded datagram must be dropped at capacity")

	trailing1 := trailingFragment(t, 0x0101, 5, false, 24)
	require.False(t, m.filterInbound(trailing1, len(trailing1)),
		"already-recorded datagram should keep passing at capacity")
}

// v6FragmentHeader builds the 8-byte IPv6 fragment extension header for the
// given inner protocol, offset (8-byte units), More Fragments bit and id.
func v6FragmentHeader(proto layers.IPProtocol, offsetOctets uint16, moreFragments bool, id uint32) []byte {
	offsetFlags := offsetOctets << 3
	if moreFragments {
		offsetFlags |= 1
	}
	hdr := make([]byte, 8)
	hdr[0] = uint8(proto)
	binary.BigEndian.PutUint16(hdr[2:4], offsetFlags)
	binary.BigEndian.PutUint32(hdr[4:8], id)
	return hdr
}

func v6UDPHeader(dstPort uint16, dataLen int) []byte {
	hdr := make([]byte, 8)
	binary.BigEndian.PutUint16(hdr[0:2], 40000)
	binary.BigEndian.PutUint16(hdr[2:4], dstPort)
	binary.BigEndian.PutUint16(hdr[4:6], uint16(8+dataLen))
	return hdr
}

// firstFragmentUDPv6 builds the first fragment of a fragmented IPv6 UDP
// datagram: fragment header (offset 0, More Fragments set) + full UDP header +
// data.
func firstFragmentUDPv6(tb testing.TB, id uint32, dstPort uint16, dataLen int) []byte {
	tb.Helper()
	return fragmentUDPv6(tb, id, dstPort, dataLen, true)
}

// fragmentUDPv6 builds an offset-zero IPv6 UDP fragment. With moreFragments
// false it is an atomic fragment (a complete datagram, RFC 6946).
func fragmentUDPv6(tb testing.TB, id uint32, dstPort uint16, dataLen int, moreFragments bool) []byte {
	tb.Helper()

	ip := &layers.IPv6{
		Version:    6,
		NextHeader: layers.IPProtocolIPv6Fragment,
		HopLimit:   64,
		SrcIP:      net.ParseIP(fragTestSrcV6),
		DstIP:      net.ParseIP(fragTestDstV6),
	}
	payload := append(v6FragmentHeader(layers.IPProtocolUDP, 0, moreFragments, id), v6UDPHeader(dstPort, dataLen)...)
	payload = append(payload, make([]byte, dataLen)...)

	buf := gopacket.NewSerializeBuffer()
	require.NoError(tb, gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true}, ip, gopacket.Payload(payload)))
	return buf.Bytes()
}

// trailingFragmentV6 builds a non-first IPv6 fragment: fragment header at the
// given offset carrying raw data and no transport header.
func trailingFragmentV6(tb testing.TB, id uint32, offsetOctets uint16, moreFragments bool, dataLen int) []byte {
	tb.Helper()

	ip := &layers.IPv6{
		Version:    6,
		NextHeader: layers.IPProtocolIPv6Fragment,
		HopLimit:   64,
		SrcIP:      net.ParseIP(fragTestSrcV6),
		DstIP:      net.ParseIP(fragTestDstV6),
	}
	payload := append(v6FragmentHeader(layers.IPProtocolUDP, offsetOctets, moreFragments, id), make([]byte, dataLen)...)

	buf := gopacket.NewSerializeBuffer()
	require.NoError(tb, gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true}, ip, gopacket.Payload(payload)))
	return buf.Bytes()
}

// TestFragmentV6_TrailingWithoutFirstDropped verifies the IPv6 bypass is closed:
// a trailing fragment with no allowed first fragment is dropped.
func TestFragmentV6_TrailingWithoutFirstDropped(t *testing.T) {
	m := newFragmentTestManager(t)

	frag := trailingFragmentV6(t, 0xAABBCCDD, 100, false, 40)
	require.True(t, m.filterInbound(frag, len(frag)),
		"IPv6 trailing fragment without an allowed first fragment must be dropped")
}

// TestFragmentV6_AllowedFirstPassesTrailing verifies IPv6 fragments are
// evaluated like IPv4: an allowed first fragment lets its trailing fragments
// through.
func TestFragmentV6_AllowedFirstPassesTrailing(t *testing.T) {
	m := newFragmentTestManager(t)
	_, err := m.AddPeerFiltering(nil, net.ParseIP(fragTestSrcV6), fw.ProtocolUDP, nil,
		&fw.Port{Values: []uint16{8080}}, fw.ActionAccept, "")
	require.NoError(t, err)

	// First fragment: UDP header (8) + 32 data = 40 octets -> headerEnd = 5.
	first := firstFragmentUDPv6(t, 0xAABBCCDD, 8080, 32)
	require.False(t, m.filterInbound(first, len(first)),
		"allowed IPv6 first fragment should pass and be recorded")

	trailing := trailingFragmentV6(t, 0xAABBCCDD, 5, false, 24)
	require.False(t, m.filterInbound(trailing, len(trailing)),
		"trailing fragment of an allowed IPv6 datagram should pass")
}

// TestFragmentV6_AtomicNotCached verifies an IPv6 atomic fragment (fragment
// header with offset 0 and no More Fragments, a complete datagram per RFC 6946)
// is evaluated but not recorded, so a flood of allowed atomic fragments can't
// exhaust the verdict table.
func TestFragmentV6_AtomicNotCached(t *testing.T) {
	m := newFragmentTestManager(t)
	_, err := m.AddPeerFiltering(nil, net.ParseIP(fragTestSrcV6), fw.ProtocolUDP, nil,
		&fw.Port{Values: []uint16{8080}}, fw.ActionAccept, "")
	require.NoError(t, err)

	atomic := fragmentUDPv6(t, 0xA70301C, 8080, 16, false)
	require.False(t, m.filterInbound(atomic, len(atomic)),
		"allowed IPv6 atomic fragment should pass")

	m.fragments.mutex.Lock()
	n := len(m.fragments.entries)
	m.fragments.mutex.Unlock()
	require.Zero(t, n, "atomic fragment must not create a verdict entry")

	// A genuine fragmented datagram (More Fragments set) is still recorded.
	first := fragmentUDPv6(t, 0xBEEF, 8080, 32, true)
	require.False(t, m.filterInbound(first, len(first)))
	m.fragments.mutex.Lock()
	n = len(m.fragments.entries)
	m.fragments.mutex.Unlock()
	require.Equal(t, 1, n, "genuine first fragment must record a verdict")
}
