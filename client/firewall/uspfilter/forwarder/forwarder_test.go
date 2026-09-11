package forwarder

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

const echoRequestSize = 8

func makeIPv6(t *testing.T, src, dst netip.Addr, nextHdr uint8, payload []byte) []byte {
	t.Helper()
	buf := make([]byte, header.IPv6MinimumSize+len(payload))
	ip := header.IPv6(buf)
	ip.Encode(&header.IPv6Fields{
		PayloadLength:     uint16(len(payload)),
		TransportProtocol: 0, // overwritten below to allow any value
		HopLimit:          64,
		SrcAddr:           tcpipAddrFromNetip(src),
		DstAddr:           tcpipAddrFromNetip(dst),
	})
	buf[6] = nextHdr
	copy(buf[header.IPv6MinimumSize:], payload)
	return buf
}

func tcpipAddrFromNetip(a netip.Addr) tcpip.Address {
	b := a.As16()
	return tcpip.AddrFrom16(b)
}

func echoRequest() []byte {
	icmp := make([]byte, echoRequestSize)
	icmp[0] = uint8(header.ICMPv6EchoRequest)
	return icmp
}

// extHdr builds a generic IPv6 extension header (HBH/Routing/DestOpts) of the
// given total octet length (must be multiple of 8, >= 8) with the given next
// header.
func extHdr(t *testing.T, next uint8, totalLen int) []byte {
	t.Helper()
	require.GreaterOrEqual(t, totalLen, 8)
	require.Equal(t, 0, totalLen%8)
	buf := make([]byte, totalLen)
	buf[0] = next
	buf[1] = uint8(totalLen/8 - 1)
	return buf
}

func TestParseICMPv6_NoExtensions(t *testing.T) {
	src := netip.MustParseAddr("fd00::1")
	dst := netip.MustParseAddr("fd00::2")
	pkt := makeIPv6(t, src, dst, uint8(header.ICMPv6ProtocolNumber), echoRequest())

	off, icmpLen, _, _, ok := parseICMPv6(pkt)
	require.True(t, ok)
	assert.Equal(t, header.IPv6MinimumSize, off)
	assert.Equal(t, echoRequestSize, icmpLen)
}

func TestParseICMPv6_SingleExtension(t *testing.T) {
	src := netip.MustParseAddr("fd00::1")
	dst := netip.MustParseAddr("fd00::2")
	hbh := extHdr(t, uint8(header.ICMPv6ProtocolNumber), 8)
	payload := append([]byte{}, hbh...)
	payload = append(payload, echoRequest()...)
	pkt := makeIPv6(t, src, dst, uint8(header.IPv6HopByHopOptionsExtHdrIdentifier), payload)

	off, icmpLen, _, _, ok := parseICMPv6(pkt)
	require.True(t, ok)
	assert.Equal(t, header.IPv6MinimumSize+8, off)
	assert.Equal(t, echoRequestSize, icmpLen)
}

func TestParseICMPv6_ChainedExtensions(t *testing.T) {
	src := netip.MustParseAddr("fd00::1")
	dst := netip.MustParseAddr("fd00::2")
	dest := extHdr(t, uint8(header.ICMPv6ProtocolNumber), 16)
	rt := extHdr(t, uint8(header.IPv6DestinationOptionsExtHdrIdentifier), 8)
	hbh := extHdr(t, uint8(header.IPv6RoutingExtHdrIdentifier), 8)
	payload := append(append(append([]byte{}, hbh...), rt...), dest...)
	payload = append(payload, echoRequest()...)
	pkt := makeIPv6(t, src, dst, uint8(header.IPv6HopByHopOptionsExtHdrIdentifier), payload)

	off, icmpLen, _, _, ok := parseICMPv6(pkt)
	require.True(t, ok)
	assert.Equal(t, header.IPv6MinimumSize+8+8+16, off)
	assert.Equal(t, echoRequestSize, icmpLen)
}

func TestParseICMPv6_FragmentDefersToGVisor(t *testing.T) {
	src := netip.MustParseAddr("fd00::1")
	dst := netip.MustParseAddr("fd00::2")
	pkt := makeIPv6(t, src, dst, uint8(header.IPv6FragmentExtHdrIdentifier), make([]byte, 8))

	_, _, _, _, ok := parseICMPv6(pkt)
	assert.False(t, ok)
}

func TestParseICMPv6_TruncatedExtension(t *testing.T) {
	src := netip.MustParseAddr("fd00::1")
	dst := netip.MustParseAddr("fd00::2")
	// Extension claims 16 bytes but only 8 remain after the IP header.
	hbh := []byte{uint8(header.ICMPv6ProtocolNumber), 1, 0, 0, 0, 0, 0, 0}
	pkt := makeIPv6(t, src, dst, uint8(header.IPv6HopByHopOptionsExtHdrIdentifier), hbh)

	_, _, _, _, ok := parseICMPv6(pkt)
	assert.False(t, ok)
}

func TestParseICMPv6_TruncatedICMPPayload(t *testing.T) {
	src := netip.MustParseAddr("fd00::1")
	dst := netip.MustParseAddr("fd00::2")
	// PayloadLength claims 8 bytes of ICMPv6 but the buffer only holds 4.
	pkt := makeIPv6(t, src, dst, uint8(header.ICMPv6ProtocolNumber), make([]byte, 8))
	pkt = pkt[:header.IPv6MinimumSize+4]

	_, _, _, _, ok := parseICMPv6(pkt)
	assert.False(t, ok)
}

func TestParseICMPv4_RejectsShortIHL(t *testing.T) {
	pkt := make([]byte, 28)
	pkt[0] = 0x44 // version 4, IHL 4 (16 bytes - below minimum)
	pkt[9] = uint8(header.ICMPv4ProtocolNumber)
	header.IPv4(pkt).SetTotalLength(28)

	_, _, _, _, ok := parseICMPv4(pkt)
	assert.False(t, ok)
}

func TestParseICMPv4_RejectsTotalLenOverBuffer(t *testing.T) {
	pkt := make([]byte, header.IPv4MinimumSize+header.ICMPv4MinimumSize)
	ip := header.IPv4(pkt)
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(len(pkt) + 16),
		Protocol:    uint8(header.ICMPv4ProtocolNumber),
		TTL:         64,
	})

	_, _, _, _, ok := parseICMPv4(pkt)
	assert.False(t, ok)
}

func TestParseICMPv4_RejectsFragment(t *testing.T) {
	pkt := make([]byte, header.IPv4MinimumSize+header.ICMPv4MinimumSize)
	ip := header.IPv4(pkt)
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(len(pkt)),
		Protocol:    uint8(header.ICMPv4ProtocolNumber),
		TTL:         64,
		Flags:       header.IPv4FlagMoreFragments,
	})

	_, _, _, _, ok := parseICMPv4(pkt)
	assert.False(t, ok)
}
