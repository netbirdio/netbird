package capture

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// buildIPv4Packet creates a minimal IPv4+TCP/UDP packet for filter testing.
func buildIPv4Packet(t *testing.T, srcIP, dstIP netip.Addr, proto uint8, srcPort, dstPort uint16) []byte {
	t.Helper()

	hdrLen := 20
	pkt := make([]byte, hdrLen+20)
	pkt[0] = 0x45
	pkt[9] = proto

	src := srcIP.As4()
	dst := dstIP.As4()
	copy(pkt[12:16], src[:])
	copy(pkt[16:20], dst[:])

	pkt[20] = byte(srcPort >> 8)
	pkt[21] = byte(srcPort)
	pkt[22] = byte(dstPort >> 8)
	pkt[23] = byte(dstPort)

	return pkt
}

// buildIPv6Packet creates a minimal IPv6+TCP/UDP packet for filter testing.
func buildIPv6Packet(t *testing.T, srcIP, dstIP netip.Addr, proto uint8, srcPort, dstPort uint16) []byte {
	t.Helper()

	pkt := make([]byte, 44) // 40 header + 4 ports
	pkt[0] = 0x60           // version 6
	pkt[6] = proto          // next header

	src := srcIP.As16()
	dst := dstIP.As16()
	copy(pkt[8:24], src[:])
	copy(pkt[24:40], dst[:])

	pkt[40] = byte(srcPort >> 8)
	pkt[41] = byte(srcPort)
	pkt[42] = byte(dstPort >> 8)
	pkt[43] = byte(dstPort)

	return pkt
}

// ---- Filter struct tests ----

func TestFilter_Empty(t *testing.T) {
	f := Filter{}
	assert.True(t, f.IsEmpty())
	assert.True(t, f.Match(buildIPv4Packet(t,
		netip.MustParseAddr("10.0.0.1"),
		netip.MustParseAddr("10.0.0.2"),
		protoTCP, 12345, 443)))
}

func TestFilter_Host(t *testing.T) {
	f := Filter{Host: netip.MustParseAddr("10.0.0.1")}
	assert.True(t, f.Match(buildIPv4Packet(t, netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.2"), protoTCP, 1234, 80)))
	assert.True(t, f.Match(buildIPv4Packet(t, netip.MustParseAddr("10.0.0.2"), netip.MustParseAddr("10.0.0.1"), protoTCP, 1234, 80)))
	assert.False(t, f.Match(buildIPv4Packet(t, netip.MustParseAddr("10.0.0.2"), netip.MustParseAddr("10.0.0.3"), protoTCP, 1234, 80)))
}

func TestFilter_InvalidPacket(t *testing.T) {
	f := Filter{Host: netip.MustParseAddr("10.0.0.1")}
	assert.False(t, f.Match(nil))
	assert.False(t, f.Match([]byte{}))
	assert.False(t, f.Match([]byte{0x00}))
}

func TestParsePacketInfo_IPv4(t *testing.T) {
	pkt := buildIPv4Packet(t, netip.MustParseAddr("192.168.1.1"), netip.MustParseAddr("10.0.0.1"), protoTCP, 54321, 80)
	info, ok := parsePacketInfo(pkt)
	require.True(t, ok)
	assert.Equal(t, uint8(4), info.family)
	assert.Equal(t, netip.MustParseAddr("192.168.1.1"), info.srcIP)
	assert.Equal(t, netip.MustParseAddr("10.0.0.1"), info.dstIP)
	assert.Equal(t, uint8(protoTCP), info.proto)
	assert.Equal(t, uint16(54321), info.srcPort)
	assert.Equal(t, uint16(80), info.dstPort)
}

func TestParsePacketInfo_IPv6(t *testing.T) {
	pkt := buildIPv6Packet(t, netip.MustParseAddr("fd00::1"), netip.MustParseAddr("fd00::2"), protoUDP, 1234, 53)
	info, ok := parsePacketInfo(pkt)
	require.True(t, ok)
	assert.Equal(t, uint8(6), info.family)
	assert.Equal(t, netip.MustParseAddr("fd00::1"), info.srcIP)
	assert.Equal(t, netip.MustParseAddr("fd00::2"), info.dstIP)
	assert.Equal(t, uint8(protoUDP), info.proto)
	assert.Equal(t, uint16(1234), info.srcPort)
	assert.Equal(t, uint16(53), info.dstPort)
}

// ---- ParseFilter expression tests ----

func matchV4(t *testing.T, m Matcher, srcIP, dstIP string, proto uint8, srcPort, dstPort uint16) bool {
	t.Helper()
	return m.Match(buildIPv4Packet(t, netip.MustParseAddr(srcIP), netip.MustParseAddr(dstIP), proto, srcPort, dstPort))
}

func matchV6(t *testing.T, m Matcher, srcIP, dstIP string, proto uint8, srcPort, dstPort uint16) bool {
	t.Helper()
	return m.Match(buildIPv6Packet(t, netip.MustParseAddr(srcIP), netip.MustParseAddr(dstIP), proto, srcPort, dstPort))
}

func TestParseFilter_Empty(t *testing.T) {
	m, err := ParseFilter("")
	require.NoError(t, err)
	assert.Nil(t, m, "empty expression should return nil matcher")
}

func TestParseFilter_Atoms(t *testing.T) {
	tests := []struct {
		expr  string
		match bool
	}{
		{"tcp", true},
		{"udp", false},
		{"host 10.0.0.1", true},
		{"host 10.0.0.99", false},
		{"port 443", true},
		{"port 80", false},
		{"src host 10.0.0.1", true},
		{"dst host 10.0.0.2", true},
		{"dst host 10.0.0.1", false},
		{"src port 12345", true},
		{"dst port 443", true},
		{"dst port 80", false},
		{"proto 6", true},
		{"proto 17", false},
	}

	pkt := buildIPv4Packet(t, netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.2"), protoTCP, 12345, 443)

	for _, tt := range tests {
		t.Run(tt.expr, func(t *testing.T) {
			m, err := ParseFilter(tt.expr)
			require.NoError(t, err)
			assert.Equal(t, tt.match, m.Match(pkt))
		})
	}
}

func TestParseFilter_And(t *testing.T) {
	m, err := ParseFilter("host 10.0.0.1 and tcp port 443")
	require.NoError(t, err)
	assert.True(t, matchV4(t, m, "10.0.0.1", "10.0.0.2", protoTCP, 55555, 443))
	assert.False(t, matchV4(t, m, "10.0.0.1", "10.0.0.2", protoUDP, 55555, 443), "wrong proto")
	assert.False(t, matchV4(t, m, "10.0.0.3", "10.0.0.2", protoTCP, 55555, 443), "wrong host")
	assert.False(t, matchV4(t, m, "10.0.0.1", "10.0.0.2", protoTCP, 55555, 80), "wrong port")
}

func TestParseFilter_ImplicitAnd(t *testing.T) {
	// "tcp port 443" = implicit AND between tcp and port 443
	m, err := ParseFilter("tcp port 443")
	require.NoError(t, err)
	assert.True(t, matchV4(t, m, "10.0.0.1", "10.0.0.2", protoTCP, 1, 443))
	assert.False(t, matchV4(t, m, "10.0.0.1", "10.0.0.2", protoUDP, 1, 443))
}

func TestParseFilter_Or(t *testing.T) {
	m, err := ParseFilter("port 80 or port 443")
	require.NoError(t, err)
	assert.True(t, matchV4(t, m, "1.2.3.4", "5.6.7.8", protoTCP, 1, 80))
	assert.True(t, matchV4(t, m, "1.2.3.4", "5.6.7.8", protoTCP, 1, 443))
	assert.False(t, matchV4(t, m, "1.2.3.4", "5.6.7.8", protoTCP, 1, 8080))
}

func TestParseFilter_Not(t *testing.T) {
	m, err := ParseFilter("not port 22")
	require.NoError(t, err)
	assert.True(t, matchV4(t, m, "10.0.0.1", "10.0.0.2", protoTCP, 1, 443))
	assert.False(t, matchV4(t, m, "10.0.0.1", "10.0.0.2", protoTCP, 1, 22))
	assert.False(t, matchV4(t, m, "10.0.0.1", "10.0.0.2", protoTCP, 22, 80))
}

func TestParseFilter_Parens(t *testing.T) {
	m, err := ParseFilter("(port 80 or port 443) and tcp")
	require.NoError(t, err)
	assert.True(t, matchV4(t, m, "1.2.3.4", "5.6.7.8", protoTCP, 1, 443))
	assert.False(t, matchV4(t, m, "1.2.3.4", "5.6.7.8", protoUDP, 1, 443), "wrong proto")
	assert.False(t, matchV4(t, m, "1.2.3.4", "5.6.7.8", protoTCP, 1, 8080), "wrong port")
}

func TestParseFilter_Family(t *testing.T) {
	mV4, err := ParseFilter("ip")
	require.NoError(t, err)
	assert.True(t, matchV4(t, mV4, "10.0.0.1", "10.0.0.2", protoTCP, 1, 80))
	assert.False(t, matchV6(t, mV4, "fd00::1", "fd00::2", protoTCP, 1, 80))

	mV6, err := ParseFilter("ip6")
	require.NoError(t, err)
	assert.False(t, matchV4(t, mV6, "10.0.0.1", "10.0.0.2", protoTCP, 1, 80))
	assert.True(t, matchV6(t, mV6, "fd00::1", "fd00::2", protoTCP, 1, 80))
}

func TestParseFilter_Net(t *testing.T) {
	m, err := ParseFilter("net 10.0.0.0/24")
	require.NoError(t, err)
	assert.True(t, matchV4(t, m, "10.0.0.1", "192.168.1.1", protoTCP, 1, 80), "src in net")
	assert.True(t, matchV4(t, m, "192.168.1.1", "10.0.0.200", protoTCP, 1, 80), "dst in net")
	assert.False(t, matchV4(t, m, "10.0.1.1", "192.168.1.1", protoTCP, 1, 80), "neither in net")
}

func TestParseFilter_SrcDstNet(t *testing.T) {
	m, err := ParseFilter("src net 10.0.0.0/8 and dst net 192.168.0.0/16")
	require.NoError(t, err)
	assert.True(t, matchV4(t, m, "10.1.2.3", "192.168.1.1", protoTCP, 1, 80))
	assert.False(t, matchV4(t, m, "192.168.1.1", "10.1.2.3", protoTCP, 1, 80), "reversed")
}

func TestParseFilter_Complex(t *testing.T) {
	// Real-world: capture HTTP(S) traffic to/from specific host, excluding SSH
	m, err := ParseFilter("host 10.0.0.1 and (port 80 or port 443) and not port 22")
	require.NoError(t, err)
	assert.True(t, matchV4(t, m, "10.0.0.1", "10.0.0.2", protoTCP, 55555, 443))
	assert.True(t, matchV4(t, m, "10.0.0.2", "10.0.0.1", protoTCP, 55555, 80))
	assert.False(t, matchV4(t, m, "10.0.0.1", "10.0.0.2", protoTCP, 22, 443), "port 22 excluded")
	assert.False(t, matchV4(t, m, "10.0.0.3", "10.0.0.2", protoTCP, 55555, 443), "wrong host")
}

func TestParseFilter_IPv6Combined(t *testing.T) {
	m, err := ParseFilter("ip6 and icmp6")
	require.NoError(t, err)
	assert.True(t, matchV6(t, m, "fd00::1", "fd00::2", protoICMPv6, 0, 0))
	assert.False(t, matchV4(t, m, "10.0.0.1", "10.0.0.2", protoICMP, 0, 0), "wrong family")
	assert.False(t, matchV6(t, m, "fd00::1", "fd00::2", protoTCP, 1, 80), "wrong proto")
}

func TestParseFilter_CaseInsensitive(t *testing.T) {
	m, err := ParseFilter("HOST 10.0.0.1 AND TCP PORT 443")
	require.NoError(t, err)
	assert.True(t, matchV4(t, m, "10.0.0.1", "10.0.0.2", protoTCP, 1, 443))
}

func TestParseFilter_Errors(t *testing.T) {
	bad := []string{
		"badkeyword",
		"host",
		"port abc",
		"port 99999",
		"net invalid",
		"(",
		"(port 80",
		"not",
		"src",
	}
	for _, expr := range bad {
		t.Run(expr, func(t *testing.T) {
			_, err := ParseFilter(expr)
			assert.Error(t, err, "should fail for %q", expr)
		})
	}
}
