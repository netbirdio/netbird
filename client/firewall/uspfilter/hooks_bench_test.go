package uspfilter

import (
	"net"
	"net/netip"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/require"

	nbiface "github.com/netbirdio/netbird/client/iface"
	"github.com/netbirdio/netbird/client/iface/device"
)

func buildUDPPacket(b *testing.B, srcIP, dstIP string, srcPort, dstPort uint16) []byte {
	b.Helper()

	ipLayer := &layers.IPv4{
		Version:  4,
		TTL:      64,
		SrcIP:    net.ParseIP(srcIP),
		DstIP:    net.ParseIP(dstIP),
		Protocol: layers.IPProtocolUDP,
	}
	udpLayer := &layers.UDP{
		SrcPort: layers.UDPPort(srcPort),
		DstPort: layers.UDPPort(dstPort),
	}
	if err := udpLayer.SetNetworkLayerForChecksum(ipLayer); err != nil {
		b.Fatal(err)
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}
	if err := gopacket.SerializeLayers(buf, opts, ipLayer, udpLayer, gopacket.Payload([]byte("test"))); err != nil {
		b.Fatal(err)
	}
	return buf.Bytes()
}

func buildTCPPacket(b *testing.B, srcIP, dstIP string, srcPort, dstPort uint16) []byte {
	b.Helper()

	ipLayer := &layers.IPv4{
		Version:  4,
		TTL:      64,
		SrcIP:    net.ParseIP(srcIP),
		DstIP:    net.ParseIP(dstIP),
		Protocol: layers.IPProtocolTCP,
	}
	tcpLayer := &layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(dstPort),
		SYN:     true,
	}
	if err := tcpLayer.SetNetworkLayerForChecksum(ipLayer); err != nil {
		b.Fatal(err)
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}
	if err := gopacket.SerializeLayers(buf, opts, ipLayer, tcpLayer, gopacket.Payload([]byte("test"))); err != nil {
		b.Fatal(err)
	}
	return buf.Bytes()
}

func newBenchManager(b *testing.B) *Manager {
	b.Helper()
	m, err := Create(&IFaceMock{
		SetFilterFunc: func(device.PacketFilter) error { return nil },
	}, false, flowLogger, nbiface.DefaultMTU)
	require.NoError(b, err)
	return m
}

// BenchmarkHooksDrop_UDPMatch measures the cost of the UDP hook check when the
// packet matches the registered hook (the DNS interception fast path).
func BenchmarkHooksDrop_UDPMatch(b *testing.B) {
	m := newBenchManager(b)
	m.SetUDPPacketHook(netip.MustParseAddr("100.10.255.254"), 53, func([]byte) bool { return true })

	pkt := buildUDPPacket(b, "100.10.0.1", "100.10.255.254", 12345, 53)

	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		m.udpHooksDrop(53, netip.MustParseAddr("100.10.255.254"), pkt)
	}
}

// BenchmarkHooksDrop_UDPMiss measures the cost when no UDP hook matches
// (common case for non-DNS traffic).
func BenchmarkHooksDrop_UDPMiss(b *testing.B) {
	m := newBenchManager(b)
	m.SetUDPPacketHook(netip.MustParseAddr("100.10.255.254"), 53, func([]byte) bool { return true })

	pkt := buildUDPPacket(b, "100.10.0.1", "100.10.0.2", 12345, 8080)

	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		m.udpHooksDrop(8080, netip.MustParseAddr("100.10.0.2"), pkt)
	}
}

// BenchmarkHooksDrop_TCPMatch measures the TCP hook check when matching (DNS TCP).
func BenchmarkHooksDrop_TCPMatch(b *testing.B) {
	m := newBenchManager(b)
	m.SetTCPPacketHook(netip.MustParseAddr("100.10.255.254"), 53, func([]byte) bool { return true })

	pkt := buildTCPPacket(b, "100.10.0.1", "100.10.255.254", 12345, 53)

	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		m.tcpHooksDrop(53, netip.MustParseAddr("100.10.255.254"), pkt)
	}
}

// BenchmarkHooksDrop_TCPMiss measures TCP hook check for non-matching traffic.
func BenchmarkHooksDrop_TCPMiss(b *testing.B) {
	m := newBenchManager(b)
	m.SetTCPPacketHook(netip.MustParseAddr("100.10.255.254"), 53, func([]byte) bool { return true })

	pkt := buildTCPPacket(b, "100.10.0.1", "100.10.0.2", 12345, 443)

	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		m.tcpHooksDrop(443, netip.MustParseAddr("100.10.0.2"), pkt)
	}
}

// BenchmarkHooksDrop_NoHooks measures the cost when no hooks are registered
// (the baseline for all non-DNS traffic).
func BenchmarkHooksDrop_NoHooks(b *testing.B) {
	m := newBenchManager(b)

	pkt := buildUDPPacket(b, "100.10.0.1", "100.10.0.2", 12345, 8080)

	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		m.udpHooksDrop(8080, netip.MustParseAddr("100.10.0.2"), pkt)
		m.tcpHooksDrop(8080, netip.MustParseAddr("100.10.0.2"), pkt)
	}
}

// BenchmarkFilterOutbound_WithHooks benchmarks the full FilterOutbound path
// with both UDP and TCP hooks registered (the real-world DNS scenario).
func BenchmarkFilterOutbound_WithHooks(b *testing.B) {
	m := newBenchManager(b)
	m.SetUDPPacketHook(netip.MustParseAddr("100.10.255.254"), 53, func([]byte) bool { return true })
	m.SetTCPPacketHook(netip.MustParseAddr("100.10.255.254"), 53, func([]byte) bool { return true })

	udpDNS := buildUDPPacket(b, "100.10.0.1", "100.10.255.254", 12345, 53)
	tcpDNS := buildTCPPacket(b, "100.10.0.1", "100.10.255.254", 12345, 53)
	tcpHTTPS := buildTCPPacket(b, "100.10.0.1", "100.10.0.2", 12345, 443)

	b.Run("udp_dns_match", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			m.FilterOutbound(udpDNS, len(udpDNS))
		}
	})

	b.Run("tcp_dns_match", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			m.FilterOutbound(tcpDNS, len(tcpDNS))
		}
	})

	b.Run("tcp_https_miss", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			m.FilterOutbound(tcpHTTPS, len(tcpHTTPS))
		}
	})
}
