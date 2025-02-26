package conntrack

import (
	"net"
	"net/netip"
	"testing"

	"github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/firewall/uspfilter/log"
)

var logger = log.NewFromLogrus(logrus.StandardLogger())

func BenchmarkIPOperations(b *testing.B) {
	b.Run("MakeIPAddr", func(b *testing.B) {
		ip := net.ParseIP("192.168.1.1")
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = MakeIPAddr(ip)
		}
	})

	b.Run("ValidateIPs", func(b *testing.B) {
		ip1 := net.ParseIP("192.168.1.1")
		ip2 := net.ParseIP("192.168.1.1")
		addr := MakeIPAddr(ip1)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = ValidateIPs(addr, ip2)
		}
	})

	b.Run("IPPool", func(b *testing.B) {
		pool := NewPreallocatedIPs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			ip := pool.Get()
			pool.Put(ip)
		}
	})

}

// Memory pressure tests
func BenchmarkMemoryPressure(b *testing.B) {
	b.Run("TCPHighLoad", func(b *testing.B) {
		tracker := NewTCPTracker(DefaultTCPTimeout, logger, nil)
		defer tracker.Close()

		// Generate different IPs
		srcIPs := make([]net.IP, 100)
		dstIPs := make([]net.IP, 100)
		for i := 0; i < 100; i++ {
			srcIPs[i] = net.IPv4(192, 168, byte(i/256), byte(i%256))
			dstIPs[i] = net.IPv4(10, 0, byte(i/256), byte(i%256))
		}

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			srcIdx := i % len(srcIPs)
			dstIdx := (i + 1) % len(dstIPs)
			tracker.TrackOutbound(srcIPs[srcIdx], dstIPs[dstIdx], uint16(i%65535), 80, TCPSyn)

			// Simulate some valid inbound packets
			if i%3 == 0 {
				tracker.IsValidInbound(dstIPs[dstIdx], srcIPs[srcIdx], 80, uint16(i%65535), TCPAck)
			}
		}
	})

	b.Run("UDPHighLoad", func(b *testing.B) {
		tracker := NewUDPTracker(DefaultUDPTimeout, logger, nil)
		defer tracker.Close()

		// Generate different IPs
		srcIPs := make([]net.IP, 100)
		dstIPs := make([]net.IP, 100)
		for i := 0; i < 100; i++ {
			srcIPs[i] = net.IPv4(192, 168, byte(i/256), byte(i%256))
			dstIPs[i] = net.IPv4(10, 0, byte(i/256), byte(i%256))
		}

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			srcIdx := i % len(srcIPs)
			dstIdx := (i + 1) % len(dstIPs)
			tracker.TrackOutbound(srcIPs[srcIdx], dstIPs[dstIdx], uint16(i%65535), 80)

			// Simulate some valid inbound packets
			if i%3 == 0 {
				tracker.IsValidInbound(dstIPs[dstIdx], srcIPs[srcIdx], 80, uint16(i%65535))
			}
		}
	})
}

// Benchmark for creating IP addresses
func BenchmarkMakeIP(b *testing.B) {
	ipv4Str := "192.168.1.1"
	ipv6Str := "2001:db8::1"

	ipv4 := net.ParseIP(ipv4Str)
	ipv6 := net.ParseIP(ipv6Str)

	b.Run("Custom-IPv4", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = MakeIPAddr(ipv4)
		}
	})

	b.Run("Netip-IPv4", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			addr, _ := netip.ParseAddr(ipv4Str)
			_ = addr
		}
	})

	b.Run("Netip-IPv4-FromNetIP", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			addr, _ := netip.AddrFromSlice(ipv4)
			_ = addr
		}
	})

	b.Run("Custom-IPv6", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = MakeIPAddr(ipv6)
		}
	})

	b.Run("Netip-IPv6", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			addr, _ := netip.ParseAddr(ipv6Str)
			_ = addr
		}
	})

	b.Run("Netip-IPv6-FromNetIP", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			addr, _ := netip.AddrFromSlice(ipv6)
			_ = addr
		}
	})
}

// Benchmark for comparing IP addresses
func BenchmarkCompareIP(b *testing.B) {
	ipv4_1 := net.ParseIP("192.168.1.1")
	ipv4_2 := net.ParseIP("192.168.1.2")
	ipv6_1 := net.ParseIP("2001:db8::1")
	ipv6_2 := net.ParseIP("2001:db8::2")

	customIPv4_1 := MakeIPAddr(ipv4_1)
	customIPv6_1 := MakeIPAddr(ipv6_1)

	netipIPv4_1, _ := netip.AddrFromSlice(ipv4_1)
	netipIPv4_2, _ := netip.AddrFromSlice(ipv4_2)
	netipIPv6_1, _ := netip.AddrFromSlice(ipv6_1)
	netipIPv6_2, _ := netip.AddrFromSlice(ipv6_2)

	b.Run("Custom-IPv4-Equal", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = ValidateIPs(customIPv4_1, ipv4_1)
		}
	})

	b.Run("Custom-IPv4-Different", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = ValidateIPs(customIPv4_1, ipv4_2)
		}
	})

	b.Run("Netip-IPv4-Equal", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = netipIPv4_1 == netipIPv4_1
		}
	})

	b.Run("Netip-IPv4-Different", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = netipIPv4_1 == netipIPv4_2
		}
	})

	b.Run("Custom-IPv6-Equal", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = ValidateIPs(customIPv6_1, ipv6_1)
		}
	})

	b.Run("Custom-IPv6-Different", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = ValidateIPs(customIPv6_1, ipv6_2)
		}
	})

	b.Run("Netip-IPv6-Equal", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = netipIPv6_1 == netipIPv6_1
		}
	})

	b.Run("Netip-IPv6-Different", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = netipIPv6_1 == netipIPv6_2
		}
	})
}

// Benchmark for key operations (creation and comparison)
func BenchmarkConnKey(b *testing.B) {
	type CustomConnKey struct {
		SrcIP   IPAddr
		DstIP   IPAddr
		SrcPort uint16
		DstPort uint16
	}

	type NetipConnKey struct {
		SrcIP   netip.Addr
		DstIP   netip.Addr
		SrcPort uint16
		DstPort uint16
	}

	ipv4_src := net.ParseIP("192.168.1.1")
	ipv4_dst := net.ParseIP("192.168.1.2")

	b.Run("Custom-CreateKey", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			key := CustomConnKey{
				SrcIP:   MakeIPAddr(ipv4_src),
				DstIP:   MakeIPAddr(ipv4_dst),
				SrcPort: 12345,
				DstPort: 80,
			}
			_ = key
		}
	})

	b.Run("Netip-CreateKey", func(b *testing.B) {
		srcAddr, _ := netip.AddrFromSlice(ipv4_src)
		dstAddr, _ := netip.AddrFromSlice(ipv4_dst)

		for i := 0; i < b.N; i++ {
			key := NetipConnKey{
				SrcIP:   srcAddr,
				DstIP:   dstAddr,
				SrcPort: 12345,
				DstPort: 80,
			}
			_ = key
		}
	})

	// Create keys for comparison
	customKey1 := CustomConnKey{
		SrcIP:   MakeIPAddr(ipv4_src),
		DstIP:   MakeIPAddr(ipv4_dst),
		SrcPort: 12345,
		DstPort: 80,
	}

	customKey2 := CustomConnKey{
		SrcIP:   MakeIPAddr(ipv4_src),
		DstIP:   MakeIPAddr(ipv4_dst),
		SrcPort: 12345,
		DstPort: 80,
	}

	srcAddr, _ := netip.AddrFromSlice(ipv4_src)
	dstAddr, _ := netip.AddrFromSlice(ipv4_dst)

	netipKey1 := NetipConnKey{
		SrcIP:   srcAddr,
		DstIP:   dstAddr,
		SrcPort: 12345,
		DstPort: 80,
	}

	netipKey2 := NetipConnKey{
		SrcIP:   srcAddr,
		DstIP:   dstAddr,
		SrcPort: 12345,
		DstPort: 80,
	}

	b.Run("Custom-CompareKey", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			equal := customKey1.SrcIP == customKey2.SrcIP &&
				customKey1.DstIP == customKey2.DstIP &&
				customKey1.SrcPort == customKey2.SrcPort &&
				customKey1.DstPort == customKey2.DstPort
			_ = equal
		}
	})

	b.Run("Netip-CompareKey", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			equal := netipKey1.SrcIP == netipKey2.SrcIP &&
				netipKey1.DstIP == netipKey2.DstIP &&
				netipKey1.SrcPort == netipKey2.SrcPort &&
				netipKey1.DstPort == netipKey2.DstPort
			_ = equal
		}
	})
}
