package bind

import (
	"net"
	"testing"
)

var (
	ipv4Addr = &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}
	ipv6Addr = &net.UDPAddr{IP: net.ParseIP("::1"), Port: 12345}
	payload  = make([]byte, 1200)
)

func BenchmarkWriteTo_DirectUDPConn(b *testing.B) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		b.Fatal(err)
	}
	defer conn.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = conn.WriteTo(payload, ipv4Addr)
	}
}

func BenchmarkWriteTo_DualStack_IPv4Only(b *testing.B) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		b.Fatal(err)
	}
	defer conn.Close()

	ds := NewDualStackPacketConn(conn, nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ds.WriteTo(payload, ipv4Addr)
	}
}

func BenchmarkWriteTo_DualStack_IPv6Only(b *testing.B) {
	conn, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6zero, Port: 0})
	if err != nil {
		b.Skipf("IPv6 not available: %v", err)
	}
	defer conn.Close()

	ds := NewDualStackPacketConn(nil, conn)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ds.WriteTo(payload, ipv6Addr)
	}
}

func BenchmarkWriteTo_DualStack_Both_IPv4Traffic(b *testing.B) {
	conn4, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		b.Fatal(err)
	}
	defer conn4.Close()

	conn6, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6zero, Port: 0})
	if err != nil {
		b.Skipf("IPv6 not available: %v", err)
	}
	defer conn6.Close()

	ds := NewDualStackPacketConn(conn4, conn6)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ds.WriteTo(payload, ipv4Addr)
	}
}

func BenchmarkWriteTo_DualStack_Both_IPv6Traffic(b *testing.B) {
	conn4, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		b.Fatal(err)
	}
	defer conn4.Close()

	conn6, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6zero, Port: 0})
	if err != nil {
		b.Skipf("IPv6 not available: %v", err)
	}
	defer conn6.Close()

	ds := NewDualStackPacketConn(conn4, conn6)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ds.WriteTo(payload, ipv6Addr)
	}
}

func BenchmarkWriteTo_DualStack_Both_MixedTraffic(b *testing.B) {
	conn4, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		b.Fatal(err)
	}
	defer conn4.Close()

	conn6, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6zero, Port: 0})
	if err != nil {
		b.Skipf("IPv6 not available: %v", err)
	}
	defer conn6.Close()

	ds := NewDualStackPacketConn(conn4, conn6)
	addrs := []net.Addr{ipv4Addr, ipv6Addr}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ds.WriteTo(payload, addrs[i&1])
	}
}
