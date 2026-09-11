package uspfilter

import (
	"net/netip"
	"testing"

	"github.com/netbirdio/netbird/client/iface/wgaddr"
)

func setupManager(b *testing.B) *localIPManager {
	b.Helper()
	m := newLocalIPManager()
	mock := &IFaceMock{
		AddressFunc: func() wgaddr.Address {
			return wgaddr.Address{
				IP:      netip.MustParseAddr("100.64.0.1"),
				Network: netip.MustParsePrefix("100.64.0.0/16"),
				IPv6:    netip.MustParseAddr("fd00::1"),
				IPv6Net: netip.MustParsePrefix("fd00::/64"),
			}
		},
	}
	if err := m.UpdateLocalIPs(mock); err != nil {
		b.Fatalf("UpdateLocalIPs: %v", err)
	}
	return m
}

func BenchmarkIsLocalIP_v4_hit(b *testing.B) {
	m := setupManager(b)
	ip := netip.MustParseAddr("100.64.0.1")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.IsLocalIP(ip)
	}
}

func BenchmarkIsLocalIP_v4_miss(b *testing.B) {
	m := setupManager(b)
	ip := netip.MustParseAddr("8.8.8.8")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.IsLocalIP(ip)
	}
}

func BenchmarkIsLocalIP_v6_hit(b *testing.B) {
	m := setupManager(b)
	ip := netip.MustParseAddr("fd00::1")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.IsLocalIP(ip)
	}
}

func BenchmarkIsLocalIP_v6_miss(b *testing.B) {
	m := setupManager(b)
	ip := netip.MustParseAddr("2001:db8::1")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.IsLocalIP(ip)
	}
}

func BenchmarkIsLocalIP_loopback(b *testing.B) {
	m := setupManager(b)
	ip := netip.MustParseAddr("127.0.0.1")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.IsLocalIP(ip)
	}
}
