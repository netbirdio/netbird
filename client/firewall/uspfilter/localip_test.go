package uspfilter

import (
	"net"
	"testing"
)

// MapImplementation is a version using map[string]struct{}
type MapImplementation struct {
	localIPs map[string]struct{}
}

func BenchmarkIPChecks(b *testing.B) {
	interfaces := make([]net.IP, 16)
	for i := range interfaces {
		interfaces[i] = net.IPv4(10, 0, byte(i>>8), byte(i))
	}

	// Setup bitmap version
	bitmapManager := &localIPManager{
		ipv4Bitmap: [1 << 16]uint32{},
	}
	for _, ip := range interfaces[:8] { // Add half of IPs
		bitmapManager.setBitmapBit(ip)
	}

	// Setup map version
	mapManager := &MapImplementation{
		localIPs: make(map[string]struct{}),
	}
	for _, ip := range interfaces[:8] {
		mapManager.localIPs[ip.String()] = struct{}{}
	}

	b.Run("Bitmap_Hit", func(b *testing.B) {
		ip := interfaces[4]
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			bitmapManager.checkBitmapBit(ip)
		}
	})

	b.Run("Bitmap_Miss", func(b *testing.B) {
		ip := interfaces[12]
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			bitmapManager.checkBitmapBit(ip)
		}
	})

	b.Run("Map_Hit", func(b *testing.B) {
		ip := interfaces[4]
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = mapManager.localIPs[ip.String()]
		}
	})

	b.Run("Map_Miss", func(b *testing.B) {
		ip := interfaces[12]
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = mapManager.localIPs[ip.String()]
		}
	})
}

func BenchmarkWGPosition(b *testing.B) {
	wgIP := net.ParseIP("10.10.0.1")

	// Create two managers - one checks WG IP first, other checks it last
	b.Run("WG_First", func(b *testing.B) {
		bm := &localIPManager{ipv4Bitmap: [1 << 16]uint32{}}
		bm.setBitmapBit(wgIP)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			bm.checkBitmapBit(wgIP)
		}
	})

	b.Run("WG_Last", func(b *testing.B) {
		bm := &localIPManager{ipv4Bitmap: [1 << 16]uint32{}}
		// Fill with other IPs first
		for i := 0; i < 15; i++ {
			bm.setBitmapBit(net.IPv4(10, 0, byte(i>>8), byte(i)))
		}
		bm.setBitmapBit(wgIP) // Add WG IP last
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			bm.checkBitmapBit(wgIP)
		}
	})
}
