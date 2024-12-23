package conntrack

import (
	"net"
	"testing"
)

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
func BenchmarkAtomicOperations(b *testing.B) {
	conn := &BaseConnTrack{}
	b.Run("UpdateLastSeen", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			conn.UpdateLastSeen()
		}
	})

	b.Run("IsEstablished", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = conn.IsEstablished()
		}
	})

	b.Run("SetEstablished", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			conn.SetEstablished(i%2 == 0)
		}
	})

	b.Run("GetLastSeen", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = conn.GetLastSeen()
		}
	})
}

// Memory pressure tests
func BenchmarkMemoryPressure(b *testing.B) {
	b.Run("TCPHighLoad", func(b *testing.B) {
		tracker := NewTCPTracker(DefaultTCPTimeout)
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
		tracker := NewUDPTracker(DefaultUDPTimeout)
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
