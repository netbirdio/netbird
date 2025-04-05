package conntrack

import (
	"net/netip"
	"testing"
	"time"
)

func BenchmarkTCPTracker(b *testing.B) {
	b.Run("TrackOutbound", func(b *testing.B) {
		tracker := NewTCPTracker(DefaultTCPTimeout, logger, flowLogger)
		defer tracker.Close()

		srcIP := netip.MustParseAddr("192.168.1.1")
		dstIP := netip.MustParseAddr("192.168.1.2")

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			tracker.TrackOutbound(srcIP, dstIP, uint16(i%65535), 80, TCPSyn, 0)
		}
	})

	b.Run("IsValidInbound", func(b *testing.B) {
		tracker := NewTCPTracker(DefaultTCPTimeout, logger, flowLogger)
		defer tracker.Close()

		srcIP := netip.MustParseAddr("192.168.1.1")
		dstIP := netip.MustParseAddr("192.168.1.2")

		// Pre-populate some connections
		for i := 0; i < 1000; i++ {
			tracker.TrackOutbound(srcIP, dstIP, uint16(i), 80, TCPSyn, 0)
		}

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			tracker.IsValidInbound(dstIP, srcIP, 80, uint16(i%1000), TCPAck|TCPSyn, 0)
		}
	})

	b.Run("ConcurrentAccess", func(b *testing.B) {
		tracker := NewTCPTracker(DefaultTCPTimeout, logger, flowLogger)
		defer tracker.Close()

		srcIP := netip.MustParseAddr("192.168.1.1")
		dstIP := netip.MustParseAddr("192.168.1.2")

		b.RunParallel(func(pb *testing.PB) {
			i := 0
			for pb.Next() {
				if i%2 == 0 {
					tracker.TrackOutbound(srcIP, dstIP, uint16(i%65535), 80, TCPSyn, 0)
				} else {
					tracker.IsValidInbound(dstIP, srcIP, 80, uint16(i%65535), TCPAck|TCPSyn, 0)
				}
				i++
			}
		})
	})
}

// Benchmark connection cleanup
func BenchmarkCleanup(b *testing.B) {
	b.Run("TCPCleanup", func(b *testing.B) {
		tracker := NewTCPTracker(100*time.Millisecond, logger, flowLogger)
		defer tracker.Close()

		// Pre-populate with expired connections
		srcIP := netip.MustParseAddr("192.168.1.1")
		dstIP := netip.MustParseAddr("192.168.1.2")
		for i := 0; i < 10000; i++ {
			tracker.TrackOutbound(srcIP, dstIP, uint16(i), 80, TCPSyn, 0)
		}

		// Wait for connections to expire
		time.Sleep(200 * time.Millisecond)

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			tracker.cleanup()
		}
	})
}
