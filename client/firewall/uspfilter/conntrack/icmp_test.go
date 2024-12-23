package conntrack

import (
	"net"
	"testing"
)

func BenchmarkICMPTracker(b *testing.B) {
	b.Run("TrackOutbound", func(b *testing.B) {
		tracker := NewICMPTracker(DefaultICMPTimeout)
		defer tracker.Close()

		srcIP := net.ParseIP("192.168.1.1")
		dstIP := net.ParseIP("192.168.1.2")

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			tracker.TrackOutbound(srcIP, dstIP, uint16(i%65535), uint16(i%65535))
		}
	})

	b.Run("IsValidInbound", func(b *testing.B) {
		tracker := NewICMPTracker(DefaultICMPTimeout)
		defer tracker.Close()

		srcIP := net.ParseIP("192.168.1.1")
		dstIP := net.ParseIP("192.168.1.2")

		// Pre-populate some connections
		for i := 0; i < 1000; i++ {
			tracker.TrackOutbound(srcIP, dstIP, uint16(i), uint16(i))
		}

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			tracker.IsValidInbound(dstIP, srcIP, uint16(i%1000), uint16(i%1000), 0)
		}
	})
}
