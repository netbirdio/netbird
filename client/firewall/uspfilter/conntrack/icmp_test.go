package conntrack

import (
	"net/netip"
	"testing"
)

func BenchmarkICMPTracker(b *testing.B) {
	b.Run("TrackOutbound", func(b *testing.B) {
		tracker := NewICMPTracker(DefaultICMPTimeout, logger, flowLogger)
		defer tracker.Close()

		srcIP := netip.MustParseAddr("192.168.1.1")
		dstIP := netip.MustParseAddr("192.168.1.2")

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			tracker.TrackOutbound(srcIP, dstIP, uint16(i%65535), 0, []byte{}, 0)
		}
	})

	b.Run("IsValidInbound", func(b *testing.B) {
		tracker := NewICMPTracker(DefaultICMPTimeout, logger, flowLogger)
		defer tracker.Close()

		srcIP := netip.MustParseAddr("192.168.1.1")
		dstIP := netip.MustParseAddr("192.168.1.2")

		// Pre-populate some connections
		for i := 0; i < 1000; i++ {
			tracker.TrackOutbound(srcIP, dstIP, uint16(i), 0, []byte{}, 0)
		}

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			tracker.IsValidInbound(dstIP, srcIP, uint16(i%1000), 0, 0)
		}
	})
}
