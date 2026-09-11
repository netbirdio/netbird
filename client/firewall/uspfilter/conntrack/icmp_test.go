package conntrack

import (
	"net/netip"
	"testing"
)

func TestICMPConnKey_String(t *testing.T) {
	tests := []struct {
		name   string
		key    ICMPConnKey
		expect string
	}{
		{
			name: "IPv4",
			key: ICMPConnKey{
				SrcIP: netip.MustParseAddr("192.168.1.1"),
				DstIP: netip.MustParseAddr("10.0.0.1"),
				ID:    1234,
			},
			expect: "192.168.1.1 → 10.0.0.1 (id 1234)",
		},
		{
			name: "IPv6",
			key: ICMPConnKey{
				SrcIP: netip.MustParseAddr("2001:db8::1"),
				DstIP: netip.MustParseAddr("2001:db8::2"),
				ID:    5678,
			},
			expect: "2001:db8::1 → 2001:db8::2 (id 5678)",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.key.String()
			if got != tc.expect {
				t.Errorf("got %q, want %q", got, tc.expect)
			}
		})
	}
}

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
