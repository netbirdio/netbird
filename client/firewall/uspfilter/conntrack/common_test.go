package conntrack

import (
	"net/netip"
	"testing"

	"github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/firewall/uspfilter/log"
	"github.com/netbirdio/netbird/client/internal/netflow"
)

var logger = log.NewFromLogrus(logrus.StandardLogger())
var flowLogger = netflow.NewManager(nil, []byte{}, nil).GetLogger()

func TestConnKey_String(t *testing.T) {
	tests := []struct {
		name   string
		key    ConnKey
		expect string
	}{
		{
			name: "IPv4",
			key: ConnKey{
				SrcIP:   netip.MustParseAddr("192.168.1.1"),
				DstIP:   netip.MustParseAddr("10.0.0.1"),
				SrcPort: 12345,
				DstPort: 80,
			},
			expect: "192.168.1.1:12345 → 10.0.0.1:80",
		},
		{
			name: "IPv6",
			key: ConnKey{
				SrcIP:   netip.MustParseAddr("2001:db8::1"),
				DstIP:   netip.MustParseAddr("2001:db8::2"),
				SrcPort: 54321,
				DstPort: 443,
			},
			expect: "[2001:db8::1]:54321 → [2001:db8::2]:443",
		},
		{
			name: "IPv4-mapped IPv6 unmaps",
			key: ConnKey{
				SrcIP:   netip.MustParseAddr("::ffff:10.0.0.1"),
				DstIP:   netip.MustParseAddr("::ffff:10.0.0.2"),
				SrcPort: 1000,
				DstPort: 2000,
			},
			expect: "10.0.0.1:1000 → 10.0.0.2:2000",
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

// Memory pressure tests
func BenchmarkMemoryPressure(b *testing.B) {
	b.Run("TCPHighLoad", func(b *testing.B) {
		tracker := NewTCPTracker(DefaultTCPTimeout, logger, flowLogger)
		defer tracker.Close()

		// Generate different IPs
		srcIPs := make([]netip.Addr, 100)
		dstIPs := make([]netip.Addr, 100)
		for i := 0; i < 100; i++ {
			srcIPs[i] = netip.AddrFrom4([4]byte{192, 168, byte(i / 256), byte(i % 256)})
			dstIPs[i] = netip.AddrFrom4([4]byte{10, 0, byte(i / 256), byte(i % 256)})
		}

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			srcIdx := i % len(srcIPs)
			dstIdx := (i + 1) % len(dstIPs)
			tracker.TrackOutbound(srcIPs[srcIdx], dstIPs[dstIdx], uint16(i%65535), 80, TCPSyn, 0)

			// Simulate some valid inbound packets
			if i%3 == 0 {
				tracker.IsValidInbound(dstIPs[dstIdx], srcIPs[srcIdx], 80, uint16(i%65535), TCPAck, 0)
			}
		}
	})

	b.Run("UDPHighLoad", func(b *testing.B) {
		tracker := NewUDPTracker(DefaultUDPTimeout, logger, flowLogger)
		defer tracker.Close()

		// Generate different IPs
		srcIPs := make([]netip.Addr, 100)
		dstIPs := make([]netip.Addr, 100)
		for i := 0; i < 100; i++ {
			srcIPs[i] = netip.AddrFrom4([4]byte{192, 168, byte(i / 256), byte(i % 256)})
			dstIPs[i] = netip.AddrFrom4([4]byte{10, 0, byte(i / 256), byte(i % 256)})
		}

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			srcIdx := i % len(srcIPs)
			dstIdx := (i + 1) % len(dstIPs)
			tracker.TrackOutbound(srcIPs[srcIdx], dstIPs[dstIdx], uint16(i%65535), 80, 0)

			// Simulate some valid inbound packets
			if i%3 == 0 {
				tracker.IsValidInbound(dstIPs[dstIdx], srcIPs[srcIdx], 80, uint16(i%65535), 0)
			}
		}
	})
}
