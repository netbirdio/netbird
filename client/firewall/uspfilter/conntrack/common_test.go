package conntrack

import (
	"context"
	"net"
	"testing"

	"github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/firewall/uspfilter/log"
	"github.com/netbirdio/netbird/client/internal/netflow"
)

var logger = log.NewFromLogrus(logrus.StandardLogger())
var flowLogger = netflow.NewManager(context.Background(), []byte{}).GetLogger()

// Memory pressure tests
func BenchmarkMemoryPressure(b *testing.B) {
	b.Run("TCPHighLoad", func(b *testing.B) {
		tracker := NewTCPTracker(DefaultTCPTimeout, logger, flowLogger)
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
		tracker := NewUDPTracker(DefaultUDPTimeout, logger, flowLogger)
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
