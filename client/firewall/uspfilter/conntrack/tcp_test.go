package conntrack

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestTCPStateMachine(t *testing.T) {
	tracker := NewTCPTracker(DefaultTCPTimeout, nil)
	defer tracker.Close()

	srcIP := net.ParseIP("100.64.0.1")
	dstIP := net.ParseIP("100.64.0.2")
	srcPort := uint16(12345)
	dstPort := uint16(80)

	t.Run("Security Tests", func(t *testing.T) {
		tests := []struct {
			name     string
			flags    uint8
			wantDrop bool
			desc     string
		}{
			{
				name:     "Block unsolicited SYN-ACK",
				flags:    TCPSyn | TCPAck,
				wantDrop: true,
				desc:     "Should block SYN-ACK without prior SYN",
			},
			{
				name:     "Block invalid SYN-FIN",
				flags:    TCPSyn | TCPFin,
				wantDrop: true,
				desc:     "Should block invalid SYN-FIN combination",
			},
			{
				name:     "Block unsolicited RST",
				flags:    TCPRst,
				wantDrop: true,
				desc:     "Should block RST without connection",
			},
			{
				name:     "Block unsolicited ACK",
				flags:    TCPAck,
				wantDrop: true,
				desc:     "Should block ACK without connection",
			},
			{
				name:     "Block data without connection",
				flags:    TCPAck | TCPPush,
				wantDrop: true,
				desc:     "Should block data without established connection",
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				isValid := tracker.IsValidInbound(dstIP, srcIP, dstPort, srcPort, tt.flags, nil)
				require.Equal(t, !tt.wantDrop, isValid, tt.desc)
			})
		}
	})

	t.Run("Connection Flow Tests", func(t *testing.T) {
		tests := []struct {
			name string
			test func(*testing.T)
			desc string
		}{
			{
				name: "Normal Handshake",
				test: func(t *testing.T) {
					t.Helper()

					// Send initial SYN
					tracker.TrackOutbound(srcIP, dstIP, srcPort, dstPort, TCPSyn, nil)

					// Receive SYN-ACK
					valid := tracker.IsValidInbound(dstIP, srcIP, dstPort, srcPort, TCPSyn|TCPAck, nil)
					require.True(t, valid, "SYN-ACK should be allowed")

					// Send ACK
					tracker.TrackOutbound(srcIP, dstIP, srcPort, dstPort, TCPAck, nil)

					// Test data transfer
					valid = tracker.IsValidInbound(dstIP, srcIP, dstPort, srcPort, TCPPush|TCPAck, nil)
					require.True(t, valid, "Data should be allowed after handshake")
				},
			},
			{
				name: "Normal Close",
				test: func(t *testing.T) {
					t.Helper()

					// First establish connection
					establishConnection(t, tracker, srcIP, dstIP, srcPort, dstPort)

					// Send FIN
					tracker.TrackOutbound(srcIP, dstIP, srcPort, dstPort, TCPFin|TCPAck, nil)

					// Receive ACK for FIN
					valid := tracker.IsValidInbound(dstIP, srcIP, dstPort, srcPort, TCPAck, nil)
					require.True(t, valid, "ACK for FIN should be allowed")

					// Receive FIN from other side
					valid = tracker.IsValidInbound(dstIP, srcIP, dstPort, srcPort, TCPFin|TCPAck, nil)
					require.True(t, valid, "FIN should be allowed")

					// Send final ACK
					tracker.TrackOutbound(srcIP, dstIP, srcPort, dstPort, TCPAck, nil)
				},
			},
			{
				name: "RST During Connection",
				test: func(t *testing.T) {
					t.Helper()

					// First establish connection
					establishConnection(t, tracker, srcIP, dstIP, srcPort, dstPort)

					// Receive RST
					valid := tracker.IsValidInbound(dstIP, srcIP, dstPort, srcPort, TCPRst, nil)
					require.True(t, valid, "RST should be allowed for established connection")

					// Verify connection is closed
					valid = tracker.IsValidInbound(dstIP, srcIP, dstPort, srcPort, TCPPush|TCPAck, nil)
					t.Helper()

					require.False(t, valid, "Data should be blocked after RST")
				},
			},
			{
				name: "Simultaneous Close",
				test: func(t *testing.T) {
					t.Helper()

					// First establish connection
					establishConnection(t, tracker, srcIP, dstIP, srcPort, dstPort)

					// Both sides send FIN+ACK
					tracker.TrackOutbound(srcIP, dstIP, srcPort, dstPort, TCPFin|TCPAck, nil)
					valid := tracker.IsValidInbound(dstIP, srcIP, dstPort, srcPort, TCPFin|TCPAck, nil)
					require.True(t, valid, "Simultaneous FIN should be allowed")

					// Both sides send final ACK
					tracker.TrackOutbound(srcIP, dstIP, srcPort, dstPort, TCPAck, nil)
					valid = tracker.IsValidInbound(dstIP, srcIP, dstPort, srcPort, TCPAck, nil)
					require.True(t, valid, "Final ACKs should be allowed")
				},
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				t.Helper()

				tracker = NewTCPTracker(DefaultTCPTimeout, nil)
				tt.test(t)
			})
		}
	})
}

func TestRSTHandling(t *testing.T) {
	tracker := NewTCPTracker(DefaultTCPTimeout, nil)
	defer tracker.Close()

	srcIP := net.ParseIP("100.64.0.1")
	dstIP := net.ParseIP("100.64.0.2")
	srcPort := uint16(12345)
	dstPort := uint16(80)

	tests := []struct {
		name       string
		setupState func()
		sendRST    func()
		wantValid  bool
		desc       string
	}{
		{
			name: "RST in established",
			setupState: func() {
				// Establish connection first
				tracker.TrackOutbound(srcIP, dstIP, srcPort, dstPort, TCPSyn, nil)
				tracker.IsValidInbound(dstIP, srcIP, dstPort, srcPort, TCPSyn|TCPAck, nil)
				tracker.TrackOutbound(srcIP, dstIP, srcPort, dstPort, TCPAck, nil)
			},
			sendRST: func() {
				tracker.IsValidInbound(dstIP, srcIP, dstPort, srcPort, TCPRst, nil)
			},
			wantValid: true,
			desc:      "Should accept RST for established connection",
		},
		{
			name:       "RST without connection",
			setupState: func() {},
			sendRST: func() {
				tracker.IsValidInbound(dstIP, srcIP, dstPort, srcPort, TCPRst, nil)
			},
			wantValid: false,
			desc:      "Should reject RST without connection",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupState()
			tt.sendRST()

			// Verify connection state is as expected
			key := makeConnKey(srcIP, dstIP, srcPort, dstPort)
			conn := tracker.connections[key]
			if tt.wantValid {
				require.NotNil(t, conn)
				require.Equal(t, TCPStateClosed, conn.State)
				require.False(t, conn.IsEstablished())
			}
		})
	}
}

// Helper to establish a TCP connection
func establishConnection(t *testing.T, tracker *TCPTracker, srcIP, dstIP net.IP, srcPort, dstPort uint16) {
	t.Helper()

	tracker.TrackOutbound(srcIP, dstIP, srcPort, dstPort, TCPSyn, nil)

	valid := tracker.IsValidInbound(dstIP, srcIP, dstPort, srcPort, TCPSyn|TCPAck, nil)
	require.True(t, valid, "SYN-ACK should be allowed")

	tracker.TrackOutbound(srcIP, dstIP, srcPort, dstPort, TCPAck, nil)
}

func BenchmarkTCPTracker(b *testing.B) {
	b.Run("TrackOutbound", func(b *testing.B) {
		tracker := NewTCPTracker(DefaultTCPTimeout, nil)
		defer tracker.Close()

		srcIP := net.ParseIP("192.168.1.1")
		dstIP := net.ParseIP("192.168.1.2")

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			tracker.TrackOutbound(srcIP, dstIP, uint16(i%65535), 80, TCPSyn, nil)
		}
	})

	b.Run("IsValidInbound", func(b *testing.B) {
		tracker := NewTCPTracker(DefaultTCPTimeout, nil)
		defer tracker.Close()

		srcIP := net.ParseIP("192.168.1.1")
		dstIP := net.ParseIP("192.168.1.2")

		// Pre-populate some connections
		for i := 0; i < 1000; i++ {
			tracker.TrackOutbound(srcIP, dstIP, uint16(i), 80, TCPSyn, nil)
		}

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			tracker.IsValidInbound(dstIP, srcIP, 80, uint16(i%1000), TCPAck, nil)
		}
	})

	b.Run("ConcurrentAccess", func(b *testing.B) {
		tracker := NewTCPTracker(DefaultTCPTimeout, nil)
		defer tracker.Close()

		srcIP := net.ParseIP("192.168.1.1")
		dstIP := net.ParseIP("192.168.1.2")

		b.RunParallel(func(pb *testing.PB) {
			i := 0
			for pb.Next() {
				if i%2 == 0 {
					tracker.TrackOutbound(srcIP, dstIP, uint16(i%65535), 80, TCPSyn, nil)
				} else {
					tracker.IsValidInbound(dstIP, srcIP, 80, uint16(i%65535), TCPAck, nil)
				}
				i++
			}
		})
	})
}

// Benchmark connection cleanup
func BenchmarkCleanup(b *testing.B) {
	b.Run("TCPCleanup", func(b *testing.B) {
		tracker := NewTCPTracker(100*time.Millisecond, nil) // Short timeout for testing
		defer tracker.Close()

		// Pre-populate with expired connections
		srcIP := net.ParseIP("192.168.1.1")
		dstIP := net.ParseIP("192.168.1.2")
		for i := 0; i < 10000; i++ {
			tracker.TrackOutbound(srcIP, dstIP, uint16(i), 80, TCPSyn, nil)
		}

		// Wait for connections to expire
		time.Sleep(200 * time.Millisecond)

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			tracker.cleanup()
		}
	})
}