package conntrack

import (
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTCPStateMachine(t *testing.T) {
	tracker := NewTCPTracker(DefaultTCPTimeout, logger, flowLogger)
	defer tracker.Close()

	srcIP := netip.MustParseAddr("100.64.0.1")
	dstIP := netip.MustParseAddr("100.64.0.2")
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
				isValid := tracker.IsValidInbound(dstIP, srcIP, dstPort, srcPort, tt.flags, 0)
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
					tracker.TrackOutbound(srcIP, dstIP, srcPort, dstPort, TCPSyn, 0)

					// Receive SYN-ACK
					valid := tracker.IsValidInbound(dstIP, srcIP, dstPort, srcPort, TCPSyn|TCPAck, 0)
					require.True(t, valid, "SYN-ACK should be allowed")

					// Send ACK
					tracker.TrackOutbound(srcIP, dstIP, srcPort, dstPort, TCPAck, 0)

					// Test data transfer
					valid = tracker.IsValidInbound(dstIP, srcIP, dstPort, srcPort, TCPPush|TCPAck, 0)
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
					tracker.TrackOutbound(srcIP, dstIP, srcPort, dstPort, TCPFin|TCPAck, 0)

					// Receive ACK for FIN
					valid := tracker.IsValidInbound(dstIP, srcIP, dstPort, srcPort, TCPAck, 0)
					require.True(t, valid, "ACK for FIN should be allowed")

					// Receive FIN from other side
					valid = tracker.IsValidInbound(dstIP, srcIP, dstPort, srcPort, TCPFin|TCPAck, 0)
					require.True(t, valid, "FIN should be allowed")

					// Send final ACK
					tracker.TrackOutbound(srcIP, dstIP, srcPort, dstPort, TCPAck, 0)
				},
			},
			{
				name: "RST During Connection",
				test: func(t *testing.T) {
					t.Helper()

					// First establish connection
					establishConnection(t, tracker, srcIP, dstIP, srcPort, dstPort)

					// Receive RST
					valid := tracker.IsValidInbound(dstIP, srcIP, dstPort, srcPort, TCPRst, 0)
					require.True(t, valid, "RST should be allowed for established connection")
				},
			},
			{
				name: "Simultaneous Close",
				test: func(t *testing.T) {
					t.Helper()

					// First establish connection
					establishConnection(t, tracker, srcIP, dstIP, srcPort, dstPort)

					// Both sides send FIN+ACK
					tracker.TrackOutbound(srcIP, dstIP, srcPort, dstPort, TCPFin|TCPAck, 0)
					valid := tracker.IsValidInbound(dstIP, srcIP, dstPort, srcPort, TCPFin|TCPAck, 0)
					require.True(t, valid, "Simultaneous FIN should be allowed")

					// Both sides send final ACK
					tracker.TrackOutbound(srcIP, dstIP, srcPort, dstPort, TCPAck, 0)
					valid = tracker.IsValidInbound(dstIP, srcIP, dstPort, srcPort, TCPAck, 0)
					require.True(t, valid, "Final ACKs should be allowed")
				},
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				t.Helper()

				tracker = NewTCPTracker(DefaultTCPTimeout, logger, flowLogger)
				tt.test(t)
			})
		}
	})
}

func TestRSTHandling(t *testing.T) {
	tracker := NewTCPTracker(DefaultTCPTimeout, logger, flowLogger)
	defer tracker.Close()

	srcIP := netip.MustParseAddr("100.64.0.1")
	dstIP := netip.MustParseAddr("100.64.0.2")
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
				tracker.TrackOutbound(srcIP, dstIP, srcPort, dstPort, TCPSyn, 0)
				tracker.IsValidInbound(dstIP, srcIP, dstPort, srcPort, TCPSyn|TCPAck, 0)
				tracker.TrackOutbound(srcIP, dstIP, srcPort, dstPort, TCPAck, 0)
			},
			sendRST: func() {
				tracker.IsValidInbound(dstIP, srcIP, dstPort, srcPort, TCPRst, 0)
			},
			wantValid: true,
			desc:      "Should accept RST for established connection",
		},
		{
			name:       "RST without connection",
			setupState: func() {},
			sendRST: func() {
				tracker.IsValidInbound(dstIP, srcIP, dstPort, srcPort, TCPRst, 0)
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
			key := ConnKey{
				SrcIP:   srcIP,
				DstIP:   dstIP,
				SrcPort: srcPort,
				DstPort: dstPort,
			}
			conn := tracker.connections[key]
			if tt.wantValid {
				require.NotNil(t, conn)
				require.Equal(t, TCPStateClosed, conn.GetState())
			}
		})
	}
}

func TestTCPRetransmissions(t *testing.T) {
	tracker := NewTCPTracker(DefaultTCPTimeout, logger, flowLogger)
	defer tracker.Close()

	srcIP := netip.MustParseAddr("100.64.0.1")
	dstIP := netip.MustParseAddr("100.64.0.2")
	srcPort := uint16(12345)
	dstPort := uint16(80)

	// Test SYN retransmission
	t.Run("SYN Retransmission", func(t *testing.T) {
		// Initial SYN
		tracker.TrackOutbound(srcIP, dstIP, srcPort, dstPort, TCPSyn, 0)

		// Retransmit SYN (should not affect the state machine)
		tracker.TrackOutbound(srcIP, dstIP, srcPort, dstPort, TCPSyn, 0)

		// Verify we're still in SYN-SENT state
		key := ConnKey{
			SrcIP:   srcIP,
			DstIP:   dstIP,
			SrcPort: srcPort,
			DstPort: dstPort,
		}
		conn := tracker.connections[key]
		require.NotNil(t, conn)
		require.Equal(t, TCPStateSynSent, conn.GetState())

		// Complete the handshake
		valid := tracker.IsValidInbound(dstIP, srcIP, dstPort, srcPort, TCPSyn|TCPAck, 0)
		require.True(t, valid)
		tracker.TrackOutbound(srcIP, dstIP, srcPort, dstPort, TCPAck, 0)

		// Verify we're in ESTABLISHED state
		require.Equal(t, TCPStateEstablished, conn.GetState())
	})

	// Test ACK retransmission in established state
	t.Run("ACK Retransmission", func(t *testing.T) {
		tracker = NewTCPTracker(DefaultTCPTimeout, logger, flowLogger)

		// Establish connection
		establishConnection(t, tracker, srcIP, dstIP, srcPort, dstPort)

		// Get connection object
		key := ConnKey{
			SrcIP:   srcIP,
			DstIP:   dstIP,
			SrcPort: srcPort,
			DstPort: dstPort,
		}
		conn := tracker.connections[key]
		require.NotNil(t, conn)
		require.Equal(t, TCPStateEstablished, conn.GetState())

		// Retransmit ACK
		tracker.TrackOutbound(srcIP, dstIP, srcPort, dstPort, TCPAck, 0)

		// State should remain ESTABLISHED
		require.Equal(t, TCPStateEstablished, conn.GetState())
	})

	// Test FIN retransmission
	t.Run("FIN Retransmission", func(t *testing.T) {
		tracker = NewTCPTracker(DefaultTCPTimeout, logger, flowLogger)

		// Establish connection
		establishConnection(t, tracker, srcIP, dstIP, srcPort, dstPort)

		// Get connection object
		key := ConnKey{
			SrcIP:   srcIP,
			DstIP:   dstIP,
			SrcPort: srcPort,
			DstPort: dstPort,
		}
		conn := tracker.connections[key]
		require.NotNil(t, conn)

		// Send FIN
		tracker.TrackOutbound(srcIP, dstIP, srcPort, dstPort, TCPFin|TCPAck, 0)
		require.Equal(t, TCPStateFinWait1, conn.GetState())

		// Retransmit FIN (should not change state)
		tracker.TrackOutbound(srcIP, dstIP, srcPort, dstPort, TCPFin|TCPAck, 0)
		require.Equal(t, TCPStateFinWait1, conn.GetState())

		// Receive ACK for FIN
		valid := tracker.IsValidInbound(dstIP, srcIP, dstPort, srcPort, TCPAck, 0)
		require.True(t, valid)
		require.Equal(t, TCPStateFinWait2, conn.GetState())
	})
}

func TestTCPDataTransfer(t *testing.T) {
	tracker := NewTCPTracker(DefaultTCPTimeout, logger, flowLogger)
	defer tracker.Close()

	srcIP := netip.MustParseAddr("100.64.0.1")
	dstIP := netip.MustParseAddr("100.64.0.2")
	srcPort := uint16(12345)
	dstPort := uint16(80)

	t.Run("Data Transfer", func(t *testing.T) {
		establishConnection(t, tracker, srcIP, dstIP, srcPort, dstPort)

		// Get connection object
		key := ConnKey{
			SrcIP:   srcIP,
			DstIP:   dstIP,
			SrcPort: srcPort,
			DstPort: dstPort,
		}
		conn := tracker.connections[key]
		require.NotNil(t, conn)

		// Send data
		tracker.TrackOutbound(srcIP, dstIP, srcPort, dstPort, TCPPush|TCPAck, 1000)

		// Receive ACK for data
		valid := tracker.IsValidInbound(dstIP, srcIP, dstPort, srcPort, TCPAck, 100)
		require.True(t, valid)

		// Receive data
		valid = tracker.IsValidInbound(dstIP, srcIP, dstPort, srcPort, TCPPush|TCPAck, 1500)
		require.True(t, valid)

		// Send ACK for received data
		tracker.TrackOutbound(srcIP, dstIP, srcPort, dstPort, TCPAck, 100)

		// State should remain ESTABLISHED
		require.Equal(t, TCPStateEstablished, conn.GetState())

		assert.Equal(t, uint64(1300), conn.BytesTx.Load())
		assert.Equal(t, uint64(1700), conn.BytesRx.Load())
		assert.Equal(t, uint64(4), conn.PacketsTx.Load())
		assert.Equal(t, uint64(3), conn.PacketsRx.Load())
	})
}

func TestTCPHalfClosedConnections(t *testing.T) {
	tracker := NewTCPTracker(DefaultTCPTimeout, logger, flowLogger)
	defer tracker.Close()

	srcIP := netip.MustParseAddr("100.64.0.1")
	dstIP := netip.MustParseAddr("100.64.0.2")
	srcPort := uint16(12345)
	dstPort := uint16(80)

	// Test half-closed connection: local end closes, remote end continues sending data
	t.Run("Local Close, Remote Data", func(t *testing.T) {
		establishConnection(t, tracker, srcIP, dstIP, srcPort, dstPort)

		key := ConnKey{
			SrcIP:   srcIP,
			DstIP:   dstIP,
			SrcPort: srcPort,
			DstPort: dstPort,
		}
		conn := tracker.connections[key]
		require.NotNil(t, conn)

		// Send FIN
		tracker.TrackOutbound(srcIP, dstIP, srcPort, dstPort, TCPFin|TCPAck, 0)
		require.Equal(t, TCPStateFinWait1, conn.GetState())

		// Receive ACK for FIN
		valid := tracker.IsValidInbound(dstIP, srcIP, dstPort, srcPort, TCPAck, 0)
		require.True(t, valid)
		require.Equal(t, TCPStateFinWait2, conn.GetState())

		// Remote end can still send data
		valid = tracker.IsValidInbound(dstIP, srcIP, dstPort, srcPort, TCPPush|TCPAck, 1000)
		require.True(t, valid)

		// We can still ACK their data
		tracker.TrackOutbound(srcIP, dstIP, srcPort, dstPort, TCPAck, 0)

		// Receive FIN from remote end
		valid = tracker.IsValidInbound(dstIP, srcIP, dstPort, srcPort, TCPFin|TCPAck, 0)
		require.True(t, valid)
		require.Equal(t, TCPStateTimeWait, conn.GetState())

		// Send final ACK
		tracker.TrackOutbound(srcIP, dstIP, srcPort, dstPort, TCPAck, 0)

		// State should remain TIME-WAIT (waiting for possible retransmissions)
		require.Equal(t, TCPStateTimeWait, conn.GetState())
	})

	// Test half-closed connection: remote end closes, local end continues sending data
	t.Run("Remote Close, Local Data", func(t *testing.T) {
		tracker = NewTCPTracker(DefaultTCPTimeout, logger, flowLogger)

		// Establish connection
		establishConnection(t, tracker, srcIP, dstIP, srcPort, dstPort)

		// Get connection object
		key := ConnKey{
			SrcIP:   srcIP,
			DstIP:   dstIP,
			SrcPort: srcPort,
			DstPort: dstPort,
		}
		conn := tracker.connections[key]
		require.NotNil(t, conn)

		// Receive FIN from remote
		valid := tracker.IsValidInbound(dstIP, srcIP, dstPort, srcPort, TCPFin|TCPAck, 0)
		require.True(t, valid)
		require.Equal(t, TCPStateCloseWait, conn.GetState())

		// We can still send data
		tracker.TrackOutbound(srcIP, dstIP, srcPort, dstPort, TCPPush|TCPAck, 1000)

		// Remote can still ACK our data
		valid = tracker.IsValidInbound(dstIP, srcIP, dstPort, srcPort, TCPAck, 0)
		require.True(t, valid)

		// Send our FIN
		tracker.TrackOutbound(srcIP, dstIP, srcPort, dstPort, TCPFin|TCPAck, 0)
		require.Equal(t, TCPStateLastAck, conn.GetState())

		// Receive final ACK
		valid = tracker.IsValidInbound(dstIP, srcIP, dstPort, srcPort, TCPAck, 0)
		require.True(t, valid)
		require.Equal(t, TCPStateClosed, conn.GetState())
	})
}

func TestTCPAbnormalSequences(t *testing.T) {
	tracker := NewTCPTracker(DefaultTCPTimeout, logger, flowLogger)
	defer tracker.Close()

	srcIP := netip.MustParseAddr("100.64.0.1")
	dstIP := netip.MustParseAddr("100.64.0.2")
	srcPort := uint16(12345)
	dstPort := uint16(80)

	// Test handling of unsolicited RST in various states
	t.Run("Unsolicited RST in SYN-SENT", func(t *testing.T) {
		// Send SYN
		tracker.TrackOutbound(srcIP, dstIP, srcPort, dstPort, TCPSyn, 0)

		// Receive unsolicited RST (without proper ACK)
		valid := tracker.IsValidInbound(dstIP, srcIP, dstPort, srcPort, TCPRst, 0)
		require.False(t, valid, "RST without proper ACK in SYN-SENT should be rejected")

		// Receive RST with proper ACK
		valid = tracker.IsValidInbound(dstIP, srcIP, dstPort, srcPort, TCPRst|TCPAck, 0)
		require.True(t, valid, "RST with proper ACK in SYN-SENT should be accepted")

		key := ConnKey{
			SrcIP:   srcIP,
			DstIP:   dstIP,
			SrcPort: srcPort,
			DstPort: dstPort,
		}
		conn := tracker.connections[key]
		require.Equal(t, TCPStateClosed, conn.GetState())
		require.True(t, conn.IsTombstone())
	})
}

func TestTCPTimeoutHandling(t *testing.T) {
	// Create tracker with a very short timeout for testing
	shortTimeout := 100 * time.Millisecond
	tracker := NewTCPTracker(shortTimeout, logger, flowLogger)
	defer tracker.Close()

	srcIP := netip.MustParseAddr("100.64.0.1")
	dstIP := netip.MustParseAddr("100.64.0.2")
	srcPort := uint16(12345)
	dstPort := uint16(80)

	t.Run("Connection Timeout", func(t *testing.T) {
		// Establish a connection
		establishConnection(t, tracker, srcIP, dstIP, srcPort, dstPort)

		// Get connection object
		key := ConnKey{
			SrcIP:   srcIP,
			DstIP:   dstIP,
			SrcPort: srcPort,
			DstPort: dstPort,
		}
		conn := tracker.connections[key]
		require.NotNil(t, conn)
		require.Equal(t, TCPStateEstablished, conn.GetState())

		// Wait for the connection to timeout
		time.Sleep(2 * shortTimeout)

		// Force cleanup
		tracker.cleanup()

		// Connection should be removed
		_, exists := tracker.connections[key]
		require.False(t, exists, "Connection should be removed after timeout")
	})

	t.Run("TIME_WAIT Timeout", func(t *testing.T) {
		tracker = NewTCPTracker(shortTimeout, logger, flowLogger)

		establishConnection(t, tracker, srcIP, dstIP, srcPort, dstPort)

		key := ConnKey{
			SrcIP:   srcIP,
			DstIP:   dstIP,
			SrcPort: srcPort,
			DstPort: dstPort,
		}
		conn := tracker.connections[key]
		require.NotNil(t, conn)

		// Complete the connection close to enter TIME_WAIT
		tracker.TrackOutbound(srcIP, dstIP, srcPort, dstPort, TCPFin|TCPAck, 0)
		tracker.IsValidInbound(dstIP, srcIP, dstPort, srcPort, TCPAck, 0)
		tracker.IsValidInbound(dstIP, srcIP, dstPort, srcPort, TCPFin|TCPAck, 0)
		tracker.TrackOutbound(srcIP, dstIP, srcPort, dstPort, TCPAck, 0)

		require.Equal(t, TCPStateTimeWait, conn.GetState())

		// TIME_WAIT should have its own timeout value (usually 2*MSL)
		// For the test, we're using a short timeout
		time.Sleep(2 * shortTimeout)

		tracker.cleanup()

		// Connection should be removed
		_, exists := tracker.connections[key]
		require.False(t, exists, "Connection should be removed after TIME_WAIT timeout")
	})
}

func TestSynFlood(t *testing.T) {
	tracker := NewTCPTracker(DefaultTCPTimeout, logger, flowLogger)
	defer tracker.Close()

	srcIP := netip.MustParseAddr("100.64.0.1")
	dstIP := netip.MustParseAddr("100.64.0.2")
	basePort := uint16(10000)
	dstPort := uint16(80)

	// Create a large number of SYN packets to simulate a SYN flood
	for i := uint16(0); i < 1000; i++ {
		tracker.TrackOutbound(srcIP, dstIP, basePort+i, dstPort, TCPSyn, 0)
	}

	// Check that we're tracking all connections
	require.Equal(t, 1000, len(tracker.connections))

	// Now simulate SYN timeout
	var oldConns int
	tracker.mutex.Lock()
	for _, conn := range tracker.connections {
		if conn.GetState() == TCPStateSynSent {
			// Make the connection appear old
			conn.lastSeen.Store(time.Now().Add(-TCPHandshakeTimeout - time.Second).UnixNano())
			oldConns++
		}
	}
	tracker.mutex.Unlock()
	require.Equal(t, 1000, oldConns)

	// Run cleanup
	tracker.cleanup()

	// Check that stale connections were cleaned up
	require.Equal(t, 0, len(tracker.connections))
}

func TestTCPInboundInitiatedConnection(t *testing.T) {
	tracker := NewTCPTracker(DefaultTCPTimeout, logger, flowLogger)
	defer tracker.Close()

	clientIP := netip.MustParseAddr("100.64.0.1")
	serverIP := netip.MustParseAddr("100.64.0.2")
	clientPort := uint16(12345)
	serverPort := uint16(80)

	// 1. Client sends SYN (we receive it as inbound)
	tracker.TrackInbound(clientIP, serverIP, clientPort, serverPort, TCPSyn, nil, 100)

	key := ConnKey{
		SrcIP:   clientIP,
		DstIP:   serverIP,
		SrcPort: clientPort,
		DstPort: serverPort,
	}

	tracker.mutex.RLock()
	conn := tracker.connections[key]
	tracker.mutex.RUnlock()

	require.NotNil(t, conn)
	require.Equal(t, TCPStateSynReceived, conn.GetState(), "Connection should be in SYN-RECEIVED state after inbound SYN")

	// 2. Server sends SYN-ACK response
	tracker.TrackOutbound(serverIP, clientIP, serverPort, clientPort, TCPSyn|TCPAck, 100)

	// 3. Client sends ACK to complete handshake
	tracker.TrackInbound(clientIP, serverIP, clientPort, serverPort, TCPAck, nil, 100)
	require.Equal(t, TCPStateEstablished, conn.GetState(), "Connection should be ESTABLISHED after handshake completion")

	// 4. Test data transfer
	// Client sends data
	tracker.TrackInbound(clientIP, serverIP, clientPort, serverPort, TCPPush|TCPAck, nil, 1000)

	// Server sends ACK for data
	tracker.TrackOutbound(serverIP, clientIP, serverPort, clientPort, TCPAck, 100)

	// Server sends data
	tracker.TrackOutbound(serverIP, clientIP, serverPort, clientPort, TCPPush|TCPAck, 1500)

	// Client sends ACK for data
	tracker.TrackInbound(clientIP, serverIP, clientPort, serverPort, TCPAck, nil, 100)

	// Verify state and counters
	require.Equal(t, TCPStateEstablished, conn.GetState())
	assert.Equal(t, uint64(1300), conn.BytesRx.Load()) // 3 packets * 100 + 1000 data
	assert.Equal(t, uint64(1700), conn.BytesTx.Load()) // 2 packets * 100 + 1500 data
	assert.Equal(t, uint64(4), conn.PacketsRx.Load())  // SYN, ACK, Data
	assert.Equal(t, uint64(3), conn.PacketsTx.Load())  // SYN-ACK, Data
}

// Helper to establish a TCP connection
func establishConnection(t *testing.T, tracker *TCPTracker, srcIP, dstIP netip.Addr, srcPort, dstPort uint16) {
	t.Helper()

	tracker.TrackOutbound(srcIP, dstIP, srcPort, dstPort, TCPSyn, 100)

	valid := tracker.IsValidInbound(dstIP, srcIP, dstPort, srcPort, TCPSyn|TCPAck, 100)
	require.True(t, valid, "SYN-ACK should be allowed")

	tracker.TrackOutbound(srcIP, dstIP, srcPort, dstPort, TCPAck, 100)
}
