package conntrack

import (
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// These tests exercise cases where the TCP state machine currently advances
// on retransmitted or wrong-direction segments and tears the flow down
// prematurely. They are expected to fail until the direction checks are added.

func TestTCPCloseWaitRetransmittedPeerFIN(t *testing.T) {
	tracker := NewTCPTracker(DefaultTCPTimeout, logger, flowLogger)
	defer tracker.Close()

	srcIP := netip.MustParseAddr("100.64.0.1")
	dstIP := netip.MustParseAddr("100.64.0.2")
	srcPort := uint16(12345)
	dstPort := uint16(80)
	key := ConnKey{SrcIP: srcIP, DstIP: dstIP, SrcPort: srcPort, DstPort: dstPort}

	establishConnection(t, tracker, srcIP, dstIP, srcPort, dstPort)

	// Peer sends FIN -> CloseWait (our app has not yet closed).
	valid := tracker.IsValidInbound(dstIP, srcIP, dstPort, srcPort, TCPFin|TCPAck, 0)
	require.True(t, valid)
	conn := tracker.connections[key]
	require.Equal(t, TCPStateCloseWait, conn.GetState())

	// Peer retransmits their FIN (ACK may have been delayed). We have NOT
	// sent our FIN yet, so state must remain CloseWait.
	valid = tracker.IsValidInbound(dstIP, srcIP, dstPort, srcPort, TCPFin|TCPAck, 0)
	require.True(t, valid, "retransmitted peer FIN must still be accepted")
	require.Equal(t, TCPStateCloseWait, conn.GetState(),
		"retransmitted peer FIN must not advance CloseWait to LastAck")

	// Our app finally closes -> LastAck.
	tracker.TrackOutbound(srcIP, dstIP, srcPort, dstPort, TCPFin|TCPAck, 0)
	require.Equal(t, TCPStateLastAck, conn.GetState())

	// Peer ACK closes.
	valid = tracker.IsValidInbound(dstIP, srcIP, dstPort, srcPort, TCPAck, 0)
	require.True(t, valid)
	require.Equal(t, TCPStateClosed, conn.GetState())
}

func TestTCPFinWait2RetransmittedOwnFIN(t *testing.T) {
	tracker := NewTCPTracker(DefaultTCPTimeout, logger, flowLogger)
	defer tracker.Close()

	srcIP := netip.MustParseAddr("100.64.0.1")
	dstIP := netip.MustParseAddr("100.64.0.2")
	srcPort := uint16(12345)
	dstPort := uint16(80)
	key := ConnKey{SrcIP: srcIP, DstIP: dstIP, SrcPort: srcPort, DstPort: dstPort}

	establishConnection(t, tracker, srcIP, dstIP, srcPort, dstPort)

	// We initiate close.
	tracker.TrackOutbound(srcIP, dstIP, srcPort, dstPort, TCPFin|TCPAck, 0)
	valid := tracker.IsValidInbound(dstIP, srcIP, dstPort, srcPort, TCPAck, 0)
	require.True(t, valid)
	conn := tracker.connections[key]
	require.Equal(t, TCPStateFinWait2, conn.GetState())

	// Stray retransmit of our own FIN (same direction as originator) must
	// NOT advance FinWait2 to TimeWait; only the peer's FIN should.
	tracker.TrackOutbound(srcIP, dstIP, srcPort, dstPort, TCPFin|TCPAck, 0)
	require.Equal(t, TCPStateFinWait2, conn.GetState(),
		"own FIN retransmit must not advance FinWait2 to TimeWait")

	// Peer FIN -> TimeWait.
	valid = tracker.IsValidInbound(dstIP, srcIP, dstPort, srcPort, TCPFin|TCPAck, 0)
	require.True(t, valid)
	require.Equal(t, TCPStateTimeWait, conn.GetState())
}

func TestTCPLastAckDirectionCheck(t *testing.T) {
	tracker := NewTCPTracker(DefaultTCPTimeout, logger, flowLogger)
	defer tracker.Close()

	srcIP := netip.MustParseAddr("100.64.0.1")
	dstIP := netip.MustParseAddr("100.64.0.2")
	srcPort := uint16(12345)
	dstPort := uint16(80)
	key := ConnKey{SrcIP: srcIP, DstIP: dstIP, SrcPort: srcPort, DstPort: dstPort}

	establishConnection(t, tracker, srcIP, dstIP, srcPort, dstPort)

	// Drive to LastAck: peer FIN -> CloseWait, our FIN -> LastAck.
	require.True(t, tracker.IsValidInbound(dstIP, srcIP, dstPort, srcPort, TCPFin|TCPAck, 0))
	tracker.TrackOutbound(srcIP, dstIP, srcPort, dstPort, TCPFin|TCPAck, 0)
	conn := tracker.connections[key]
	require.Equal(t, TCPStateLastAck, conn.GetState())

	// Our own ACK retransmit (same direction as originator) must NOT close.
	tracker.TrackOutbound(srcIP, dstIP, srcPort, dstPort, TCPAck, 0)
	require.Equal(t, TCPStateLastAck, conn.GetState(),
		"own ACK retransmit in LastAck must not transition to Closed")

	// Peer's ACK -> Closed.
	require.True(t, tracker.IsValidInbound(dstIP, srcIP, dstPort, srcPort, TCPAck, 0))
	require.Equal(t, TCPStateClosed, conn.GetState())
}

func TestTCPFinWait1OwnAckDoesNotAdvance(t *testing.T) {
	tracker := NewTCPTracker(DefaultTCPTimeout, logger, flowLogger)
	defer tracker.Close()

	srcIP := netip.MustParseAddr("100.64.0.1")
	dstIP := netip.MustParseAddr("100.64.0.2")
	srcPort := uint16(12345)
	dstPort := uint16(80)
	key := ConnKey{SrcIP: srcIP, DstIP: dstIP, SrcPort: srcPort, DstPort: dstPort}

	establishConnection(t, tracker, srcIP, dstIP, srcPort, dstPort)

	tracker.TrackOutbound(srcIP, dstIP, srcPort, dstPort, TCPFin|TCPAck, 0)
	conn := tracker.connections[key]
	require.Equal(t, TCPStateFinWait1, conn.GetState())

	// Our own ACK retransmit (same direction as originator) must not advance.
	tracker.TrackOutbound(srcIP, dstIP, srcPort, dstPort, TCPAck, 0)
	require.Equal(t, TCPStateFinWait1, conn.GetState(),
		"own ACK in FinWait1 must not advance to FinWait2")
}

func TestTCPPerStateTeardownTimeouts(t *testing.T) {
	// Verify cleanup reaps entries in each teardown state at the configured
	// per-state timeout, not at the single handshake timeout.
	t.Setenv(EnvTCPFinWaitTimeout, "50ms")
	t.Setenv(EnvTCPCloseWaitTimeout, "80ms")
	t.Setenv(EnvTCPLastAckTimeout, "30ms")

	dstIP := netip.MustParseAddr("100.64.0.2")
	dstPort := uint16(80)

	// Drives a connection to the target state, forces its lastSeen well
	// beyond the configured timeout, runs cleanup, and asserts reaping.
	cases := []struct {
		name string
		// drive takes a fresh tracker and returns the conn key after
		// transitioning the flow into the intended teardown state.
		drive func(t *testing.T, tr *TCPTracker, srcIP netip.Addr, srcPort uint16) (ConnKey, TCPState)
	}{
		{
			name: "FinWait1",
			drive: func(t *testing.T, tr *TCPTracker, srcIP netip.Addr, srcPort uint16) (ConnKey, TCPState) {
				establishConnection(t, tr, srcIP, dstIP, srcPort, dstPort)
				tr.TrackOutbound(srcIP, dstIP, srcPort, dstPort, TCPFin|TCPAck, 0) // → FinWait1
				return ConnKey{SrcIP: srcIP, DstIP: dstIP, SrcPort: srcPort, DstPort: dstPort}, TCPStateFinWait1
			},
		},
		{
			name: "FinWait2",
			drive: func(t *testing.T, tr *TCPTracker, srcIP netip.Addr, srcPort uint16) (ConnKey, TCPState) {
				establishConnection(t, tr, srcIP, dstIP, srcPort, dstPort)
				tr.TrackOutbound(srcIP, dstIP, srcPort, dstPort, TCPFin|TCPAck, 0)              // FinWait1
				require.True(t, tr.IsValidInbound(dstIP, srcIP, dstPort, srcPort, TCPAck, 0))   // → FinWait2
				return ConnKey{SrcIP: srcIP, DstIP: dstIP, SrcPort: srcPort, DstPort: dstPort}, TCPStateFinWait2
			},
		},
		{
			name: "CloseWait",
			drive: func(t *testing.T, tr *TCPTracker, srcIP netip.Addr, srcPort uint16) (ConnKey, TCPState) {
				establishConnection(t, tr, srcIP, dstIP, srcPort, dstPort)
				require.True(t, tr.IsValidInbound(dstIP, srcIP, dstPort, srcPort, TCPFin|TCPAck, 0)) // → CloseWait
				return ConnKey{SrcIP: srcIP, DstIP: dstIP, SrcPort: srcPort, DstPort: dstPort}, TCPStateCloseWait
			},
		},
		{
			name: "LastAck",
			drive: func(t *testing.T, tr *TCPTracker, srcIP netip.Addr, srcPort uint16) (ConnKey, TCPState) {
				establishConnection(t, tr, srcIP, dstIP, srcPort, dstPort)
				require.True(t, tr.IsValidInbound(dstIP, srcIP, dstPort, srcPort, TCPFin|TCPAck, 0)) // CloseWait
				tr.TrackOutbound(srcIP, dstIP, srcPort, dstPort, TCPFin|TCPAck, 0)                   // → LastAck
				return ConnKey{SrcIP: srcIP, DstIP: dstIP, SrcPort: srcPort, DstPort: dstPort}, TCPStateLastAck
			},
		},
	}

	// Use a unique source port per subtest so nothing aliases.
	port := uint16(12345)
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tracker := NewTCPTracker(DefaultTCPTimeout, logger, flowLogger)
			defer tracker.Close()

			require.Equal(t, 50*time.Millisecond, tracker.finWaitTimeout)
			require.Equal(t, 80*time.Millisecond, tracker.closeWaitTimeout)
			require.Equal(t, 30*time.Millisecond, tracker.lastAckTimeout)

			srcIP := netip.MustParseAddr("100.64.0.1")
			port++
			key, wantState := c.drive(t, tracker, srcIP, port)
			conn := tracker.connections[key]
			require.NotNil(t, conn)
			require.Equal(t, wantState, conn.GetState())

			// Age the entry past the largest per-state timeout.
			conn.lastSeen.Store(time.Now().Add(-500 * time.Millisecond).UnixNano())
			tracker.cleanup()
			_, exists := tracker.connections[key]
			require.False(t, exists, "%s entry should be reaped", c.name)
		})
	}
}

func TestTCPEstablishedPSHACKInFinStates(t *testing.T) {
	// Verifies FIN|PSH|ACK and bare ACK keepalives are not dropped in FIN
	// teardown states, which some stacks emit during close.
	tracker := NewTCPTracker(DefaultTCPTimeout, logger, flowLogger)
	defer tracker.Close()

	srcIP := netip.MustParseAddr("100.64.0.1")
	dstIP := netip.MustParseAddr("100.64.0.2")
	srcPort := uint16(12345)
	dstPort := uint16(80)

	establishConnection(t, tracker, srcIP, dstIP, srcPort, dstPort)

	// Peer FIN -> CloseWait.
	require.True(t, tracker.IsValidInbound(dstIP, srcIP, dstPort, srcPort, TCPFin|TCPAck, 0))

	// Peer pushes trailing data + FIN|PSH|ACK (legal).
	require.True(t, tracker.IsValidInbound(dstIP, srcIP, dstPort, srcPort, TCPFin|TCPPush|TCPAck, 100),
		"FIN|PSH|ACK in CloseWait must be accepted")

	// Bare ACK keepalive from peer in CloseWait must be accepted.
	require.True(t, tracker.IsValidInbound(dstIP, srcIP, dstPort, srcPort, TCPAck, 0),
		"bare ACK in CloseWait must be accepted")
}
