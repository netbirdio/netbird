package conntrack

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
)

// RST hygiene tests: the tracker currently closes the flow on any RST that
// matches the 4-tuple, regardless of direction or state. These tests cover
// the minimum checks we want (no SEQ tracking).

func TestTCPRstInSynSentWrongDirection(t *testing.T) {
	tracker := NewTCPTracker(DefaultTCPTimeout, logger, flowLogger)
	defer tracker.Close()

	srcIP := netip.MustParseAddr("100.64.0.1")
	dstIP := netip.MustParseAddr("100.64.0.2")
	srcPort := uint16(12345)
	dstPort := uint16(80)
	key := ConnKey{SrcIP: srcIP, DstIP: dstIP, SrcPort: srcPort, DstPort: dstPort}

	tracker.TrackOutbound(srcIP, dstIP, srcPort, dstPort, TCPSyn, 0)
	conn := tracker.connections[key]
	require.Equal(t, TCPStateSynSent, conn.GetState())

	// A RST arriving in the same direction as the SYN (i.e. TrackOutbound)
	// cannot be a legitimate response. It must not close the connection.
	tracker.TrackOutbound(srcIP, dstIP, srcPort, dstPort, TCPRst|TCPAck, 0)
	require.Equal(t, TCPStateSynSent, conn.GetState(),
		"RST in same direction as SYN must not close connection")
	require.False(t, conn.IsTombstone())
}

func TestTCPRstInTimeWaitIgnored(t *testing.T) {
	tracker := NewTCPTracker(DefaultTCPTimeout, logger, flowLogger)
	defer tracker.Close()

	srcIP := netip.MustParseAddr("100.64.0.1")
	dstIP := netip.MustParseAddr("100.64.0.2")
	srcPort := uint16(12345)
	dstPort := uint16(80)
	key := ConnKey{SrcIP: srcIP, DstIP: dstIP, SrcPort: srcPort, DstPort: dstPort}

	// Drive to TIME-WAIT via active close.
	establishConnection(t, tracker, srcIP, dstIP, srcPort, dstPort)
	tracker.TrackOutbound(srcIP, dstIP, srcPort, dstPort, TCPFin|TCPAck, 0)
	require.True(t, tracker.IsValidInbound(dstIP, srcIP, dstPort, srcPort, TCPAck, 0))
	require.True(t, tracker.IsValidInbound(dstIP, srcIP, dstPort, srcPort, TCPFin|TCPAck, 0))
	tracker.TrackOutbound(srcIP, dstIP, srcPort, dstPort, TCPAck, 0)

	conn := tracker.connections[key]
	require.Equal(t, TCPStateTimeWait, conn.GetState())
	require.False(t, conn.IsTombstone(), "TIME-WAIT must not be tombstoned")

	// Late RST during TIME-WAIT must not tombstone the entry (TIME-WAIT
	// exists to absorb late segments).
	tracker.IsValidInbound(dstIP, srcIP, dstPort, srcPort, TCPRst, 0)
	require.Equal(t, TCPStateTimeWait, conn.GetState(),
		"RST in TIME-WAIT must not transition state")
	require.False(t, conn.IsTombstone(),
		"RST in TIME-WAIT must not tombstone the entry")
}

func TestTCPIllegalFlagCombos(t *testing.T) {
	tracker := NewTCPTracker(DefaultTCPTimeout, logger, flowLogger)
	defer tracker.Close()

	srcIP := netip.MustParseAddr("100.64.0.1")
	dstIP := netip.MustParseAddr("100.64.0.2")
	srcPort := uint16(12345)
	dstPort := uint16(80)
	key := ConnKey{SrcIP: srcIP, DstIP: dstIP, SrcPort: srcPort, DstPort: dstPort}

	establishConnection(t, tracker, srcIP, dstIP, srcPort, dstPort)
	conn := tracker.connections[key]

	// Illegal combos must be rejected and must not change state.
	combos := []struct {
		name  string
		flags uint8
	}{
		{"SYN+RST", TCPSyn | TCPRst},
		{"FIN+RST", TCPFin | TCPRst},
		{"SYN+FIN", TCPSyn | TCPFin},
		{"SYN+FIN+RST", TCPSyn | TCPFin | TCPRst},
	}

	for _, c := range combos {
		t.Run(c.name, func(t *testing.T) {
			before := conn.GetState()
			valid := tracker.IsValidInbound(dstIP, srcIP, dstPort, srcPort, c.flags, 0)
			require.False(t, valid, "illegal flag combo must be rejected: %s", c.name)
			require.Equal(t, before, conn.GetState(),
				"illegal flag combo must not change state")
			require.False(t, conn.IsTombstone())
		})
	}
}
