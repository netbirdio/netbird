package conntrack

import (
	"net/netip"
	"testing"

	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/require"
)

func TestTCPCapEvicts(t *testing.T) {
	t.Setenv(EnvTCPMaxEntries, "4")

	tracker := NewTCPTracker(DefaultTCPTimeout, logger, flowLogger)
	defer tracker.Close()
	require.Equal(t, 4, tracker.maxEntries)

	src := netip.MustParseAddr("100.64.0.1")
	dst := netip.MustParseAddr("100.64.0.2")

	for i := 0; i < 10; i++ {
		tracker.TrackOutbound(src, dst, uint16(10000+i), 80, TCPSyn, 0)
	}
	require.LessOrEqual(t, len(tracker.connections), 4,
		"TCP table must not exceed the configured cap")
	require.Greater(t, len(tracker.connections), 0,
		"some entries must remain after eviction")
}

func TestTCPCapPrefersTombstonedForEviction(t *testing.T) {
	t.Setenv(EnvTCPMaxEntries, "3")

	tracker := NewTCPTracker(DefaultTCPTimeout, logger, flowLogger)
	defer tracker.Close()

	src := netip.MustParseAddr("100.64.0.1")
	dst := netip.MustParseAddr("100.64.0.2")

	// Fill to cap with 3 live connections.
	for i := 0; i < 3; i++ {
		tracker.TrackOutbound(src, dst, uint16(20000+i), 80, TCPSyn, 0)
	}
	require.Len(t, tracker.connections, 3)

	// Tombstone one by sending RST through IsValidInbound.
	tombstonedKey := ConnKey{SrcIP: src, DstIP: dst, SrcPort: 20001, DstPort: 80}
	require.True(t, tracker.IsValidInbound(dst, src, 80, 20001, TCPRst|TCPAck, 0))
	require.True(t, tracker.connections[tombstonedKey].IsTombstone())

	// Another live connection forces eviction. The tombstone must go first.
	tracker.TrackOutbound(src, dst, uint16(29999), 80, TCPSyn, 0)

	_, tombstonedStillPresent := tracker.connections[tombstonedKey]
	require.False(t, tombstonedStillPresent,
		"tombstoned entry should be evicted before live entries")
	require.LessOrEqual(t, len(tracker.connections), 3)
}

func TestUDPCapEvicts(t *testing.T) {
	t.Setenv(EnvUDPMaxEntries, "5")

	tracker := NewUDPTracker(DefaultUDPTimeout, logger, flowLogger)
	defer tracker.Close()
	require.Equal(t, 5, tracker.maxEntries)

	src := netip.MustParseAddr("100.64.0.1")
	dst := netip.MustParseAddr("100.64.0.2")

	for i := 0; i < 12; i++ {
		tracker.TrackOutbound(src, dst, uint16(30000+i), 53, 0)
	}
	require.LessOrEqual(t, len(tracker.connections), 5)
	require.Greater(t, len(tracker.connections), 0)
}

func TestICMPCapEvicts(t *testing.T) {
	t.Setenv(EnvICMPMaxEntries, "3")

	tracker := NewICMPTracker(DefaultICMPTimeout, logger, flowLogger)
	defer tracker.Close()
	require.Equal(t, 3, tracker.maxEntries)

	src := netip.MustParseAddr("100.64.0.1")
	dst := netip.MustParseAddr("100.64.0.2")

	echoReq := layers.CreateICMPv4TypeCode(uint8(layers.ICMPv4TypeEchoRequest), 0)
	for i := 0; i < 8; i++ {
		tracker.TrackOutbound(src, dst, uint16(i), echoReq, nil, 64)
	}
	require.LessOrEqual(t, len(tracker.connections), 3)
	require.Greater(t, len(tracker.connections), 0)
}
