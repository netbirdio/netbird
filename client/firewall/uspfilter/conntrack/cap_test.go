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

	// The most recently admitted flow must be present: eviction must make
	// room for new entries, not silently drop them.
	require.Contains(t, tracker.connections,
		ConnKey{SrcIP: src, DstIP: dst, SrcPort: uint16(10009), DstPort: 80},
		"newest TCP flow must be admitted after eviction")
	// A pre-cap flow must have been evicted to fit the last one.
	require.NotContains(t, tracker.connections,
		ConnKey{SrcIP: src, DstIP: dst, SrcPort: uint16(10000), DstPort: 80},
		"oldest TCP flow should have been evicted")
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

	// Both live pre-cap entries must survive: eviction must prefer the
	// tombstone, not just satisfy the size bound by dropping any entry.
	require.Contains(t, tracker.connections,
		ConnKey{SrcIP: src, DstIP: dst, SrcPort: uint16(20000), DstPort: 80},
		"live entries must not be evicted while a tombstone exists")
	require.Contains(t, tracker.connections,
		ConnKey{SrcIP: src, DstIP: dst, SrcPort: uint16(20002), DstPort: 80},
		"live entries must not be evicted while a tombstone exists")
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

	require.Contains(t, tracker.connections,
		ConnKey{SrcIP: src, DstIP: dst, SrcPort: uint16(30011), DstPort: 53},
		"newest UDP flow must be admitted after eviction")
	require.NotContains(t, tracker.connections,
		ConnKey{SrcIP: src, DstIP: dst, SrcPort: uint16(30000), DstPort: 53},
		"oldest UDP flow should have been evicted")
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

	require.Contains(t, tracker.connections,
		ICMPConnKey{SrcIP: src, DstIP: dst, ID: uint16(7)},
		"newest ICMP flow must be admitted after eviction")
	require.NotContains(t, tracker.connections,
		ICMPConnKey{SrcIP: src, DstIP: dst, ID: uint16(0)},
		"oldest ICMP flow should have been evicted")
}
