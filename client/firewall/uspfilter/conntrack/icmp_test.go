package conntrack

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/require"
	// Assume these come from your internal packages.
)

func TestICMPTracker_TrackOutbound_NonEcho(t *testing.T) {
	// Use a non-echo type (for example, 3 = Destination Unreachable)
	nonEchoTypeCode := layers.CreateICMPv4TypeCode(3, 0)

	flowLogger.Enable()
	defer flowLogger.Disable()

	// Use a reasonable timeout.
	tracker := NewICMPTracker(30*time.Second, logger, flowLogger)
	defer tracker.Close()

	localIP := netip.MustParseAddr("192.0.2.1")
	remoteIP := netip.MustParseAddr("192.0.2.2")
	id := uint16(1000)
	size := 120

	// For outbound, the function first checks for an inverse connection.
	// Since none exists, TrackOutbound will call track().
	tracker.TrackOutbound(localIP, remoteIP, id, nonEchoTypeCode, size)

	// Since type != EchoRequest the connection should not be stored.
	require.Equal(t, 0, len(tracker.connections), "Non-echo request should not be tracked")
	// No events should be generated for non-echo requests.
	events := flowLogger.GetEvents()
	require.Equal(t, len(events), 0, "Non-echo request should not generate an event")
}

func TestICMPTracker_TrackOutbound_Echo(t *testing.T) {
	// Use EchoRequest type.
	echoTypeCode := layers.CreateICMPv4TypeCode(8, 0)

	flowLogger.Enable()
	defer flowLogger.Disable()

	tracker := NewICMPTracker(30*time.Second, logger, flowLogger)
	defer tracker.Close()

	localIP := netip.MustParseAddr("192.0.2.10")
	remoteIP := netip.MustParseAddr("192.0.2.20")
	id := uint16(2000)
	size := 150

	// This call should track the connection since it is an echo request.
	tracker.TrackOutbound(localIP, remoteIP, id, echoTypeCode, size)

	// The connection key is formed with (srcIP, dstIP, id).
	key := ICMPConnKey{SrcIP: localIP, DstIP: remoteIP, ID: id}
	tracker.mutex.RLock()
	_, exists := tracker.connections[key]
	tracker.mutex.RUnlock()
	require.True(t, exists, "Echo request should be tracked as a connection")

}

func TestICMPTracker_TrackInbound(t *testing.T) {
	// For inbound, we pass a rule ID.
	echoTypeCode := layers.CreateICMPv4TypeCode(8, 0)
	ruleID := []byte("rule-123")

	tracker := NewICMPTracker(30*time.Second, logger, flowLogger)
	defer tracker.Close()

	// Here srcIP is the remote host and dstIP is local.
	remoteIP := netip.MustParseAddr("203.0.113.5")
	localIP := netip.MustParseAddr("203.0.113.10")
	id := uint16(3000)
	size := 180

	tracker.TrackInbound(remoteIP, localIP, id, echoTypeCode, ruleID, size)

	// The connection key for inbound echo request is (srcIP, dstIP, id).
	key := ICMPConnKey{SrcIP: remoteIP, DstIP: localIP, ID: id}
	tracker.mutex.RLock()
	_, exists := tracker.connections[key]
	tracker.mutex.RUnlock()
	require.True(t, exists, "Inbound echo request should be tracked")
}

func TestICMPTracker_IsValidInbound(t *testing.T) {
	// For a valid echo reply, the tracker must have stored the echo request.
	echoRequest := layers.CreateICMPv4TypeCode(8, 0)

	// Use a slightly short timeout for testing expiry.
	tracker := NewICMPTracker(1*time.Second, logger, flowLogger)
	defer tracker.Close()

	localIP := netip.MustParseAddr("10.0.0.1")
	remoteIP := netip.MustParseAddr("10.0.0.2")
	id := uint16(4000)
	size := 100

	// Initiate the echo request.
	tracker.TrackOutbound(localIP, remoteIP, id, echoRequest, size)

	// For an echo reply, the src and dst are swapped relative to the request.
	valid := tracker.IsValidInbound(remoteIP, localIP, id, uint8(layers.ICMPv4TypeEchoReply), size)
	require.True(t, valid, "Valid echo reply should return true")

	// Test with a wrong ICMP type (not echo reply).
	invalid := tracker.IsValidInbound(remoteIP, localIP, id, 99, size)
	require.False(t, invalid, "Invalid echo type should return false")

	// Let the connection expire.
	time.Sleep(1100 * time.Millisecond)
	expired := tracker.IsValidInbound(remoteIP, localIP, id, uint8(layers.ICMPv4TypeEchoReply), size)
	require.False(t, expired, "Expired connection should return false")
}

func TestICMPTracker_cleanup(t *testing.T) {
	// Use a very short timeout to force cleanup.
	echoRequest := layers.CreateICMPv4TypeCode(8, 0)

	tracker := NewICMPTracker(50*time.Millisecond, logger, flowLogger)
	defer tracker.Close()

	localIP := netip.MustParseAddr("172.16.0.1")
	remoteIP := netip.MustParseAddr("172.16.0.2")
	id := uint16(5000)
	size := 100

	tracker.TrackOutbound(localIP, remoteIP, id, echoRequest, size)
	key := ICMPConnKey{SrcIP: localIP, DstIP: remoteIP, ID: id}

	// Confirm the connection is present.
	tracker.mutex.RLock()
	_, exists := tracker.connections[key]
	tracker.mutex.RUnlock()
	require.True(t, exists, "Connection should exist before cleanup")

	// Wait for the timeout to expire.
	time.Sleep(100 * time.Millisecond)

	// Manually trigger cleanup.
	tracker.cleanup()

	tracker.mutex.RLock()
	_, exists = tracker.connections[key]
	tracker.mutex.RUnlock()
	require.False(t, exists, "Expired connection should have been cleaned up")
}

func TestICMPTracker_Close(t *testing.T) {
	echoRequest := layers.CreateICMPv4TypeCode(8, 0)

	tracker := NewICMPTracker(30*time.Second, logger, flowLogger)

	// Add a connection.
	localIP := netip.MustParseAddr("198.51.100.1")
	remoteIP := netip.MustParseAddr("198.51.100.2")
	id := uint16(6000)
	size := 100
	tracker.TrackOutbound(localIP, remoteIP, id, echoRequest, size)

	// Close the tracker.
	tracker.Close()

	// After Close the connections map should be nil.
	tracker.mutex.RLock()
	require.Nil(t, tracker.connections, "Connections map should be nil after Close")
	tracker.mutex.RUnlock()

	// The cleanup goroutine should also be stopped. Canceling the ticker context should end cleanupRoutine.
	select {
	case <-time.After(50 * time.Millisecond):
		// no panic or deadlock indicates Close worked correctly.
	case <-context.Background().Done():
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
			tracker.TrackOutbound(srcIP, dstIP, uint16(i%65535), 0, 0)
		}
	})

	b.Run("IsValidInbound", func(b *testing.B) {
		tracker := NewICMPTracker(DefaultICMPTimeout, logger, flowLogger)
		defer tracker.Close()

		srcIP := netip.MustParseAddr("192.168.1.1")
		dstIP := netip.MustParseAddr("192.168.1.2")

		// Pre-populate some connections
		for i := 0; i < 1000; i++ {
			tracker.TrackOutbound(srcIP, dstIP, uint16(i), 0, 0)
		}

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			tracker.IsValidInbound(dstIP, srcIP, uint16(i%1000), 0, 0)
		}
	})
}
