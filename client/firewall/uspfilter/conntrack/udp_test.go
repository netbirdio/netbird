package conntrack

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewUDPTracker(t *testing.T) {
	tests := []struct {
		name        string
		timeout     time.Duration
		wantTimeout time.Duration
	}{
		{
			name:        "with custom timeout",
			timeout:     1 * time.Minute,
			wantTimeout: 1 * time.Minute,
		},
		{
			name:        "with zero timeout uses default",
			timeout:     0,
			wantTimeout: DefaultUDPTimeout,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tracker := NewUDPTracker(tt.timeout, logger, flowLogger)
			assert.NotNil(t, tracker)
			assert.Equal(t, tt.wantTimeout, tracker.timeout)
			assert.NotNil(t, tracker.connections)
			assert.NotNil(t, tracker.cleanupTicker)
			assert.NotNil(t, tracker.tickerCancel)
		})
	}
}

func TestUDPTracker_TrackOutbound(t *testing.T) {
	tracker := NewUDPTracker(DefaultUDPTimeout, logger, flowLogger)
	defer tracker.Close()

	srcIP := netip.MustParseAddr("192.168.1.2")
	dstIP := netip.MustParseAddr("192.168.1.3")
	srcPort := uint16(12345)
	dstPort := uint16(53)

	tracker.TrackOutbound(srcIP, dstIP, srcPort, dstPort, 0)

	// Verify connection was tracked
	key := ConnKey{
		SrcIP:   srcIP,
		DstIP:   dstIP,
		SrcPort: srcPort,
		DstPort: dstPort,
	}
	conn, exists := tracker.connections[key]
	require.True(t, exists)
	assert.True(t, conn.SourceIP.Compare(srcIP) == 0)
	assert.True(t, conn.DestIP.Compare(dstIP) == 0)
	assert.Equal(t, srcPort, conn.SourcePort)
	assert.Equal(t, dstPort, conn.DestPort)
	assert.WithinDuration(t, time.Now(), conn.GetLastSeen(), 1*time.Second)
}

func TestUDPTracker_IsValidInbound(t *testing.T) {
	tracker := NewUDPTracker(1*time.Second, logger, flowLogger)
	defer tracker.Close()

	srcIP := netip.MustParseAddr("192.168.1.2")
	dstIP := netip.MustParseAddr("192.168.1.3")
	srcPort := uint16(12345)
	dstPort := uint16(53)

	// Track outbound connection
	tracker.TrackOutbound(srcIP, dstIP, srcPort, dstPort, 0)

	tests := []struct {
		name    string
		srcIP   netip.Addr
		dstIP   netip.Addr
		srcPort uint16
		dstPort uint16
		sleep   time.Duration
		want    bool
	}{
		{
			name:    "valid inbound response",
			srcIP:   dstIP,   // Original destination is now source
			dstIP:   srcIP,   // Original source is now destination
			srcPort: dstPort, // Original destination port is now source
			dstPort: srcPort, // Original source port is now destination
			sleep:   0,
			want:    true,
		},
		{
			name:    "invalid source IP",
			srcIP:   netip.MustParseAddr("192.168.1.4"),
			dstIP:   srcIP,
			srcPort: dstPort,
			dstPort: srcPort,
			sleep:   0,
			want:    false,
		},
		{
			name:    "invalid destination IP",
			srcIP:   dstIP,
			dstIP:   netip.MustParseAddr("192.168.1.4"),
			srcPort: dstPort,
			dstPort: srcPort,
			sleep:   0,
			want:    false,
		},
		{
			name:    "invalid source port",
			srcIP:   dstIP,
			dstIP:   srcIP,
			srcPort: 54321,
			dstPort: srcPort,
			sleep:   0,
			want:    false,
		},
		{
			name:    "invalid destination port",
			srcIP:   dstIP,
			dstIP:   srcIP,
			srcPort: dstPort,
			dstPort: 54321,
			sleep:   0,
			want:    false,
		},
		{
			name:    "expired connection",
			srcIP:   dstIP,
			dstIP:   srcIP,
			srcPort: dstPort,
			dstPort: srcPort,
			sleep:   2 * time.Second, // Longer than tracker timeout
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.sleep > 0 {
				time.Sleep(tt.sleep)
			}
			got := tracker.IsValidInbound(tt.srcIP, tt.dstIP, tt.srcPort, tt.dstPort, 0)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestUDPTracker_Cleanup(t *testing.T) {
	// Use shorter intervals for testing
	timeout := 50 * time.Millisecond
	cleanupInterval := 25 * time.Millisecond

	ctx, tickerCancel := context.WithCancel(context.Background())
	defer tickerCancel()

	// Create tracker with custom cleanup interval
	tracker := &UDPTracker{
		connections:   make(map[ConnKey]*UDPConnTrack),
		timeout:       timeout,
		cleanupTicker: time.NewTicker(cleanupInterval),
		tickerCancel:  tickerCancel,
		logger:        logger,
		flowLogger:    flowLogger,
	}

	// Start cleanup routine
	go tracker.cleanupRoutine(ctx)

	// Add some connections
	connections := []struct {
		srcIP   netip.Addr
		dstIP   netip.Addr
		srcPort uint16
		dstPort uint16
	}{
		{
			srcIP:   netip.MustParseAddr("192.168.1.2"),
			dstIP:   netip.MustParseAddr("192.168.1.3"),
			srcPort: 12345,
			dstPort: 53,
		},
		{
			srcIP:   netip.MustParseAddr("192.168.1.4"),
			dstIP:   netip.MustParseAddr("192.168.1.5"),
			srcPort: 12346,
			dstPort: 53,
		},
	}

	for _, conn := range connections {
		tracker.TrackOutbound(conn.srcIP, conn.dstIP, conn.srcPort, conn.dstPort, 0)
	}

	// Verify initial connections
	assert.Equal(t, 2, tracker.getConnectionsLen())

	// Wait for connection timeout and cleanup interval
	time.Sleep(timeout + 2*cleanupInterval)

	tracker.mutex.RLock()
	connCount := tracker.getConnectionsLen()
	tracker.mutex.RUnlock()

	// Verify connections were cleaned up
	assert.Equal(t, 0, connCount, "Expected all connections to be cleaned up")

	// Properly close the tracker
	tracker.Close()
}

func BenchmarkUDPTracker(b *testing.B) {
	b.Run("TrackOutbound", func(b *testing.B) {
		tracker := NewUDPTracker(DefaultUDPTimeout, logger, flowLogger)
		defer tracker.Close()

		srcIP := netip.MustParseAddr("192.168.1.1")
		dstIP := netip.MustParseAddr("192.168.1.2")

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			tracker.TrackOutbound(srcIP, dstIP, uint16(i%65535), 80, 0)
		}
	})

	b.Run("IsValidInbound", func(b *testing.B) {
		tracker := NewUDPTracker(DefaultUDPTimeout, logger, flowLogger)
		defer tracker.Close()

		srcIP := netip.MustParseAddr("192.168.1.1")
		dstIP := netip.MustParseAddr("192.168.1.2")

		// Pre-populate some connections
		for i := 0; i < 1000; i++ {
			tracker.TrackOutbound(srcIP, dstIP, uint16(i), 80, 0)
		}

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			tracker.IsValidInbound(dstIP, srcIP, 80, uint16(i%1000), 0)
		}
	})
}
