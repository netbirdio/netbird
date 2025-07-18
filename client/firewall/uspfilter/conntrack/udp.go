package conntrack

import (
	"context"
	"net/netip"
	"sync"
	"time"

	"github.com/google/uuid"

	nblog "github.com/netbirdio/netbird/client/firewall/uspfilter/log"
	nftypes "github.com/netbirdio/netbird/client/internal/netflow/types"
)

const (
	// DefaultUDPTimeout is the default timeout for UDP connections
	DefaultUDPTimeout = 30 * time.Second
	// UDPCleanupInterval is how often we check for stale connections
	UDPCleanupInterval = 15 * time.Second
)

// UDPConnTrack represents a UDP connection state
type UDPConnTrack struct {
	BaseConnTrack
	SourcePort uint16
	DestPort   uint16
}

// UDPTracker manages UDP connection states
type UDPTracker struct {
	logger        *nblog.Logger
	connections   map[ConnKey]*UDPConnTrack
	timeout       time.Duration
	cleanupTicker *time.Ticker
	tickerCancel  context.CancelFunc
	mutex         sync.RWMutex
	flowLogger    nftypes.FlowLogger
}

// NewUDPTracker creates a new UDP connection tracker
func NewUDPTracker(timeout time.Duration, logger *nblog.Logger, flowLogger nftypes.FlowLogger) *UDPTracker {
	if timeout == 0 {
		timeout = DefaultUDPTimeout
	}

	ctx, cancel := context.WithCancel(context.Background())

	tracker := &UDPTracker{
		logger:        logger,
		connections:   make(map[ConnKey]*UDPConnTrack),
		timeout:       timeout,
		cleanupTicker: time.NewTicker(UDPCleanupInterval),
		tickerCancel:  cancel,
		flowLogger:    flowLogger,
	}

	go tracker.cleanupRoutine(ctx)
	return tracker
}

// TrackOutbound records an outbound UDP connection
func (t *UDPTracker) TrackOutbound(srcIP netip.Addr, dstIP netip.Addr, srcPort uint16, dstPort uint16, size int) {
	if _, exists := t.updateIfExists(dstIP, srcIP, dstPort, srcPort, nftypes.Egress, size); !exists {
		// if (inverted direction) conn is not tracked, track this direction
		t.track(srcIP, dstIP, srcPort, dstPort, nftypes.Egress, nil, size)
	}
}

// TrackInbound records an inbound UDP connection
func (t *UDPTracker) TrackInbound(srcIP netip.Addr, dstIP netip.Addr, srcPort uint16, dstPort uint16, ruleID []byte, size int) {
	t.track(srcIP, dstIP, srcPort, dstPort, nftypes.Ingress, ruleID, size)
}

func (t *UDPTracker) updateIfExists(srcIP netip.Addr, dstIP netip.Addr, srcPort uint16, dstPort uint16, direction nftypes.Direction, size int) (ConnKey, bool) {
	key := ConnKey{
		SrcIP:   srcIP,
		DstIP:   dstIP,
		SrcPort: srcPort,
		DstPort: dstPort,
	}

	t.mutex.RLock()
	conn, exists := t.connections[key]
	t.mutex.RUnlock()

	if exists {
		conn.UpdateLastSeen()
		conn.UpdateCounters(direction, size)
		return key, true
	}

	return key, false
}

// track is the common implementation for tracking both inbound and outbound connections
func (t *UDPTracker) track(srcIP netip.Addr, dstIP netip.Addr, srcPort uint16, dstPort uint16, direction nftypes.Direction, ruleID []byte, size int) {
	key, exists := t.updateIfExists(srcIP, dstIP, srcPort, dstPort, direction, size)
	if exists {
		return
	}

	conn := &UDPConnTrack{
		BaseConnTrack: BaseConnTrack{
			FlowId:    uuid.New(),
			Direction: direction,
			SourceIP:  srcIP,
			DestIP:    dstIP,
		},
		SourcePort: srcPort,
		DestPort:   dstPort,
	}
	conn.UpdateLastSeen()
	conn.UpdateCounters(direction, size)

	t.mutex.Lock()
	t.connections[key] = conn
	t.mutex.Unlock()

	t.logger.Trace("New %s UDP connection: %s", direction, key)
	t.sendEvent(nftypes.TypeStart, conn, ruleID)
}

// IsValidInbound checks if an inbound packet matches a tracked connection
func (t *UDPTracker) IsValidInbound(srcIP netip.Addr, dstIP netip.Addr, srcPort uint16, dstPort uint16, size int) bool {
	key := ConnKey{
		SrcIP:   dstIP,
		DstIP:   srcIP,
		SrcPort: dstPort,
		DstPort: srcPort,
	}

	t.mutex.RLock()
	conn, exists := t.connections[key]
	t.mutex.RUnlock()

	if !exists || conn.timeoutExceeded(t.timeout) {
		return false
	}

	conn.UpdateLastSeen()
	conn.UpdateCounters(nftypes.Ingress, size)

	return true
}

// cleanupRoutine periodically removes stale connections
func (t *UDPTracker) cleanupRoutine(ctx context.Context) {
	defer t.cleanupTicker.Stop()

	for {
		select {
		case <-t.cleanupTicker.C:
			t.cleanup()
		case <-ctx.Done():
			return
		}
	}
}

func (t *UDPTracker) cleanup() {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	for key, conn := range t.connections {
		if conn.timeoutExceeded(t.timeout) {
			delete(t.connections, key)

			t.logger.Trace("Removed UDP connection %s (timeout) [in: %d Pkts/%d B, out: %d Pkts/%d B]",
				key, conn.PacketsRx.Load(), conn.BytesRx.Load(), conn.PacketsTx.Load(), conn.BytesTx.Load())
			t.sendEvent(nftypes.TypeEnd, conn, nil)
		}
	}
}

// Close stops the cleanup routine and releases resources
func (t *UDPTracker) Close() {
	t.tickerCancel()

	t.mutex.Lock()
	t.connections = nil
	t.mutex.Unlock()
}

// GetConnection safely retrieves a connection state
func (t *UDPTracker) GetConnection(srcIP netip.Addr, srcPort uint16, dstIP netip.Addr, dstPort uint16) (*UDPConnTrack, bool) {
	t.mutex.RLock()
	defer t.mutex.RUnlock()

	key := ConnKey{
		SrcIP:   srcIP,
		DstIP:   dstIP,
		SrcPort: srcPort,
		DstPort: dstPort,
	}
	conn, exists := t.connections[key]
	return conn, exists
}

// Timeout returns the configured timeout duration for the tracker
func (t *UDPTracker) Timeout() time.Duration {
	return t.timeout
}

func (t *UDPTracker) sendEvent(typ nftypes.Type, conn *UDPConnTrack, ruleID []byte) {
	t.flowLogger.StoreEvent(nftypes.EventFields{
		FlowID:     conn.FlowId,
		Type:       typ,
		RuleID:     ruleID,
		Direction:  conn.Direction,
		Protocol:   nftypes.UDP,
		SourceIP:   conn.SourceIP,
		DestIP:     conn.DestIP,
		SourcePort: conn.SourcePort,
		DestPort:   conn.DestPort,
		RxPackets:  conn.PacketsRx.Load(),
		TxPackets:  conn.PacketsTx.Load(),
		RxBytes:    conn.BytesRx.Load(),
		TxBytes:    conn.BytesTx.Load(),
	})
}

func (t *UDPTracker) getConnectionsLen() int {
	t.mutex.RLock()
	defer t.mutex.RUnlock()
	return len(t.connections)
}
