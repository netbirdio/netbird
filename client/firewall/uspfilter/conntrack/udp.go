package conntrack

import (
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
}

// UDPTracker manages UDP connection states
type UDPTracker struct {
	logger        *nblog.Logger
	connections   map[ConnKey]*UDPConnTrack
	timeout       time.Duration
	cleanupTicker *time.Ticker
	mutex         sync.RWMutex
	done          chan struct{}
	flowLogger    nftypes.FlowLogger
}

// NewUDPTracker creates a new UDP connection tracker
func NewUDPTracker(timeout time.Duration, logger *nblog.Logger, flowLogger nftypes.FlowLogger) *UDPTracker {
	if timeout == 0 {
		timeout = DefaultUDPTimeout
	}

	tracker := &UDPTracker{
		logger:        logger,
		connections:   make(map[ConnKey]*UDPConnTrack),
		timeout:       timeout,
		cleanupTicker: time.NewTicker(UDPCleanupInterval),
		done:          make(chan struct{}),
		flowLogger:    flowLogger,
	}

	go tracker.cleanupRoutine()
	return tracker
}

// TrackOutbound records an outbound UDP connection
func (t *UDPTracker) TrackOutbound(srcIP netip.Addr, dstIP netip.Addr, srcPort uint16, dstPort uint16) {
	if _, exists := t.updateIfExists(dstIP, srcIP, dstPort, srcPort); !exists {
		// if (inverted direction) conn is not tracked, track this direction
		t.track(srcIP, dstIP, srcPort, dstPort, nftypes.Egress)
	}
}

// TrackInbound records an inbound UDP connection
func (t *UDPTracker) TrackInbound(srcIP netip.Addr, dstIP netip.Addr, srcPort uint16, dstPort uint16) {
	t.track(srcIP, dstIP, srcPort, dstPort, nftypes.Ingress)
}

func (t *UDPTracker) updateIfExists(srcIP netip.Addr, dstIP netip.Addr, srcPort uint16, dstPort uint16) (ConnKey, bool) {
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
		return key, true
	}

	return key, false
}

// track is the common implementation for tracking both inbound and outbound connections
func (t *UDPTracker) track(srcIP netip.Addr, dstIP netip.Addr, srcPort uint16, dstPort uint16, direction nftypes.Direction) {
	key, exists := t.updateIfExists(srcIP, dstIP, srcPort, dstPort)
	if exists {
		return
	}

	conn := &UDPConnTrack{
		BaseConnTrack: BaseConnTrack{
			FlowId:     uuid.New(),
			Direction:  direction,
			SourceIP:   srcIP,
			DestIP:     dstIP,
			SourcePort: srcPort,
			DestPort:   dstPort,
		},
	}
	conn.UpdateLastSeen()

	t.mutex.Lock()
	t.connections[key] = conn
	t.mutex.Unlock()

	t.logger.Trace("New %s UDP connection: %s", direction, key)
	t.sendEvent(nftypes.TypeStart, conn)
}

// IsValidInbound checks if an inbound packet matches a tracked connection
func (t *UDPTracker) IsValidInbound(srcIP netip.Addr, dstIP netip.Addr, srcPort uint16, dstPort uint16) bool {
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

	return true
}

// cleanupRoutine periodically removes stale connections
func (t *UDPTracker) cleanupRoutine() {
	for {
		select {
		case <-t.cleanupTicker.C:
			t.cleanup()
		case <-t.done:
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

			t.logger.Trace("Removed UDP connection %s (timeout)", key)
			t.sendEvent(nftypes.TypeEnd, conn)
		}
	}
}

// Close stops the cleanup routine and releases resources
func (t *UDPTracker) Close() {
	t.cleanupTicker.Stop()
	close(t.done)

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

func (t *UDPTracker) sendEvent(typ nftypes.Type, conn *UDPConnTrack) {
	t.flowLogger.StoreEvent(nftypes.EventFields{
		FlowID:     conn.FlowId,
		Type:       typ,
		Direction:  conn.Direction,
		Protocol:   nftypes.UDP,
		SourceIP:   conn.SourceIP,
		DestIP:     conn.DestIP,
		SourcePort: conn.SourcePort,
		DestPort:   conn.DestPort,
	})
}
