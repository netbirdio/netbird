package conntrack

import (
	"net"
	"sync"
	"time"

	"github.com/google/uuid"

	nblog "github.com/netbirdio/netbird/client/firewall/uspfilter/log"
	"github.com/netbirdio/netbird/client/internal/flowstore"
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
	ipPool        *PreallocatedIPs
	flowStore     flowstore.Store
}

// NewUDPTracker creates a new UDP connection tracker
func NewUDPTracker(timeout time.Duration, logger *nblog.Logger, flowStore flowstore.Store) *UDPTracker {
	if timeout == 0 {
		timeout = DefaultUDPTimeout
	}

	tracker := &UDPTracker{
		logger:        logger,
		connections:   make(map[ConnKey]*UDPConnTrack),
		timeout:       timeout,
		cleanupTicker: time.NewTicker(UDPCleanupInterval),
		done:          make(chan struct{}),
		ipPool:        NewPreallocatedIPs(),
		flowStore:     flowStore,
	}

	go tracker.cleanupRoutine()
	return tracker
}

// TrackOutbound records an outbound UDP connection
func (t *UDPTracker) TrackOutbound(srcIP net.IP, dstIP net.IP, srcPort uint16, dstPort uint16) {
	if _, exists := t.updateIfExists(dstIP, srcIP, dstPort, srcPort); !exists {
		// if (inverted direction) conn is not tracked, track this direction
		t.track(srcIP, dstIP, srcPort, dstPort, flowstore.Egress)
	}
}

// TrackInbound records an inbound UDP connection
func (t *UDPTracker) TrackInbound(srcIP net.IP, dstIP net.IP, srcPort uint16, dstPort uint16) {
	t.track(srcIP, dstIP, srcPort, dstPort, flowstore.Ingress)
}

func (t *UDPTracker) updateIfExists(srcIP net.IP, dstIP net.IP, srcPort uint16, dstPort uint16) (ConnKey, bool) {
	key := makeConnKey(srcIP, dstIP, srcPort, dstPort)

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
func (t *UDPTracker) track(srcIP net.IP, dstIP net.IP, srcPort uint16, dstPort uint16, direction flowstore.Direction) {
	key, exists := t.updateIfExists(srcIP, dstIP, srcPort, dstPort)
	if exists {
		return
	}

	srcIPCopy := t.ipPool.Get()
	dstIPCopy := t.ipPool.Get()
	copy(srcIPCopy, srcIP)
	copy(dstIPCopy, dstIP)

	conn := &UDPConnTrack{
		BaseConnTrack: BaseConnTrack{
			FlowId:     uuid.New(),
			Direction:  direction,
			SourceIP:   srcIPCopy,
			DestIP:     dstIPCopy,
			SourcePort: srcPort,
			DestPort:   dstPort,
		},
	}
	conn.UpdateLastSeen()

	t.mutex.Lock()
	t.connections[key] = conn
	t.mutex.Unlock()

	t.logger.Trace("New %s UDP connection: %s", direction, key)
	t.sendEvent(flowstore.TypeStart, key, conn)
}

// IsValidInbound checks if an inbound packet matches a tracked connection
func (t *UDPTracker) IsValidInbound(srcIP net.IP, dstIP net.IP, srcPort uint16, dstPort uint16) bool {
	key := makeConnKey(dstIP, srcIP, dstPort, srcPort)

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
			t.ipPool.Put(conn.SourceIP)
			t.ipPool.Put(conn.DestIP)
			delete(t.connections, key)

			t.logger.Trace("Removed UDP connection %s (timeout)", key)
			t.sendEvent(flowstore.TypeEnd, key, conn)
		}
	}
}

// Close stops the cleanup routine and releases resources
func (t *UDPTracker) Close() {
	t.cleanupTicker.Stop()
	close(t.done)

	t.mutex.Lock()
	for _, conn := range t.connections {
		t.ipPool.Put(conn.SourceIP)
		t.ipPool.Put(conn.DestIP)
	}
	t.connections = nil
	t.mutex.Unlock()
}

// GetConnection safely retrieves a connection state
func (t *UDPTracker) GetConnection(srcIP net.IP, srcPort uint16, dstIP net.IP, dstPort uint16) (*UDPConnTrack, bool) {
	t.mutex.RLock()
	defer t.mutex.RUnlock()

	key := makeConnKey(srcIP, dstIP, srcPort, dstPort)
	conn, exists := t.connections[key]
	if !exists {
		return nil, false
	}

	return conn, true
}

// Timeout returns the configured timeout duration for the tracker
func (t *UDPTracker) Timeout() time.Duration {
	return t.timeout
}

func (t *UDPTracker) sendEvent(typ flowstore.Type, key ConnKey, conn *UDPConnTrack) {
	t.flowStore.StoreEvent(flowstore.EventFields{
		FlowID:     conn.FlowId,
		Type:       typ,
		Direction:  conn.Direction,
		Protocol:   17,
		SourceIP:   key.SrcIP,
		DestIP:     key.DstIP,
		SourcePort: key.SrcPort,
		DestPort:   key.DstPort,
	})
}
