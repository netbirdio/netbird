package conntrack

import (
	"net"
	"sync"
	"time"
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
	connections   map[ConnKey]*UDPConnTrack
	timeout       time.Duration
	cleanupTicker *time.Ticker
	mutex         sync.RWMutex
	done          chan struct{}
	ipPool        *PreallocatedIPs
}

// NewUDPTracker creates a new UDP connection tracker
func NewUDPTracker(timeout time.Duration) *UDPTracker {
	if timeout == 0 {
		timeout = DefaultUDPTimeout
	}

	tracker := &UDPTracker{
		connections:   make(map[ConnKey]*UDPConnTrack),
		timeout:       timeout,
		cleanupTicker: time.NewTicker(UDPCleanupInterval),
		done:          make(chan struct{}),
		ipPool:        NewPreallocatedIPs(),
	}

	go tracker.cleanupRoutine()
	return tracker
}

// TrackOutbound records an outbound UDP connection
func (t *UDPTracker) TrackOutbound(srcIP net.IP, dstIP net.IP, srcPort uint16, dstPort uint16) {
	key := makeConnKey(srcIP, dstIP, srcPort, dstPort)
	now := time.Now().UnixNano()

	t.mutex.Lock()
	conn, exists := t.connections[key]
	if !exists {
		srcIPCopy := t.ipPool.Get()
		dstIPCopy := t.ipPool.Get()
		copyIP(srcIPCopy, srcIP)
		copyIP(dstIPCopy, dstIP)

		conn = &UDPConnTrack{
			BaseConnTrack: BaseConnTrack{
				SourceIP:   srcIPCopy,
				DestIP:     dstIPCopy,
				SourcePort: srcPort,
				DestPort:   dstPort,
			},
		}
		conn.lastSeen.Store(now)
		conn.established.Store(true)
		t.connections[key] = conn
	}
	t.mutex.Unlock()

	conn.lastSeen.Store(now)
}

// IsValidInbound checks if an inbound packet matches a tracked connection
func (t *UDPTracker) IsValidInbound(srcIP net.IP, dstIP net.IP, srcPort uint16, dstPort uint16) bool {
	key := makeConnKey(dstIP, srcIP, dstPort, srcPort)

	t.mutex.RLock()
	conn, exists := t.connections[key]
	t.mutex.RUnlock()

	if !exists {
		return false
	}

	if conn.timeoutExceeded(t.timeout) {
		return false
	}

	return conn.IsEstablished() &&
		ValidateIPs(MakeIPAddr(srcIP), conn.DestIP) &&
		ValidateIPs(MakeIPAddr(dstIP), conn.SourceIP) &&
		conn.DestPort == srcPort &&
		conn.SourcePort == dstPort
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
