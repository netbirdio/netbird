package conntrack

import (
	"net"
	"sync"
	"time"
)

const (
	// DefaultTimeout is the default timeout for UDP connections
	DefaultTimeout = 30 * time.Second
	// CleanupInterval is how often we check for stale connections
	CleanupInterval = 15 * time.Second
)

type ConnKey struct {
	// Supports both IPv4 and IPv6
	SrcIP   [16]byte
	DstIP   [16]byte
	SrcPort uint16
	DstPort uint16
}

// UDPConnTrack represents a UDP connection state
type UDPConnTrack struct {
	SourceIP    net.IP
	DestIP      net.IP
	SourcePort  uint16
	DestPort    uint16
	LastSeen    time.Time
	established bool
}

// UDPTracker manages UDP connection states
type UDPTracker struct {
	connections   map[ConnKey]*UDPConnTrack
	timeout       time.Duration
	cleanupTicker *time.Ticker
	mutex         sync.RWMutex
	done          chan struct{}
}

// NewUDPTracker creates a new UDP connection tracker
func NewUDPTracker(timeout time.Duration) *UDPTracker {
	if timeout == 0 {
		timeout = DefaultTimeout
	}

	tracker := &UDPTracker{
		connections:   make(map[ConnKey]*UDPConnTrack),
		timeout:       timeout,
		cleanupTicker: time.NewTicker(CleanupInterval),
		done:          make(chan struct{}),
	}

	go tracker.cleanupRoutine()
	return tracker
}

// TrackOutbound records an outbound UDP connection
func (t *UDPTracker) TrackOutbound(srcIP net.IP, dstIP net.IP, srcPort uint16, dstPort uint16) {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	key := makeKey(srcIP, srcPort, dstIP, dstPort)

	t.connections[key] = &UDPConnTrack{
		SourceIP:    srcIP,
		DestIP:      dstIP,
		SourcePort:  srcPort,
		DestPort:    dstPort,
		LastSeen:    time.Now(),
		established: true,
	}
}

// IsValidInbound checks if an inbound packet matches a tracked connection
func (t *UDPTracker) IsValidInbound(srcIP net.IP, dstIP net.IP, srcPort uint16, dstPort uint16) bool {
	t.mutex.RLock()
	defer t.mutex.RUnlock()

	key := makeKey(dstIP, dstPort, srcIP, srcPort)
	conn, exists := t.connections[key]
	if !exists {
		return false
	}

	// Check if connection is still valid
	if time.Since(conn.LastSeen) > t.timeout {
		return false
	}

	if conn.established &&
		conn.DestIP.Equal(srcIP) &&
		conn.SourceIP.Equal(dstIP) &&
		conn.DestPort == srcPort &&
		conn.SourcePort == dstPort {

		conn.LastSeen = time.Now()

		return true
	}

	return false
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

	now := time.Now()
	for key, conn := range t.connections {
		if now.Sub(conn.LastSeen) > t.timeout {
			delete(t.connections, key)
		}
	}
}

// Close stops the cleanup routine and releases resources
func (t *UDPTracker) Close() {
	t.cleanupTicker.Stop()
	close(t.done)
}

// GetConnection safely retrieves a connection state
func (t *UDPTracker) GetConnection(srcIP net.IP, srcPort uint16, dstIP net.IP, dstPort uint16) (*UDPConnTrack, bool) {
	t.mutex.RLock()
	defer t.mutex.RUnlock()

	key := makeKey(srcIP, srcPort, dstIP, dstPort)
	conn, exists := t.connections[key]
	if !exists {
		return nil, false
	}

	// Return a copy to prevent potential race conditions
	connCopy := &UDPConnTrack{
		SourceIP:    append(net.IP{}, conn.SourceIP...),
		DestIP:      append(net.IP{}, conn.DestIP...),
		SourcePort:  conn.SourcePort,
		DestPort:    conn.DestPort,
		LastSeen:    conn.LastSeen,
		established: conn.established,
	}

	return connCopy, true
}

// Timeout returns the configured timeout duration for the tracker
func (t *UDPTracker) Timeout() time.Duration {
	return t.timeout
}

func makeKey(srcIP net.IP, srcPort uint16, dstIP net.IP, dstPort uint16) ConnKey {
	var srcAddr, dstAddr [16]byte
	copy(srcAddr[:], srcIP.To16()) // Ensure 16-byte representation
	copy(dstAddr[:], dstIP.To16())
	return ConnKey{
		SrcIP:   srcAddr,
		SrcPort: srcPort,
		DstIP:   dstAddr,
		DstPort: dstPort,
	}
}
