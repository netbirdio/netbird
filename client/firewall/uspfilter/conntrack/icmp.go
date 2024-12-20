package conntrack

import (
	"net"
	"slices"
	"sync"
	"time"

	"github.com/google/gopacket/layers"
)

const (
	// DefaultICMPTimeout is the default timeout for ICMP connections
	DefaultICMPTimeout = 30 * time.Second
	// ICMPCleanupInterval is how often we check for stale ICMP connections
	ICMPCleanupInterval = 15 * time.Second
)

// ICMPConnKey uniquely identifies an ICMP connection
type ICMPConnKey struct {
	// Supports both IPv4 and IPv6
	SrcIP    [16]byte
	DstIP    [16]byte
	Sequence uint16 // ICMP sequence number
	ID       uint16 // ICMP identifier
}

// ICMPConnTrack represents an ICMP connection state
type ICMPConnTrack struct {
	SourceIP    net.IP
	DestIP      net.IP
	Sequence    uint16
	ID          uint16
	LastSeen    time.Time
	established bool
}

// ICMPTracker manages ICMP connection states
type ICMPTracker struct {
	connections   map[ICMPConnKey]*ICMPConnTrack
	timeout       time.Duration
	cleanupTicker *time.Ticker
	mutex         sync.RWMutex
	done          chan struct{}
}

// NewICMPTracker creates a new ICMP connection tracker
func NewICMPTracker(timeout time.Duration) *ICMPTracker {
	if timeout == 0 {
		timeout = DefaultICMPTimeout
	}

	tracker := &ICMPTracker{
		connections:   make(map[ICMPConnKey]*ICMPConnTrack),
		timeout:       timeout,
		cleanupTicker: time.NewTicker(ICMPCleanupInterval),
		done:          make(chan struct{}),
	}

	go tracker.cleanupRoutine()
	return tracker
}

// TrackOutbound records an outbound ICMP Echo Request
func (t *ICMPTracker) TrackOutbound(srcIP net.IP, dstIP net.IP, id uint16, seq uint16) {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	key := makeICMPKey(srcIP, dstIP, id, seq)

	t.connections[key] = &ICMPConnTrack{
		SourceIP:    slices.Clone(srcIP),
		DestIP:      slices.Clone(dstIP),
		ID:          id,
		Sequence:    seq,
		LastSeen:    time.Now(),
		established: true,
	}
}

// IsValidInbound checks if an inbound ICMP Echo Reply matches a tracked request
func (t *ICMPTracker) IsValidInbound(srcIP net.IP, dstIP net.IP, id uint16, seq uint16, icmpType uint8) bool {
	t.mutex.RLock()
	defer t.mutex.RUnlock()

	// Always allow Echo Request (type 8 for IPv4, 128 for IPv6)
	if icmpType == uint8(layers.ICMPv4TypeEchoRequest) || icmpType == uint8(layers.ICMPv6TypeEchoRequest) {
		return true
	}

	// For Echo Reply, check if we have a matching request
	if icmpType != uint8(layers.ICMPv4TypeEchoReply) && icmpType != uint8(layers.ICMPv6TypeEchoReply) {
		return false
	}

	key := makeICMPKey(dstIP, srcIP, id, seq)
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
		conn.ID == id &&
		conn.Sequence == seq {

		conn.LastSeen = time.Now()
		return true
	}

	return false
}

func (t *ICMPTracker) cleanupRoutine() {
	for {
		select {
		case <-t.cleanupTicker.C:
			t.cleanup()
		case <-t.done:
			return
		}
	}
}

func (t *ICMPTracker) cleanup() {
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
func (t *ICMPTracker) Close() {
	t.cleanupTicker.Stop()
	close(t.done)
}

func makeICMPKey(srcIP net.IP, dstIP net.IP, id uint16, seq uint16) ICMPConnKey {
	var srcAddr, dstAddr [16]byte
	copy(srcAddr[:], srcIP.To16())
	copy(dstAddr[:], dstIP.To16())
	return ICMPConnKey{
		SrcIP:    srcAddr,
		DstIP:    dstAddr,
		ID:       id,
		Sequence: seq,
	}
}
