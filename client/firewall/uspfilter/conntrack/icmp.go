package conntrack

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/google/gopacket/layers"

	nblog "github.com/netbirdio/netbird/client/firewall/uspfilter/log"
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
	BaseConnTrack
	Sequence uint16
	ID       uint16
}

// ICMPTracker manages ICMP connection states
type ICMPTracker struct {
	logger        *nblog.Logger
	connections   map[ICMPConnKey]*ICMPConnTrack
	timeout       time.Duration
	cleanupTicker *time.Ticker
	tickerCancel  context.CancelFunc
	mutex         sync.RWMutex
	ipPool        *PreallocatedIPs
}

// NewICMPTracker creates a new ICMP connection tracker
func NewICMPTracker(timeout time.Duration, logger *nblog.Logger) *ICMPTracker {
	if timeout == 0 {
		timeout = DefaultICMPTimeout
	}

	ctx, cancel := context.WithCancel(context.Background())

	tracker := &ICMPTracker{
		logger:        logger,
		connections:   make(map[ICMPConnKey]*ICMPConnTrack),
		timeout:       timeout,
		cleanupTicker: time.NewTicker(ICMPCleanupInterval),
		tickerCancel:  cancel,
		ipPool:        NewPreallocatedIPs(),
	}

	go tracker.cleanupRoutine(ctx)
	return tracker
}

// TrackOutbound records an outbound ICMP Echo Request
func (t *ICMPTracker) TrackOutbound(srcIP net.IP, dstIP net.IP, id uint16, seq uint16) {
	key := makeICMPKey(srcIP, dstIP, id, seq)

	t.mutex.Lock()
	conn, exists := t.connections[key]
	if !exists {
		srcIPCopy := t.ipPool.Get()
		dstIPCopy := t.ipPool.Get()
		copyIP(srcIPCopy, srcIP)
		copyIP(dstIPCopy, dstIP)

		conn = &ICMPConnTrack{
			BaseConnTrack: BaseConnTrack{
				SourceIP: srcIPCopy,
				DestIP:   dstIPCopy,
			},
			ID:       id,
			Sequence: seq,
		}
		conn.UpdateLastSeen()
		t.connections[key] = conn

		t.logger.Trace("New ICMP connection %v", key)
	}
	t.mutex.Unlock()

	conn.UpdateLastSeen()
}

// IsValidInbound checks if an inbound ICMP Echo Reply matches a tracked request
func (t *ICMPTracker) IsValidInbound(srcIP net.IP, dstIP net.IP, id uint16, seq uint16, icmpType uint8) bool {
	if icmpType != uint8(layers.ICMPv4TypeEchoReply) {
		return false
	}

	key := makeICMPKey(dstIP, srcIP, id, seq)

	t.mutex.RLock()
	conn, exists := t.connections[key]
	t.mutex.RUnlock()

	if !exists {
		return false
	}

	if conn.timeoutExceeded(t.timeout) {
		return false
	}

	return ValidateIPs(MakeIPAddr(srcIP), conn.DestIP) &&
		ValidateIPs(MakeIPAddr(dstIP), conn.SourceIP) &&
		conn.ID == id &&
		conn.Sequence == seq
}

func (t *ICMPTracker) cleanupRoutine(ctx context.Context) {
	defer t.tickerCancel()

	for {
		select {
		case <-t.cleanupTicker.C:
			t.cleanup()
		case <-ctx.Done():
			return
		}
	}
}
func (t *ICMPTracker) cleanup() {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	for key, conn := range t.connections {
		if conn.timeoutExceeded(t.timeout) {
			t.ipPool.Put(conn.SourceIP)
			t.ipPool.Put(conn.DestIP)
			delete(t.connections, key)

			t.logger.Debug("Removed ICMP connection %v (timeout)", key)
		}
	}
}

// Close stops the cleanup routine and releases resources
func (t *ICMPTracker) Close() {
	t.tickerCancel()

	t.mutex.Lock()
	for _, conn := range t.connections {
		t.ipPool.Put(conn.SourceIP)
		t.ipPool.Put(conn.DestIP)
	}
	t.connections = nil
	t.mutex.Unlock()
}

// makeICMPKey creates an ICMP connection key
func makeICMPKey(srcIP net.IP, dstIP net.IP, id uint16, seq uint16) ICMPConnKey {
	return ICMPConnKey{
		SrcIP:    MakeIPAddr(srcIP),
		DstIP:    MakeIPAddr(dstIP),
		ID:       id,
		Sequence: seq,
	}
}
