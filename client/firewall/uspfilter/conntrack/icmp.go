package conntrack

import (
	"fmt"
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
	Sequence uint16
	ID       uint16
}

func (i *ICMPConnKey) String() string {
	return fmt.Sprintf("%s -> %s (%d/%d)", i.SrcIP, i.DstIP, i.Sequence, i.ID)
}

// ICMPConnTrack represents an ICMP connection state
type ICMPConnTrack struct {
	BaseConnTrack
}

// ICMPTracker manages ICMP connection states
type ICMPTracker struct {
	logger        *nblog.Logger
	connections   map[ICMPConnKey]*ICMPConnTrack
	timeout       time.Duration
	cleanupTicker *time.Ticker
	mutex         sync.RWMutex
	done          chan struct{}
	ipPool        *PreallocatedIPs
}

// NewICMPTracker creates a new ICMP connection tracker
func NewICMPTracker(timeout time.Duration, logger *nblog.Logger) *ICMPTracker {
	if timeout == 0 {
		timeout = DefaultICMPTimeout
	}

	tracker := &ICMPTracker{
		logger:        logger,
		connections:   make(map[ICMPConnKey]*ICMPConnTrack),
		timeout:       timeout,
		cleanupTicker: time.NewTicker(ICMPCleanupInterval),
		done:          make(chan struct{}),
		ipPool:        NewPreallocatedIPs(),
	}

	go tracker.cleanupRoutine()
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
		}
		conn.UpdateLastSeen()
		t.connections[key] = conn

		t.logger.Trace("New ICMP connection %s", key)
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
		key.ID == id &&
		key.Sequence == seq
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

	for key, conn := range t.connections {
		if conn.timeoutExceeded(t.timeout) {
			t.ipPool.Put(conn.SourceIP)
			t.ipPool.Put(conn.DestIP)
			delete(t.connections, key)

			t.logger.Debug("Removed ICMP connection %s (timeout)", &key)
		}
	}
}

// Close stops the cleanup routine and releases resources
func (t *ICMPTracker) Close() {
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

// makeICMPKey creates an ICMP connection key
func makeICMPKey(srcIP net.IP, dstIP net.IP, id uint16, seq uint16) ICMPConnKey {
	return ICMPConnKey{
		SrcIP:    MakeIPAddr(srcIP),
		DstIP:    MakeIPAddr(dstIP),
		ID:       id,
		Sequence: seq,
	}
}
