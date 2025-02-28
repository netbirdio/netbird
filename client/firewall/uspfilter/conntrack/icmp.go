package conntrack

import (
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/google/gopacket/layers"
	"github.com/google/uuid"

	nblog "github.com/netbirdio/netbird/client/firewall/uspfilter/log"
	"github.com/netbirdio/netbird/client/internal/netflow/types"
)

const (
	// DefaultICMPTimeout is the default timeout for ICMP connections
	DefaultICMPTimeout = 30 * time.Second
	// ICMPCleanupInterval is how often we check for stale ICMP connections
	ICMPCleanupInterval = 15 * time.Second
)

// ICMPConnKey uniquely identifies an ICMP connection
type ICMPConnKey struct {
	SrcIP    netip.Addr
	DstIP    netip.Addr
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
	flowLogger    types.FlowLogger
}

// NewICMPTracker creates a new ICMP connection tracker
func NewICMPTracker(timeout time.Duration, logger *nblog.Logger, flowLogger types.FlowLogger) *ICMPTracker {
	if timeout == 0 {
		timeout = DefaultICMPTimeout
	}

	tracker := &ICMPTracker{
		logger:        logger,
		connections:   make(map[ICMPConnKey]*ICMPConnTrack),
		timeout:       timeout,
		cleanupTicker: time.NewTicker(ICMPCleanupInterval),
		done:          make(chan struct{}),
		flowLogger:    flowLogger,
	}

	go tracker.cleanupRoutine()
	return tracker
}

func (t *ICMPTracker) updateIfExists(srcIP net.IP, dstIP net.IP, id uint16, seq uint16) (ICMPConnKey, bool) {
	key := makeICMPKey(srcIP, dstIP, id, seq)

	t.mutex.RLock()
	conn, exists := t.connections[key]
	t.mutex.RUnlock()

	if exists {
		conn.UpdateLastSeen()

		return key, true
	}

	return key, false
}

// TrackOutbound records an outbound ICMP connection
func (t *ICMPTracker) TrackOutbound(srcIP net.IP, dstIP net.IP, id uint16, seq uint16) {
	if _, exists := t.updateIfExists(dstIP, srcIP, id, seq); !exists {
		// if (inverted direction) conn is not tracked, track this direction
		t.track(srcIP, dstIP, id, seq, types.Egress)
	}
}

// TrackInbound records an inbound ICMP Echo Request
func (t *ICMPTracker) TrackInbound(srcIP net.IP, dstIP net.IP, id uint16, seq uint16) {
	t.track(srcIP, dstIP, id, seq, types.Ingress)
}

// track is the common implementation for tracking both inbound and outbound ICMP connections
func (t *ICMPTracker) track(srcIP net.IP, dstIP net.IP, id uint16, seq uint16, direction types.Direction) {
	key, exists := t.updateIfExists(srcIP, dstIP, id, seq)
	if exists {
		return
	}

	conn := &ICMPConnTrack{
		BaseConnTrack: BaseConnTrack{
			FlowId:    uuid.New(),
			Direction: direction,
			SourceIP:  key.SrcIP,
			DestIP:    key.DstIP,
		},
	}
	conn.UpdateLastSeen()

	t.mutex.Lock()
	t.connections[key] = conn
	t.mutex.Unlock()

	t.logger.Trace("New %s ICMP connection %s", conn.Direction, key)
	t.sendEvent(types.TypeStart, key, conn)
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

	if !exists || conn.timeoutExceeded(t.timeout) {
		return false
	}

	conn.UpdateLastSeen()

	return true
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
			delete(t.connections, key)

			t.logger.Debug("Removed ICMP connection %s (timeout)", &key)
			t.sendEvent(types.TypeEnd, key, conn)
		}
	}
}

// Close stops the cleanup routine and releases resources
func (t *ICMPTracker) Close() {
	t.cleanupTicker.Stop()
	close(t.done)

	t.mutex.Lock()
	t.connections = nil
	t.mutex.Unlock()
}

func (t *ICMPTracker) sendEvent(typ types.Type, key ICMPConnKey, conn *ICMPConnTrack) {
	t.flowLogger.StoreEvent(types.EventFields{
		FlowID:    conn.FlowId,
		Type:      typ,
		Direction: conn.Direction,
		Protocol:  types.ICMP, // TODO: adjust for IPv6/icmpv6
		SourceIP:  key.SrcIP,
		DestIP:    key.DstIP,
		// TODO: add icmp code/type,
	})
}

// makeICMPKey creates an ICMP connection key
func makeICMPKey(srcIP net.IP, dstIP net.IP, id uint16, seq uint16) ICMPConnKey {
	srcAddr, _ := netip.AddrFromSlice(srcIP)
	dstAddr, _ := netip.AddrFromSlice(dstIP)
	return ICMPConnKey{
		SrcIP:    srcAddr,
		DstIP:    dstAddr,
		ID:       id,
		Sequence: seq,
	}
}
