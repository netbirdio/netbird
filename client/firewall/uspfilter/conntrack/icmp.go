package conntrack

import (
	"fmt"
	"net/netip"
	"sync"
	"time"

	"github.com/google/gopacket/layers"
	"github.com/google/uuid"

	nblog "github.com/netbirdio/netbird/client/firewall/uspfilter/log"
	nftypes "github.com/netbirdio/netbird/client/internal/netflow/types"
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

func (i ICMPConnKey) String() string {
	return fmt.Sprintf("%s -> %s (%d/%d)", i.SrcIP, i.DstIP, i.ID, i.Sequence)
}

// ICMPConnTrack represents an ICMP connection state
type ICMPConnTrack struct {
	BaseConnTrack
	ICMPType uint8
	ICMPCode uint8
}

// ICMPTracker manages ICMP connection states
type ICMPTracker struct {
	logger        *nblog.Logger
	connections   map[ICMPConnKey]*ICMPConnTrack
	timeout       time.Duration
	cleanupTicker *time.Ticker
	mutex         sync.RWMutex
	done          chan struct{}
	flowLogger    nftypes.FlowLogger
}

// NewICMPTracker creates a new ICMP connection tracker
func NewICMPTracker(timeout time.Duration, logger *nblog.Logger, flowLogger nftypes.FlowLogger) *ICMPTracker {
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

func (t *ICMPTracker) updateIfExists(srcIP netip.Addr, dstIP netip.Addr, id uint16, seq uint16) (ICMPConnKey, bool) {
	key := ICMPConnKey{
		SrcIP:    srcIP,
		DstIP:    dstIP,
		ID:       id,
		Sequence: seq,
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

// TrackOutbound records an outbound ICMP connection
func (t *ICMPTracker) TrackOutbound(srcIP netip.Addr, dstIP netip.Addr, id uint16, seq uint16, typecode layers.ICMPv4TypeCode) {
	if _, exists := t.updateIfExists(dstIP, srcIP, id, seq); !exists {
		// if (inverted direction) conn is not tracked, track this direction
		t.track(srcIP, dstIP, id, seq, typecode, nftypes.Egress, nil)
	}
}

// TrackInbound records an inbound ICMP Echo Request
func (t *ICMPTracker) TrackInbound(srcIP netip.Addr, dstIP netip.Addr, id uint16, seq uint16, typecode layers.ICMPv4TypeCode, ruleId []byte) {
	t.track(srcIP, dstIP, id, seq, typecode, nftypes.Ingress, ruleId)
}

// track is the common implementation for tracking both inbound and outbound ICMP connections
func (t *ICMPTracker) track(srcIP netip.Addr, dstIP netip.Addr, id uint16, seq uint16, typecode layers.ICMPv4TypeCode, direction nftypes.Direction, ruleId []byte) {
	// TODO: icmp doesn't need to extend the timeout
	key, exists := t.updateIfExists(srcIP, dstIP, id, seq)
	if exists {
		return
	}

	typ, code := typecode.Type(), typecode.Code()

	// non echo requests don't need tracking
	if typ != uint8(layers.ICMPv4TypeEchoRequest) {
		t.logger.Trace("New %s ICMP connection %s type %d code %d", direction, key, typ, code)
		t.sendStartEvent(direction, srcIP, dstIP, typ, code, ruleId)
		return
	}

	conn := &ICMPConnTrack{
		BaseConnTrack: BaseConnTrack{
			FlowId:    uuid.New(),
			Direction: direction,
			SourceIP:  srcIP,
			DestIP:    dstIP,
		},
		ICMPType: typ,
		ICMPCode: code,
	}
	conn.UpdateLastSeen()

	t.mutex.Lock()
	t.connections[key] = conn
	t.mutex.Unlock()

	t.logger.Trace("New %s ICMP connection %s type %d code %d", direction, key, typ, code)
	t.sendEvent(nftypes.TypeStart, conn, ruleId)
}

// IsValidInbound checks if an inbound ICMP Echo Reply matches a tracked request
func (t *ICMPTracker) IsValidInbound(srcIP netip.Addr, dstIP netip.Addr, id uint16, seq uint16, icmpType uint8) bool {
	if icmpType != uint8(layers.ICMPv4TypeEchoReply) {
		return false
	}

	key := ICMPConnKey{
		SrcIP:    dstIP,
		DstIP:    srcIP,
		ID:       id,
		Sequence: seq,
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
			t.sendEvent(nftypes.TypeEnd, conn, nil)
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

func (t *ICMPTracker) sendEvent(typ nftypes.Type, conn *ICMPConnTrack, ruleID []byte) {
	t.flowLogger.StoreEvent(nftypes.EventFields{
		FlowID:    conn.FlowId,
		Type:      typ,
		RuleID:    ruleID,
		Direction: conn.Direction,
		Protocol:  nftypes.ICMP, // TODO: adjust for IPv6/icmpv6
		SourceIP:  conn.SourceIP,
		DestIP:    conn.DestIP,
		ICMPType:  conn.ICMPType,
		ICMPCode:  conn.ICMPCode,
	})
}

func (t *ICMPTracker) sendStartEvent(direction nftypes.Direction, srcIP netip.Addr, dstIP netip.Addr, typ uint8, code uint8, RuleID []byte) {
	t.flowLogger.StoreEvent(nftypes.EventFields{
		FlowID:    uuid.New(),
		Type:      nftypes.TypeStart,
		RuleID:    RuleID,
		Direction: direction,
		Protocol:  nftypes.ICMP,
		SourceIP:  srcIP,
		DestIP:    dstIP,
		ICMPType:  typ,
		ICMPCode:  code,
	})
}
