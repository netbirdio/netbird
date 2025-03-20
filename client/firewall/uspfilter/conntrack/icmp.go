package conntrack

import (
	"context"
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
	SrcIP netip.Addr
	DstIP netip.Addr
	ID    uint16
}

func (i ICMPConnKey) String() string {
	return fmt.Sprintf("%s -> %s (id %d)", i.SrcIP, i.DstIP, i.ID)
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
	tickerCancel  context.CancelFunc
	mutex         sync.RWMutex
	flowLogger    nftypes.FlowLogger
}

// NewICMPTracker creates a new ICMP connection tracker
func NewICMPTracker(timeout time.Duration, logger *nblog.Logger, flowLogger nftypes.FlowLogger) *ICMPTracker {
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
		flowLogger:    flowLogger,
	}

	go tracker.cleanupRoutine(ctx)
	return tracker
}

func (t *ICMPTracker) updateIfExists(srcIP netip.Addr, dstIP netip.Addr, id uint16, direction nftypes.Direction, size int) (ICMPConnKey, bool) {
	key := ICMPConnKey{
		SrcIP: srcIP,
		DstIP: dstIP,
		ID:    id,
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

// TrackOutbound records an outbound ICMP connection
func (t *ICMPTracker) TrackOutbound(srcIP netip.Addr, dstIP netip.Addr, id uint16, typecode layers.ICMPv4TypeCode, size int) {
	if _, exists := t.updateIfExists(dstIP, srcIP, id, nftypes.Egress, size); !exists {
		// if (inverted direction) conn is not tracked, track this direction
		t.track(srcIP, dstIP, id, typecode, nftypes.Egress, nil, size)
	}
}

// TrackInbound records an inbound ICMP Echo Request
func (t *ICMPTracker) TrackInbound(srcIP netip.Addr, dstIP netip.Addr, id uint16, typecode layers.ICMPv4TypeCode, ruleId []byte, size int) {
	t.track(srcIP, dstIP, id, typecode, nftypes.Ingress, ruleId, size)
}

// track is the common implementation for tracking both inbound and outbound ICMP connections
func (t *ICMPTracker) track(srcIP netip.Addr, dstIP netip.Addr, id uint16, typecode layers.ICMPv4TypeCode, direction nftypes.Direction, ruleId []byte, size int) {
	key, exists := t.updateIfExists(srcIP, dstIP, id, direction, size)
	if exists {
		return
	}

	typ, code := typecode.Type(), typecode.Code()

	// non echo requests don't need tracking
	if typ != uint8(layers.ICMPv4TypeEchoRequest) {
		t.logger.Trace("New %s ICMP connection %s type %d code %d", direction, key, typ, code)
		t.sendStartEvent(direction, srcIP, dstIP, typ, code, ruleId, size)
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
	conn.UpdateCounters(direction, size)

	t.mutex.Lock()
	t.connections[key] = conn
	t.mutex.Unlock()

	t.logger.Trace("New %s ICMP connection %s type %d code %d", direction, key, typ, code)
	t.sendEvent(nftypes.TypeStart, conn, ruleId)
}

// IsValidInbound checks if an inbound ICMP Echo Reply matches a tracked request
func (t *ICMPTracker) IsValidInbound(srcIP netip.Addr, dstIP netip.Addr, id uint16, icmpType uint8, size int) bool {
	if icmpType != uint8(layers.ICMPv4TypeEchoReply) {
		return false
	}

	key := ICMPConnKey{
		SrcIP: dstIP,
		DstIP: srcIP,
		ID:    id,
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
			delete(t.connections, key)

			t.logger.Debug("Removed ICMP connection %s (timeout) [in: %d Pkts/%d B out: %d Pkts/%d B]",
				key, conn.PacketsRx.Load(), conn.BytesRx.Load(), conn.PacketsTx.Load(), conn.BytesTx.Load())
			t.sendEvent(nftypes.TypeEnd, conn, nil)
		}
	}
}

// Close stops the cleanup routine and releases resources
func (t *ICMPTracker) Close() {
	t.tickerCancel()

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
		RxPackets: conn.PacketsRx.Load(),
		TxPackets: conn.PacketsTx.Load(),
		RxBytes:   conn.BytesRx.Load(),
		TxBytes:   conn.BytesTx.Load(),
	})
}

func (t *ICMPTracker) sendStartEvent(direction nftypes.Direction, srcIP netip.Addr, dstIP netip.Addr, typ uint8, code uint8, ruleID []byte, size int) {
	fields := nftypes.EventFields{
		FlowID:    uuid.New(),
		Type:      nftypes.TypeStart,
		RuleID:    ruleID,
		Direction: direction,
		Protocol:  nftypes.ICMP,
		SourceIP:  srcIP,
		DestIP:    dstIP,
		ICMPType:  typ,
		ICMPCode:  code,
	}
	if direction == nftypes.Ingress {
		fields.RxPackets = 1
		fields.RxBytes = uint64(size)
	} else {
		fields.TxPackets = 1
		fields.TxBytes = uint64(size)
	}
	t.flowLogger.StoreEvent(fields)
}
