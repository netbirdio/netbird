package conntrack

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strconv"
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

	// MaxICMPPayloadLength is the maximum length of ICMP payload we consider for original packet info.
	// IPv4: 20-byte header + 8-byte transport = 28 bytes.
	// IPv6: 40-byte header + 8-byte transport = 48 bytes.
	MaxICMPPayloadLength = 48
	// minICMPPayloadIPv4 is the minimum embedded packet length for IPv4 ICMP errors.
	minICMPPayloadIPv4 = 28
	// minICMPPayloadIPv6 is the minimum embedded packet length for IPv6 ICMP errors.
	minICMPPayloadIPv6 = 48
)

// ICMPConnKey uniquely identifies an ICMP connection
type ICMPConnKey struct {
	SrcIP netip.Addr
	DstIP netip.Addr
	ID    uint16
}

func (i ICMPConnKey) String() string {
	return fmt.Sprintf("%s → %s (id %d)", i.SrcIP, i.DstIP, i.ID)
}

// ICMPConnTrack represents an ICMP connection state
type ICMPConnTrack struct {
	BaseConnTrack
	ICMPType uint8
	ICMPCode uint8
}

// EnvICMPMaxEntries caps the ICMP conntrack table size.
const EnvICMPMaxEntries = "NB_CONNTRACK_ICMP_MAX"

// ICMPTracker manages ICMP connection states
type ICMPTracker struct {
	logger        *nblog.Logger
	connections   map[ICMPConnKey]*ICMPConnTrack
	timeout       time.Duration
	cleanupTicker *time.Ticker
	tickerCancel  context.CancelFunc
	mutex         sync.RWMutex
	maxEntries    int
	flowLogger    nftypes.FlowLogger
}

// ICMPInfo holds ICMP type, code, and payload for lazy string formatting in logs
type ICMPInfo struct {
	TypeCode    layers.ICMPv4TypeCode
	PayloadData [MaxICMPPayloadLength]byte
	// actual length of valid data
	PayloadLen int
}

// String implements fmt.Stringer for lazy evaluation in log messages
func (info ICMPInfo) String() string {
	if info.isErrorMessage() && info.PayloadLen >= minICMPPayloadIPv4 {
		if origInfo := info.parseOriginalPacket(); origInfo != "" {
			return fmt.Sprintf("%s (original: %s)", info.TypeCode, origInfo)
		}
	}

	return info.TypeCode.String()
}

// isErrorMessage returns true if this ICMP type carries original packet info.
// Covers both ICMPv4 and ICMPv6 error types. Without a family field we match
// both sets; type 3 overlaps (v4 DestUnreachable / v6 TimeExceeded) so it's
// kept as a literal.
func (info ICMPInfo) isErrorMessage() bool {
	typ := info.TypeCode.Type()
	// ICMPv4 error types
	if typ == layers.ICMPv4TypeDestinationUnreachable ||
		typ == layers.ICMPv4TypeRedirect ||
		typ == layers.ICMPv4TypeTimeExceeded ||
		typ == layers.ICMPv4TypeParameterProblem {
		return true
	}
	// ICMPv6 error types (type 3 already matched above as v4 DestUnreachable)
	if typ == layers.ICMPv6TypeDestinationUnreachable ||
		typ == layers.ICMPv6TypePacketTooBig ||
		typ == layers.ICMPv6TypeParameterProblem {
		return true
	}
	return false
}

// parseOriginalPacket extracts info about the original packet from ICMP payload
func (info ICMPInfo) parseOriginalPacket() string {
	if info.PayloadLen == 0 {
		return ""
	}

	version := (info.PayloadData[0] >> 4) & 0xF

	var protocol uint8
	var srcIP, dstIP net.IP
	var transportData []byte

	switch version {
	case 4:
		if info.PayloadLen < minICMPPayloadIPv4 {
			return ""
		}
		protocol = info.PayloadData[9]
		srcIP = net.IP(info.PayloadData[12:16])
		dstIP = net.IP(info.PayloadData[16:20])
		transportData = info.PayloadData[20:]
	case 6:
		if info.PayloadLen < minICMPPayloadIPv6 {
			return ""
		}
		// Next Header field in IPv6 header
		protocol = info.PayloadData[6]
		srcIP = net.IP(info.PayloadData[8:24])
		dstIP = net.IP(info.PayloadData[24:40])
		transportData = info.PayloadData[40:]
	default:
		return ""
	}

	switch nftypes.Protocol(protocol) {
	case nftypes.TCP:
		srcPort := uint16(transportData[0])<<8 | uint16(transportData[1])
		dstPort := uint16(transportData[2])<<8 | uint16(transportData[3])
		return "TCP " + net.JoinHostPort(srcIP.String(), strconv.Itoa(int(srcPort))) + " → " + net.JoinHostPort(dstIP.String(), strconv.Itoa(int(dstPort)))

	case nftypes.UDP:
		srcPort := uint16(transportData[0])<<8 | uint16(transportData[1])
		dstPort := uint16(transportData[2])<<8 | uint16(transportData[3])
		return "UDP " + net.JoinHostPort(srcIP.String(), strconv.Itoa(int(srcPort))) + " → " + net.JoinHostPort(dstIP.String(), strconv.Itoa(int(dstPort)))

	case nftypes.ICMP:
		icmpType := transportData[0]
		icmpCode := transportData[1]
		return fmt.Sprintf("ICMP %s → %s (type %d code %d)", srcIP, dstIP, icmpType, icmpCode)

	default:
		return fmt.Sprintf("Proto %d %s → %s", protocol, srcIP, dstIP)
	}
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
		maxEntries:    envInt(logger, EnvICMPMaxEntries, DefaultMaxICMPEntries),
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
func (t *ICMPTracker) TrackOutbound(
	srcIP netip.Addr,
	dstIP netip.Addr,
	id uint16,
	typecode layers.ICMPv4TypeCode,
	payload []byte,
	size int,
) {
	if _, exists := t.updateIfExists(dstIP, srcIP, id, nftypes.Egress, size); !exists {
		// if (inverted direction) conn is not tracked, track this direction
		t.track(srcIP, dstIP, id, typecode, nftypes.Egress, nil, payload, size)
	}
}

// TrackInbound records an inbound ICMP Echo Request
func (t *ICMPTracker) TrackInbound(
	srcIP netip.Addr,
	dstIP netip.Addr,
	id uint16,
	typecode layers.ICMPv4TypeCode,
	ruleId []byte,
	payload []byte,
	size int,
) {
	t.track(srcIP, dstIP, id, typecode, nftypes.Ingress, ruleId, payload, size)
}

// track is the common implementation for tracking both inbound and outbound ICMP connections
func (t *ICMPTracker) track(
	srcIP netip.Addr,
	dstIP netip.Addr,
	id uint16,
	typecode layers.ICMPv4TypeCode,
	direction nftypes.Direction,
	ruleId []byte,
	payload []byte,
	size int,
) {
	key, exists := t.updateIfExists(srcIP, dstIP, id, direction, size)
	if exists {
		return
	}

	typ, code := typecode.Type(), typecode.Code()
	icmpInfo := ICMPInfo{
		TypeCode: typecode,
	}
	if len(payload) > 0 {
		icmpInfo.PayloadLen = len(payload)
		if icmpInfo.PayloadLen > MaxICMPPayloadLength {
			icmpInfo.PayloadLen = MaxICMPPayloadLength
		}
		copy(icmpInfo.PayloadData[:], payload[:icmpInfo.PayloadLen])
	}

	// non echo requests don't need tracking
	if typ != uint8(layers.ICMPv4TypeEchoRequest) {
		if t.logger.Enabled(nblog.LevelTrace) {
			t.logger.Trace3("New %s ICMP connection %s - %s", direction, key, icmpInfo)
		}
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
	if t.maxEntries > 0 && len(t.connections) >= t.maxEntries {
		t.evictOneLocked()
	}
	t.connections[key] = conn
	t.mutex.Unlock()

	if t.logger.Enabled(nblog.LevelTrace) {
		t.logger.Trace3("New %s ICMP connection %s - %s", direction, key, icmpInfo)
	}
	t.sendEvent(nftypes.TypeStart, conn, ruleId)
}

// IsValidInbound checks if an inbound ICMP Echo Reply matches a tracked request.
// Accepts both ICMPv4 (type 0) and ICMPv6 (type 129) echo replies.
func (t *ICMPTracker) IsValidInbound(srcIP netip.Addr, dstIP netip.Addr, id uint16, icmpType uint8, size int) bool {
	if icmpType != uint8(layers.ICMPv4TypeEchoReply) && icmpType != uint8(layers.ICMPv6TypeEchoReply) {
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

// evictOneLocked removes one entry to make room. Caller must hold t.mutex.
// Bounded sample scan: picks the oldest among up to evictSampleSize entries.
func (t *ICMPTracker) evictOneLocked() {
	var candKey ICMPConnKey
	var candSeen int64
	haveCand := false
	sampled := 0

	for k, c := range t.connections {
		seen := c.lastSeen.Load()
		if !haveCand || seen < candSeen {
			candKey = k
			candSeen = seen
			haveCand = true
		}
		sampled++
		if sampled >= evictSampleSize {
			break
		}
	}
	if haveCand {
		if evicted := t.connections[candKey]; evicted != nil {
			t.sendEvent(nftypes.TypeEnd, evicted, nil)
		}
		delete(t.connections, candKey)
	}
}

func (t *ICMPTracker) cleanup() {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	for key, conn := range t.connections {
		if conn.timeoutExceeded(t.timeout) {
			delete(t.connections, key)

			if t.logger.Enabled(nblog.LevelTrace) {
				t.logger.Trace5("Removed ICMP connection %s (timeout) [in: %d Pkts/%d B out: %d Pkts/%d B]",
					key, conn.PacketsRx.Load(), conn.BytesRx.Load(), conn.PacketsTx.Load(), conn.BytesTx.Load())
			}
			t.sendEvent(nftypes.TypeEnd, conn, nil)
		}
	}
}

func icmpProtocolForAddr(ip netip.Addr) nftypes.Protocol {
	if ip.Is6() {
		return nftypes.ICMPv6
	}
	return nftypes.ICMP
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
		Protocol:  icmpProtocolForAddr(conn.SourceIP),
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
		Protocol:  icmpProtocolForAddr(srcIP),
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
