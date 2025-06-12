package conntrack

import (
	"context"
	"fmt"
	"net"
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

	// MaxICMPPayloadLength is the maximum length of ICMP payload we consider for original packet info,
	// which includes the IP header (20 bytes) and transport header (8 bytes)
	MaxICMPPayloadLength = 28
)

var (
	icmpTypeDescriptions map[uint8]string
	icmpCodeDescriptions map[uint8]map[uint8]string
	icmpTypeNames        map[uint8]string
	icmpMapsOnce         sync.Once
)

func initICMPMaps() {
	icmpTypeDescriptions = map[uint8]string{
		0:  "Echo Reply",
		8:  "Echo Request",
		13: "Timestamp Request",
		14: "Timestamp Reply",
		15: "Information Request",
		16: "Information Reply",
	}

	icmpCodeDescriptions = map[uint8]map[uint8]string{
		3: { // Destination Unreachable
			0:  "Network",
			1:  "Host",
			2:  "Protocol",
			3:  "Port",
			4:  "Fragmentation needed",
			5:  "Source route failed",
			6:  "Network unknown",
			7:  "Host unknown",
			9:  "Network administratively prohibited",
			10: "Host administratively prohibited",
			11: "Network unreachable for ToS",
			12: "Host unreachable for ToS",
			13: "Communication administratively prohibited",
		},
		5: { // Redirect
			0: "Network",
			1: "Host",
			2: "Network for ToS",
			3: "Host for ToS",
		},
		11: { // Time Exceeded
			0: "TTL exceeded in transit",
			1: "Fragment reassembly time exceeded",
		},
		12: { // Parameter Problem
			0: "Pointer indicates error",
			1: "Missing required option",
			2: "Bad length",
		},
	}

	icmpTypeNames = map[uint8]string{
		3:  "Destination Unreachable",
		5:  "Redirect",
		11: "Time Exceeded",
		12: "Parameter Problem",
	}
}

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

// ICMPInfo holds ICMP type, code, and payload for lazy string formatting in logs
type ICMPInfo struct {
	Type        uint8
	Code        uint8
	PayloadData [MaxICMPPayloadLength]byte
	// actual length of valid data
	PayloadLen int
}

// String implements fmt.Stringer for lazy evaluation in log messages
func (info ICMPInfo) String() string {
	baseMsg := formatICMPTypeCode(info.Type, info.Code)

	if info.isErrorMessage() && info.PayloadLen >= MaxICMPPayloadLength {
		if origInfo := info.parseOriginalPacket(); origInfo != "" {
			return fmt.Sprintf("%s (original: %s)", baseMsg, origInfo)
		}
	}

	return baseMsg
}

// isErrorMessage returns true if this ICMP type carries original packet info
func (info ICMPInfo) isErrorMessage() bool {
	return info.Type == 3 || // Destination Unreachable
		info.Type == 5 || // Redirect
		info.Type == 11 || // Time Exceeded
		info.Type == 12 // Parameter Problem
}

// parseOriginalPacket extracts info about the original packet from ICMP payload
func (info ICMPInfo) parseOriginalPacket() string {
	if info.PayloadLen < MaxICMPPayloadLength {
		return ""
	}

	// TODO: handle IPv6
	if version := (info.PayloadData[0] >> 4) & 0xF; version != 4 {
		return ""
	}

	protocol := info.PayloadData[9]
	srcIP := net.IP(info.PayloadData[12:16])
	dstIP := net.IP(info.PayloadData[16:20])

	transportData := info.PayloadData[20:]

	switch nftypes.Protocol(protocol) {
	case nftypes.TCP:
		srcPort := uint16(transportData[0])<<8 | uint16(transportData[1])
		dstPort := uint16(transportData[2])<<8 | uint16(transportData[3])
		return fmt.Sprintf("TCP %s:%d → %s:%d", srcIP, srcPort, dstIP, dstPort)

	case nftypes.UDP:
		srcPort := uint16(transportData[0])<<8 | uint16(transportData[1])
		dstPort := uint16(transportData[2])<<8 | uint16(transportData[3])
		return fmt.Sprintf("UDP %s:%d → %s:%d", srcIP, srcPort, dstIP, dstPort)

	case nftypes.ICMP:
		icmpType := transportData[0]
		icmpCode := transportData[1]
		return fmt.Sprintf("ICMP %s → %s (type %d code %d)", srcIP, dstIP, icmpType, icmpCode)

	default:
		return fmt.Sprintf("Proto %d %s → %s", protocol, srcIP, dstIP)
	}
}

func formatICMPTypeCode(icmpType, icmpCode uint8) string {
	icmpMapsOnce.Do(initICMPMaps)

	if desc, exists := icmpTypeDescriptions[icmpType]; exists {
		return desc
	}

	// Check for types with specific code descriptions
	if typeName, hasTypeName := icmpTypeNames[icmpType]; hasTypeName {
		if codeDescs, hasCodeDescs := icmpCodeDescriptions[icmpType]; hasCodeDescs {
			if codeDesc, hasCodeDesc := codeDescs[icmpCode]; hasCodeDesc {
				return fmt.Sprintf("%s (%s)", typeName, codeDesc)
			}
		}
		return fmt.Sprintf("%s (code %d)", typeName, icmpCode)
	}

	return fmt.Sprintf("Type %d Code %d", icmpType, icmpCode)
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
		Type: typ,
		Code: code,
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
		t.logger.Trace("New %s ICMP connection %s - %s", direction, key, icmpInfo)
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

	t.logger.Trace("New %s ICMP connection %s - %s", direction, key, icmpInfo)
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

			t.logger.Trace("Removed ICMP connection %s (timeout) [in: %d Pkts/%d B out: %d Pkts/%d B]",
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
