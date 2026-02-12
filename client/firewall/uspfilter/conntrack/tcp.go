package conntrack

// TODO: Send RST packets for invalid/timed-out connections

import (
	"context"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	nblog "github.com/netbirdio/netbird/client/firewall/uspfilter/log"
	nftypes "github.com/netbirdio/netbird/client/internal/netflow/types"
)

const (
	// MSL (Maximum Segment Lifetime) is typically 2 minutes
	MSL = 2 * time.Minute
	// TimeWaitTimeout (TIME-WAIT) should last 2*MSL
	TimeWaitTimeout = 2 * MSL
)

const (
	TCPFin  uint8 = 0x01
	TCPSyn  uint8 = 0x02
	TCPRst  uint8 = 0x04
	TCPPush uint8 = 0x08
	TCPAck  uint8 = 0x10
	TCPUrg  uint8 = 0x20
)

const (
	// DefaultTCPTimeout is the default timeout for established TCP connections
	DefaultTCPTimeout = 3 * time.Hour
	// TCPHandshakeTimeout is timeout for TCP handshake completion
	TCPHandshakeTimeout = 60 * time.Second
	// TCPCleanupInterval is how often we check for stale connections
	TCPCleanupInterval = 5 * time.Minute
)

// TCPState represents the state of a TCP connection
type TCPState int32

func (s TCPState) String() string {
	switch s {
	case TCPStateNew:
		return "New"
	case TCPStateSynSent:
		return "SYN Sent"
	case TCPStateSynReceived:
		return "SYN Received"
	case TCPStateEstablished:
		return "Established"
	case TCPStateFinWait1:
		return "FIN Wait 1"
	case TCPStateFinWait2:
		return "FIN Wait 2"
	case TCPStateClosing:
		return "Closing"
	case TCPStateTimeWait:
		return "Time Wait"
	case TCPStateCloseWait:
		return "Close Wait"
	case TCPStateLastAck:
		return "Last ACK"
	case TCPStateClosed:
		return "Closed"
	default:
		return "Unknown"
	}
}

const (
	TCPStateNew TCPState = iota
	TCPStateSynSent
	TCPStateSynReceived
	TCPStateEstablished
	TCPStateFinWait1
	TCPStateFinWait2
	TCPStateClosing
	TCPStateTimeWait
	TCPStateCloseWait
	TCPStateLastAck
	TCPStateClosed
)

// TCPConnTrack represents a TCP connection state
type TCPConnTrack struct {
	BaseConnTrack
	SourcePort uint16
	DestPort   uint16
	state      atomic.Int32
	tombstone  atomic.Bool
}

// GetState safely retrieves the current state
func (t *TCPConnTrack) GetState() TCPState {
	return TCPState(t.state.Load())
}

// SetState safely updates the current state
func (t *TCPConnTrack) SetState(state TCPState) {
	t.state.Store(int32(state))
}

// CompareAndSwapState atomically changes the state from old to new if current == old
func (t *TCPConnTrack) CompareAndSwapState(old, newState TCPState) bool {
	return t.state.CompareAndSwap(int32(old), int32(newState))
}

// IsTombstone safely checks if the connection is marked for deletion
func (t *TCPConnTrack) IsTombstone() bool {
	return t.tombstone.Load()
}

// IsSupersededBy returns true if this connection should be replaced by a new one
// carrying the given flags. Tombstoned connections are always superseded; TIME-WAIT
// connections are superseded by a pure SYN (a new connection attempt for the same
// four-tuple, as contemplated by RFC 1122 §4.2.2.13 and RFC 6191).
func (t *TCPConnTrack) IsSupersededBy(flags uint8) bool {
	if t.tombstone.Load() {
		return true
	}
	return flags&TCPSyn != 0 && flags&TCPAck == 0 && TCPState(t.state.Load()) == TCPStateTimeWait
}

// SetTombstone safely marks the connection for deletion
func (t *TCPConnTrack) SetTombstone() {
	t.tombstone.Store(true)
}

// TCPTracker manages TCP connection states
type TCPTracker struct {
	logger        *nblog.Logger
	connections   map[ConnKey]*TCPConnTrack
	mutex         sync.RWMutex
	cleanupTicker *time.Ticker
	tickerCancel  context.CancelFunc
	timeout       time.Duration
	waitTimeout   time.Duration
	flowLogger    nftypes.FlowLogger
}

// NewTCPTracker creates a new TCP connection tracker
func NewTCPTracker(timeout time.Duration, logger *nblog.Logger, flowLogger nftypes.FlowLogger) *TCPTracker {
	waitTimeout := TimeWaitTimeout
	if timeout == 0 {
		timeout = DefaultTCPTimeout
	} else {
		waitTimeout = timeout / 45
	}

	ctx, cancel := context.WithCancel(context.Background())

	tracker := &TCPTracker{
		logger:        logger,
		connections:   make(map[ConnKey]*TCPConnTrack),
		cleanupTicker: time.NewTicker(TCPCleanupInterval),
		tickerCancel:  cancel,
		timeout:       timeout,
		waitTimeout:   waitTimeout,
		flowLogger:    flowLogger,
	}

	go tracker.cleanupRoutine(ctx)
	return tracker
}

func (t *TCPTracker) updateIfExists(srcIP, dstIP netip.Addr, srcPort, dstPort uint16, flags uint8, direction nftypes.Direction, size int) (ConnKey, uint16, bool) {
	key := ConnKey{
		SrcIP:   srcIP,
		DstIP:   dstIP,
		SrcPort: srcPort,
		DstPort: dstPort,
	}

	t.mutex.RLock()
	conn, exists := t.connections[key]
	t.mutex.RUnlock()

	if exists && !conn.IsSupersededBy(flags) {
		t.updateState(key, conn, flags, direction, size)
		return key, uint16(conn.DNATOrigPort.Load()), true
	}

	return key, 0, false
}

// TrackOutbound records an outbound TCP connection and returns the original port if DNAT reversal is needed
func (t *TCPTracker) TrackOutbound(srcIP, dstIP netip.Addr, srcPort, dstPort uint16, flags uint8, size int) uint16 {
	if _, origPort, exists := t.updateIfExists(dstIP, srcIP, dstPort, srcPort, flags, nftypes.Egress, size); exists {
		return origPort
	}
	// if (inverted direction) conn is not tracked, track this direction
	t.track(srcIP, dstIP, srcPort, dstPort, flags, nftypes.Egress, nil, size, 0)
	return 0
}

// TrackInbound processes an inbound TCP packet and updates connection state
func (t *TCPTracker) TrackInbound(srcIP, dstIP netip.Addr, srcPort, dstPort uint16, flags uint8, ruleID []byte, size int, dnatOrigPort uint16) {
	t.track(srcIP, dstIP, srcPort, dstPort, flags, nftypes.Ingress, ruleID, size, dnatOrigPort)
}

// track is the common implementation for tracking both inbound and outbound connections
func (t *TCPTracker) track(srcIP, dstIP netip.Addr, srcPort, dstPort uint16, flags uint8, direction nftypes.Direction, ruleID []byte, size int, origPort uint16) {
	key, _, exists := t.updateIfExists(srcIP, dstIP, srcPort, dstPort, flags, direction, size)
	if exists || flags&TCPSyn == 0 {
		return
	}

	conn := &TCPConnTrack{
		BaseConnTrack: BaseConnTrack{
			FlowId:    uuid.New(),
			Direction: direction,
			SourceIP:  srcIP,
			DestIP:    dstIP,
		},
		SourcePort: srcPort,
		DestPort:   dstPort,
	}

	conn.tombstone.Store(false)
	conn.state.Store(int32(TCPStateNew))
	conn.DNATOrigPort.Store(uint32(origPort))

	if origPort != 0 {
		t.logger.Trace4("New %s TCP connection: %s (port DNAT %d -> %d)", direction, key, origPort, dstPort)
	} else {
		t.logger.Trace2("New %s TCP connection: %s", direction, key)
	}
	t.updateState(key, conn, flags, direction, size)

	t.mutex.Lock()
	t.connections[key] = conn
	t.mutex.Unlock()

	t.sendEvent(nftypes.TypeStart, conn, ruleID)
}

// IsValidInbound checks if an inbound TCP packet matches a tracked connection
func (t *TCPTracker) IsValidInbound(srcIP, dstIP netip.Addr, srcPort, dstPort uint16, flags uint8, size int) bool {
	key := ConnKey{
		SrcIP:   dstIP,
		DstIP:   srcIP,
		SrcPort: dstPort,
		DstPort: srcPort,
	}

	t.mutex.RLock()
	conn, exists := t.connections[key]
	t.mutex.RUnlock()

	if !exists || conn.IsSupersededBy(flags) {
		return false
	}

	currentState := conn.GetState()
	if !t.isValidStateForFlags(currentState, flags) {
		t.logger.Warn3("TCP state %s is not valid with flags %x for connection %s", currentState, flags, key)
		// allow all flags for established for now
		if currentState == TCPStateEstablished {
			return true
		}
		return false
	}

	t.updateState(key, conn, flags, nftypes.Ingress, size)
	return true
}

// updateState updates the TCP connection state based on flags
func (t *TCPTracker) updateState(key ConnKey, conn *TCPConnTrack, flags uint8, packetDir nftypes.Direction, size int) {
	conn.UpdateLastSeen()
	conn.UpdateCounters(packetDir, size)

	currentState := conn.GetState()

	if flags&TCPRst != 0 {
		if conn.CompareAndSwapState(currentState, TCPStateClosed) {
			conn.SetTombstone()
			t.logger.Trace6("TCP connection reset: %s (dir: %s) [in: %d Pkts/%d B, out: %d Pkts/%d B]",
				key, packetDir, conn.PacketsRx.Load(), conn.BytesRx.Load(), conn.PacketsTx.Load(), conn.BytesTx.Load())
			t.sendEvent(nftypes.TypeEnd, conn, nil)
		}
		return
	}

	var newState TCPState
	switch currentState {
	case TCPStateNew:
		if flags&TCPSyn != 0 && flags&TCPAck == 0 {
			if conn.Direction == nftypes.Egress {
				newState = TCPStateSynSent
			} else {
				newState = TCPStateSynReceived
			}
		}

	case TCPStateSynSent:
		if flags&TCPSyn != 0 && flags&TCPAck != 0 {
			if packetDir != conn.Direction {
				newState = TCPStateEstablished
			} else {
				// Simultaneous open
				newState = TCPStateSynReceived
			}
		}

	case TCPStateSynReceived:
		if flags&TCPAck != 0 && flags&TCPSyn == 0 {
			if packetDir == conn.Direction {
				newState = TCPStateEstablished
			}
		}

	case TCPStateEstablished:
		if flags&TCPFin != 0 {
			if packetDir == conn.Direction {
				newState = TCPStateFinWait1
			} else {
				newState = TCPStateCloseWait
			}
		}

	case TCPStateFinWait1:
		if packetDir != conn.Direction {
			switch {
			case flags&TCPFin != 0 && flags&TCPAck != 0:
				newState = TCPStateClosing
			case flags&TCPFin != 0:
				newState = TCPStateClosing
			case flags&TCPAck != 0:
				newState = TCPStateFinWait2
			}
		}

	case TCPStateFinWait2:
		if flags&TCPFin != 0 {
			newState = TCPStateTimeWait
		}

	case TCPStateClosing:
		if flags&TCPAck != 0 {
			newState = TCPStateTimeWait
		}

	case TCPStateCloseWait:
		if flags&TCPFin != 0 {
			newState = TCPStateLastAck
		}

	case TCPStateLastAck:
		if flags&TCPAck != 0 {
			newState = TCPStateClosed
		}
	}

	if newState != 0 && conn.CompareAndSwapState(currentState, newState) {
		t.logger.Trace4("TCP connection %s transitioned from %s to %s (dir: %s)", key, currentState, newState, packetDir)

		switch newState {
		case TCPStateTimeWait:
			t.logger.Trace5("TCP connection %s completed [in: %d Pkts/%d B, out: %d Pkts/%d B]",
				key, conn.PacketsRx.Load(), conn.BytesRx.Load(), conn.PacketsTx.Load(), conn.BytesTx.Load())
			t.sendEvent(nftypes.TypeEnd, conn, nil)

		case TCPStateClosed:
			conn.SetTombstone()
			t.logger.Trace5("TCP connection %s closed gracefully [in: %d Pkts/%d, B out: %d Pkts/%d B]",
				key, conn.PacketsRx.Load(), conn.BytesRx.Load(), conn.PacketsTx.Load(), conn.BytesTx.Load())
			t.sendEvent(nftypes.TypeEnd, conn, nil)
		}
	}
}

// isValidStateForFlags checks if the TCP flags are valid for the current connection state
func (t *TCPTracker) isValidStateForFlags(state TCPState, flags uint8) bool {
	if !isValidFlagCombination(flags) {
		return false
	}
	if flags&TCPRst != 0 {
		if state == TCPStateSynSent {
			return flags&TCPAck != 0
		}
		return true
	}

	switch state {
	case TCPStateNew:
		return flags&TCPSyn != 0 && flags&TCPAck == 0
	case TCPStateSynSent:
		// TODO: support simultaneous open
		return flags&TCPSyn != 0 && flags&TCPAck != 0
	case TCPStateSynReceived:
		return flags&TCPAck != 0
	case TCPStateEstablished:
		return flags&TCPAck != 0
	case TCPStateFinWait1:
		return flags&TCPFin != 0 || flags&TCPAck != 0
	case TCPStateFinWait2:
		return flags&TCPFin != 0 || flags&TCPAck != 0
	case TCPStateClosing:
		// In CLOSING state, we should accept the final ACK
		return flags&TCPAck != 0
	case TCPStateTimeWait:
		// In TIME_WAIT, we might see retransmissions
		return flags&TCPAck != 0
	case TCPStateCloseWait:
		return flags&TCPFin != 0 || flags&TCPAck != 0
	case TCPStateLastAck:
		return flags&TCPAck != 0
	case TCPStateClosed:
		// Accept retransmitted ACKs in closed state, the final ACK might be lost and the peer will retransmit their FIN-ACK
		return flags&TCPAck != 0
	}
	return false
}

func (t *TCPTracker) cleanupRoutine(ctx context.Context) {
	defer t.cleanupTicker.Stop()

	for {
		select {
		case <-t.cleanupTicker.C:
			t.cleanup()
		case <-ctx.Done():
			return
		}
	}
}

func (t *TCPTracker) cleanup() {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	for key, conn := range t.connections {
		if conn.IsTombstone() {
			// Clean up tombstoned connections without sending an event
			delete(t.connections, key)
			continue
		}

		var timeout time.Duration
		currentState := conn.GetState()
		switch currentState {
		case TCPStateTimeWait:
			timeout = t.waitTimeout
		case TCPStateEstablished:
			timeout = t.timeout
		default:
			timeout = TCPHandshakeTimeout
		}

		if conn.timeoutExceeded(timeout) {
			delete(t.connections, key)

			t.logger.Trace6("Cleaned up timed-out TCP connection %s (%s) [in: %d Pkts/%d, B out: %d Pkts/%d B]",
				key, conn.GetState(), conn.PacketsRx.Load(), conn.BytesRx.Load(), conn.PacketsTx.Load(), conn.BytesTx.Load())

			// event already handled by state change
			if currentState != TCPStateTimeWait {
				t.sendEvent(nftypes.TypeEnd, conn, nil)
			}
		}
	}
}

// GetConnection safely retrieves a connection state
func (t *TCPTracker) GetConnection(srcIP netip.Addr, srcPort uint16, dstIP netip.Addr, dstPort uint16) (*TCPConnTrack, bool) {
	t.mutex.RLock()
	defer t.mutex.RUnlock()

	key := ConnKey{
		SrcIP:   srcIP,
		DstIP:   dstIP,
		SrcPort: srcPort,
		DstPort: dstPort,
	}
	conn, exists := t.connections[key]
	return conn, exists
}

// Close stops the cleanup routine and releases resources
func (t *TCPTracker) Close() {
	t.tickerCancel()

	// Clean up all remaining IPs
	t.mutex.Lock()
	t.connections = nil
	t.mutex.Unlock()
}

func isValidFlagCombination(flags uint8) bool {
	// Invalid: SYN+FIN
	if flags&TCPSyn != 0 && flags&TCPFin != 0 {
		return false
	}

	// Invalid: RST with SYN or FIN
	if flags&TCPRst != 0 && (flags&TCPSyn != 0 || flags&TCPFin != 0) {
		return false
	}

	return true
}

func (t *TCPTracker) sendEvent(typ nftypes.Type, conn *TCPConnTrack, ruleID []byte) {
	t.flowLogger.StoreEvent(nftypes.EventFields{
		FlowID:     conn.FlowId,
		Type:       typ,
		RuleID:     ruleID,
		Direction:  conn.Direction,
		Protocol:   nftypes.TCP,
		SourceIP:   conn.SourceIP,
		DestIP:     conn.DestIP,
		SourcePort: conn.SourcePort,
		DestPort:   conn.DestPort,
		RxPackets:  conn.PacketsRx.Load(),
		TxPackets:  conn.PacketsTx.Load(),
		RxBytes:    conn.BytesRx.Load(),
		TxBytes:    conn.BytesTx.Load(),
	})
}
