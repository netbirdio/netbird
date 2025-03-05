package conntrack

// TODO: Send RST packets for invalid/timed-out connections

import (
	"net"
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
	TCPSyn  uint8 = 0x02
	TCPAck  uint8 = 0x10
	TCPFin  uint8 = 0x01
	TCPRst  uint8 = 0x04
	TCPPush uint8 = 0x08
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
type TCPState int

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
	State       TCPState
	established atomic.Bool
	tombstone   atomic.Bool
	sync.RWMutex
}

// IsEstablished safely checks if connection is established
func (t *TCPConnTrack) IsEstablished() bool {
	return t.established.Load()
}

// SetEstablished safely sets the established state
func (t *TCPConnTrack) SetEstablished(state bool) {
	t.established.Store(state)
}

// IsTombstone safely checks if the connection is marked for deletion
func (t *TCPConnTrack) IsTombstone() bool {
	return t.tombstone.Load()
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
	done          chan struct{}
	timeout       time.Duration
	flowLogger    nftypes.FlowLogger
}

// NewTCPTracker creates a new TCP connection tracker
func NewTCPTracker(timeout time.Duration, logger *nblog.Logger, flowLogger nftypes.FlowLogger) *TCPTracker {
	if timeout == 0 {
		timeout = DefaultTCPTimeout
	}

	tracker := &TCPTracker{
		logger:        logger,
		connections:   make(map[ConnKey]*TCPConnTrack),
		cleanupTicker: time.NewTicker(TCPCleanupInterval),
		done:          make(chan struct{}),
		timeout:       timeout,
		flowLogger:    flowLogger,
	}

	go tracker.cleanupRoutine()
	return tracker
}

func (t *TCPTracker) updateIfExists(srcIP net.IP, dstIP net.IP, srcPort uint16, dstPort uint16, flags uint8) (ConnKey, bool) {
	key := makeConnKey(srcIP, dstIP, srcPort, dstPort)

	t.mutex.RLock()
	conn, exists := t.connections[key]
	t.mutex.RUnlock()

	if exists {
		conn.Lock()
		t.updateState(key, conn, flags, conn.Direction == nftypes.Egress)
		conn.UpdateLastSeen()
		conn.Unlock()

		return key, true
	}

	return key, false
}

// TrackOutbound records an outbound TCP connection
func (t *TCPTracker) TrackOutbound(srcIP net.IP, dstIP net.IP, srcPort uint16, dstPort uint16, flags uint8) {
	if _, exists := t.updateIfExists(dstIP, srcIP, dstPort, srcPort, flags); !exists {
		// if (inverted direction) conn is not tracked, track this direction
		t.track(srcIP, dstIP, srcPort, dstPort, flags, nftypes.Egress, nil)
	}
}

// TrackInbound processes an inbound TCP packet and updates connection state
func (t *TCPTracker) TrackInbound(srcIP net.IP, dstIP net.IP, srcPort uint16, dstPort uint16, flags uint8, ruleID []byte) {
	t.track(srcIP, dstIP, srcPort, dstPort, flags, nftypes.Ingress, ruleID)
}

// track is the common implementation for tracking both inbound and outbound connections
func (t *TCPTracker) track(srcIP net.IP, dstIP net.IP, srcPort uint16, dstPort uint16, flags uint8, direction nftypes.Direction, ruleID []byte) {
	key, exists := t.updateIfExists(srcIP, dstIP, srcPort, dstPort, flags)
	if exists {
		return
	}

	conn := &TCPConnTrack{
		BaseConnTrack: BaseConnTrack{
			FlowId:     uuid.New(),
			Direction:  direction,
			SourceIP:   key.SrcIP,
			DestIP:     key.DstIP,
			SourcePort: srcPort,
			DestPort:   dstPort,
		},
	}

	conn.UpdateLastSeen()
	conn.established.Store(false)
	conn.tombstone.Store(false)

	t.logger.Trace("New %s TCP connection: %s", direction, key)
	t.updateState(key, conn, flags, direction == nftypes.Egress)

	t.mutex.Lock()
	t.connections[key] = conn
	t.mutex.Unlock()

	t.sendEvent(nftypes.TypeStart, key, conn, ruleID)
}

// IsValidInbound checks if an inbound TCP packet matches a tracked connection
func (t *TCPTracker) IsValidInbound(srcIP net.IP, dstIP net.IP, srcPort uint16, dstPort uint16, flags uint8) bool {
	key := makeConnKey(dstIP, srcIP, dstPort, srcPort)

	t.mutex.RLock()
	conn, exists := t.connections[key]
	t.mutex.RUnlock()

	if !exists {
		return false
	}

	// Handle RST flag specially - it always causes transition to closed
	if flags&TCPRst != 0 {
		if conn.IsTombstone() {
			return true
		}

		conn.Lock()
		conn.SetTombstone()
		conn.State = TCPStateClosed
		conn.SetEstablished(false)
		conn.Unlock()

		t.logger.Trace("TCP connection reset: %s", key)
		t.sendEvent(nftypes.TypeEnd, key, conn, nil)
		return true
	}

	conn.Lock()
	t.updateState(key, conn, flags, false)
	conn.UpdateLastSeen()
	isEstablished := conn.IsEstablished()
	isValidState := t.isValidStateForFlags(conn.State, flags)
	conn.Unlock()

	return isEstablished || isValidState
}

// updateState updates the TCP connection state based on flags
func (t *TCPTracker) updateState(key ConnKey, conn *TCPConnTrack, flags uint8, isOutbound bool) {
	state := conn.State
	defer func() {
		if state != conn.State {
			t.logger.Trace("TCP connection %s transitioned from %s to %s", key, state, conn.State)
		}
	}()

	switch state {
	case TCPStateNew:
		if flags&TCPSyn != 0 && flags&TCPAck == 0 {
			conn.State = TCPStateSynSent
		}

	case TCPStateSynSent:
		if flags&TCPSyn != 0 && flags&TCPAck != 0 {
			if isOutbound {
				conn.State = TCPStateEstablished
				conn.SetEstablished(true)
			} else {
				// Simultaneous open
				conn.State = TCPStateSynReceived
			}
		}

	case TCPStateSynReceived:
		if flags&TCPAck != 0 && flags&TCPSyn == 0 {
			conn.State = TCPStateEstablished
			conn.SetEstablished(true)
		}

	case TCPStateEstablished:
		if flags&TCPFin != 0 {
			if isOutbound {
				conn.State = TCPStateFinWait1
			} else {
				conn.State = TCPStateCloseWait
			}
			conn.SetEstablished(false)
		} else if flags&TCPRst != 0 {
			conn.State = TCPStateClosed
			conn.SetTombstone()
			t.sendEvent(nftypes.TypeEnd, key, conn)
		}

	case TCPStateFinWait1:
		switch {
		case flags&TCPFin != 0 && flags&TCPAck != 0:
			conn.State = TCPStateClosing
		case flags&TCPFin != 0:
			conn.State = TCPStateFinWait2
		case flags&TCPAck != 0:
			conn.State = TCPStateFinWait2
		case flags&TCPRst != 0:
			conn.State = TCPStateClosed
			conn.SetTombstone()
			t.sendEvent(nftypes.TypeEnd, key, conn)
		}

	case TCPStateFinWait2:
		if flags&TCPFin != 0 {
			conn.State = TCPStateTimeWait

			t.logger.Trace("TCP connection %s completed", key)
			t.sendEvent(nftypes.TypeEnd, key, conn, nil)
		}

	case TCPStateClosing:
		if flags&TCPAck != 0 {
			conn.State = TCPStateTimeWait
			// Keep established = false from previous state

			t.logger.Trace("TCP connection %s closed (simultaneous)", key)
			t.sendEvent(nftypes.TypeEnd, key, conn, nil)
		}

	case TCPStateCloseWait:
		if flags&TCPFin != 0 {
			conn.State = TCPStateLastAck
		}

	case TCPStateLastAck:
		if flags&TCPAck != 0 {
			conn.State = TCPStateClosed
			conn.SetTombstone()

			// Send close event for gracefully closed connections
			t.sendEvent(nftypes.TypeEnd, key, conn, nil)
			t.logger.Trace("TCP connection %s closed gracefully", key)
		}
	}
}

// isValidStateForFlags checks if the TCP flags are valid for the current connection state
func (t *TCPTracker) isValidStateForFlags(state TCPState, flags uint8) bool {
	if !isValidFlagCombination(flags) {
		return false
	}

	switch state {
	case TCPStateNew:
		return flags&TCPSyn != 0 && flags&TCPAck == 0
	case TCPStateSynSent:
		return flags&TCPSyn != 0 && flags&TCPAck != 0
	case TCPStateSynReceived:
		return flags&TCPAck != 0
	case TCPStateEstablished:
		if flags&TCPRst != 0 {
			return true
		}
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
		// Accept retransmitted ACKs in closed state
		// This is important because the final ACK might be lost
		// and the peer will retransmit their FIN-ACK
		return flags&TCPAck != 0
	}
	return false
}

func (t *TCPTracker) cleanupRoutine() {
	for {
		select {
		case <-t.cleanupTicker.C:
			t.cleanup()
		case <-t.done:
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
		switch {
		case conn.State == TCPStateTimeWait:
			timeout = TimeWaitTimeout
		case conn.IsEstablished():
			timeout = t.timeout
		default:
			timeout = TCPHandshakeTimeout
		}

		if conn.timeoutExceeded(timeout) {
			// Return IPs to pool
			delete(t.connections, key)

			t.logger.Trace("Cleaned up timed-out TCP connection %s", &key)

			// event already handled by state change
			if conn.State != TCPStateTimeWait {
				t.sendEvent(nftypes.TypeEnd, key, conn, nil)
			}
		}
	}
}

// Close stops the cleanup routine and releases resources
func (t *TCPTracker) Close() {
	t.cleanupTicker.Stop()
	close(t.done)

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

func (t *TCPTracker) sendEvent(typ nftypes.Type, key ConnKey, conn *TCPConnTrack, ruleID []byte) {
	t.flowLogger.StoreEvent(nftypes.EventFields{
		FlowID:     conn.FlowId,
		Type:       typ,
		RuleID:     ruleID,
		Direction:  conn.Direction,
		Protocol:   nftypes.TCP,
		SourceIP:   key.SrcIP,
		DestIP:     key.DstIP,
		SourcePort: key.SrcPort,
		DestPort:   key.DstPort,
	})
}
