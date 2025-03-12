package conntrack

// TODO: Send RST packets for invalid/timed-out connections

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"time"

	nblog "github.com/netbirdio/netbird/client/firewall/uspfilter/log"
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

// TCPConnKey uniquely identifies a TCP connection
type TCPConnKey struct {
	SrcIP   [16]byte
	DstIP   [16]byte
	SrcPort uint16
	DstPort uint16
}

// TCPConnTrack represents a TCP connection state
type TCPConnTrack struct {
	BaseConnTrack
	State       TCPState
	established atomic.Bool
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

// TCPTracker manages TCP connection states
type TCPTracker struct {
	logger        *nblog.Logger
	connections   map[ConnKey]*TCPConnTrack
	mutex         sync.RWMutex
	cleanupTicker *time.Ticker
	tickerCancel  context.CancelFunc
	timeout       time.Duration
	ipPool        *PreallocatedIPs
}

// NewTCPTracker creates a new TCP connection tracker
func NewTCPTracker(timeout time.Duration, logger *nblog.Logger) *TCPTracker {

	ctx, cancel := context.WithCancel(context.Background())

	tracker := &TCPTracker{
		logger:        logger,
		connections:   make(map[ConnKey]*TCPConnTrack),
		cleanupTicker: time.NewTicker(TCPCleanupInterval),
		tickerCancel:  cancel,
		timeout:       timeout,
		ipPool:        NewPreallocatedIPs(),
	}

	go tracker.cleanupRoutine(ctx)
	return tracker
}

// TrackOutbound processes an outbound TCP packet and updates connection state
func (t *TCPTracker) TrackOutbound(srcIP net.IP, dstIP net.IP, srcPort uint16, dstPort uint16, flags uint8) {
	// Create key before lock
	key := makeConnKey(srcIP, dstIP, srcPort, dstPort)

	t.mutex.Lock()
	conn, exists := t.connections[key]
	if !exists {
		// Use preallocated IPs
		srcIPCopy := t.ipPool.Get()
		dstIPCopy := t.ipPool.Get()
		copyIP(srcIPCopy, srcIP)
		copyIP(dstIPCopy, dstIP)

		conn = &TCPConnTrack{
			BaseConnTrack: BaseConnTrack{
				SourceIP:   srcIPCopy,
				DestIP:     dstIPCopy,
				SourcePort: srcPort,
				DestPort:   dstPort,
			},
			State: TCPStateNew,
		}
		conn.UpdateLastSeen()
		conn.established.Store(false)
		t.connections[key] = conn

		t.logger.Trace("New TCP connection: %s:%d -> %s:%d", srcIP, srcPort, dstIP, dstPort)
	}
	t.mutex.Unlock()

	// Lock individual connection for state update
	conn.Lock()
	t.updateState(conn, flags, true)
	conn.Unlock()
	conn.UpdateLastSeen()
}

// IsValidInbound checks if an inbound TCP packet matches a tracked connection
func (t *TCPTracker) IsValidInbound(srcIP net.IP, dstIP net.IP, srcPort uint16, dstPort uint16, flags uint8) bool {
	if !isValidFlagCombination(flags) {
		return false
	}

	key := makeConnKey(dstIP, srcIP, dstPort, srcPort)

	t.mutex.RLock()
	conn, exists := t.connections[key]
	t.mutex.RUnlock()

	if !exists {
		return false
	}

	// Handle RST packets
	if flags&TCPRst != 0 {
		conn.Lock()
		if conn.IsEstablished() || conn.State == TCPStateSynSent || conn.State == TCPStateSynReceived {
			conn.State = TCPStateClosed
			conn.SetEstablished(false)
			conn.Unlock()
			return true
		}
		conn.Unlock()
		return false
	}

	conn.Lock()
	t.updateState(conn, flags, false)
	conn.UpdateLastSeen()
	isEstablished := conn.IsEstablished()
	isValidState := t.isValidStateForFlags(conn.State, flags)
	conn.Unlock()

	return isEstablished || isValidState
}

// updateState updates the TCP connection state based on flags
func (t *TCPTracker) updateState(conn *TCPConnTrack, flags uint8, isOutbound bool) {
	// Handle RST flag specially - it always causes transition to closed
	if flags&TCPRst != 0 {
		conn.State = TCPStateClosed
		conn.SetEstablished(false)

		t.logger.Trace("TCP connection reset: %s:%d -> %s:%d",
			conn.SourceIP, conn.SourcePort, conn.DestIP, conn.DestPort)
		return
	}

	switch conn.State {
	case TCPStateNew:
		if flags&TCPSyn != 0 && flags&TCPAck == 0 {
			conn.State = TCPStateSynSent
		}

	case TCPStateSynSent:
		if flags&TCPSyn != 0 && flags&TCPAck != 0 {
			if isOutbound {
				conn.State = TCPStateSynReceived
			} else {
				// Simultaneous open
				conn.State = TCPStateEstablished
				conn.SetEstablished(true)
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
		}

	case TCPStateFinWait1:
		switch {
		case flags&TCPFin != 0 && flags&TCPAck != 0:
			// Simultaneous close - both sides sent FIN
			conn.State = TCPStateClosing
		case flags&TCPFin != 0:
			conn.State = TCPStateFinWait2
		case flags&TCPAck != 0:
			conn.State = TCPStateFinWait2
		}

	case TCPStateFinWait2:
		if flags&TCPFin != 0 {
			conn.State = TCPStateTimeWait
		}

	case TCPStateClosing:
		if flags&TCPAck != 0 {
			conn.State = TCPStateTimeWait
			// Keep established = false from previous state

			t.logger.Trace("TCP connection closed (simultaneous) - %s:%d -> %s:%d",
				conn.SourceIP, conn.SourcePort, conn.DestIP, conn.DestPort)
		}

	case TCPStateCloseWait:
		if flags&TCPFin != 0 {
			conn.State = TCPStateLastAck
		}

	case TCPStateLastAck:
		if flags&TCPAck != 0 {
			conn.State = TCPStateClosed

			t.logger.Trace("TCP connection gracefully closed: %s:%d -> %s:%d",
				conn.SourceIP, conn.SourcePort, conn.DestIP, conn.DestPort)
		}

	case TCPStateTimeWait:
		// Stay in TIME-WAIT for 2MSL before transitioning to closed
		// This is handled by the cleanup routine

		t.logger.Trace("TCP connection completed - %s:%d -> %s:%d",
			conn.SourceIP, conn.SourcePort, conn.DestIP, conn.DestPort)
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
		var timeout time.Duration
		switch {
		case conn.State == TCPStateTimeWait:
			timeout = TimeWaitTimeout
		case conn.IsEstablished():
			timeout = t.timeout
		default:
			timeout = TCPHandshakeTimeout
		}

		lastSeen := conn.GetLastSeen()
		if time.Since(lastSeen) > timeout {
			// Return IPs to pool
			t.ipPool.Put(conn.SourceIP)
			t.ipPool.Put(conn.DestIP)
			delete(t.connections, key)

			t.logger.Trace("Cleaned up TCP connection: %s:%d -> %s:%d", conn.SourceIP, conn.SourcePort, conn.DestIP, conn.DestPort)
		}
	}
}

// Close stops the cleanup routine and releases resources
func (t *TCPTracker) Close() {
	t.tickerCancel()

	// Clean up all remaining IPs
	t.mutex.Lock()
	for _, conn := range t.connections {
		t.ipPool.Put(conn.SourceIP)
		t.ipPool.Put(conn.DestIP)
	}
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
