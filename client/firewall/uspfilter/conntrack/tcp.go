package conntrack

// TODO: Send RST packets for invalid/timed-out connections

import (
	"net"
	"slices"
	"sync"
	"time"
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
	SourceIP    net.IP
	DestIP      net.IP
	SourcePort  uint16
	DestPort    uint16
	State       TCPState
	LastSeen    time.Time
	established bool
}

// TCPTracker manages TCP connection states
type TCPTracker struct {
	connections   map[TCPConnKey]*TCPConnTrack
	mutex         sync.RWMutex
	cleanupTicker *time.Ticker
	done          chan struct{}
	timeout       time.Duration
}

// NewTCPTracker creates a new TCP connection tracker
func NewTCPTracker(timeout time.Duration) *TCPTracker {
	tracker := &TCPTracker{
		connections:   make(map[TCPConnKey]*TCPConnTrack),
		cleanupTicker: time.NewTicker(TCPCleanupInterval),
		done:          make(chan struct{}),
		timeout:       timeout,
	}

	go tracker.cleanupRoutine()
	return tracker
}

// TrackOutbound processes an outbound TCP packet and updates connection state
func (t *TCPTracker) TrackOutbound(srcIP net.IP, dstIP net.IP, srcPort uint16, dstPort uint16, flags uint8) {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	key := makeTCPKey(srcIP, dstIP, srcPort, dstPort)
	now := time.Now()

	conn, exists := t.connections[key]
	if !exists {
		conn = &TCPConnTrack{
			SourceIP:    slices.Clone(srcIP),
			DestIP:      slices.Clone(dstIP),
			SourcePort:  srcPort,
			DestPort:    dstPort,
			State:       TCPStateNew,
			LastSeen:    now,
			established: false,
		}
		t.connections[key] = conn
	}

	// Update connection state based on TCP flags
	t.updateState(conn, flags, true)
	conn.LastSeen = now
}

// IsValidInbound checks if an inbound TCP packet matches a tracked connection
func (t *TCPTracker) IsValidInbound(srcIP net.IP, dstIP net.IP, srcPort uint16, dstPort uint16, flags uint8) bool {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	// For SYN packets (new connection attempts), always allow
	if flags&TCPSyn != 0 && flags&TCPAck == 0 {
		key := makeTCPKey(dstIP, srcIP, dstPort, srcPort)
		t.connections[key] = &TCPConnTrack{
			SourceIP:    slices.Clone(dstIP),
			DestIP:      slices.Clone(srcIP),
			SourcePort:  dstPort,
			DestPort:    srcPort,
			State:       TCPStateSynReceived,
			LastSeen:    time.Now(),
			established: false,
		}
		return true
	}

	key := makeTCPKey(dstIP, srcIP, dstPort, srcPort)
	conn, exists := t.connections[key]
	if !exists {
		return false
	}

	// Update state and check validity
	if flags&TCPRst != 0 {
		conn.State = TCPStateClosed
		conn.established = false
		return true
	}

	// Special handling for FIN state
	if conn.State == TCPStateFinWait1 || conn.State == TCPStateFinWait2 {
		t.updateState(conn, flags, false)
		conn.LastSeen = time.Now()
		return true
	}

	t.updateState(conn, flags, false)
	conn.LastSeen = time.Now()

	// Allow if established or in a valid state for the flags
	return conn.established || t.isValidStateForFlags(conn.State, flags)
}

// updateState updates the TCP connection state based on flags
func (t *TCPTracker) updateState(conn *TCPConnTrack, flags uint8, isOutbound bool) {
	// Handle RST flag specially - it always causes transition to closed
	if flags&TCPRst != 0 {
		conn.State = TCPStateClosed
		conn.established = false
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
				conn.established = true
			}
		}

	case TCPStateSynReceived:
		if flags&TCPAck != 0 && flags&TCPSyn == 0 {
			conn.State = TCPStateEstablished
			conn.established = true
		}

	case TCPStateEstablished:
		if flags&TCPFin != 0 {
			if isOutbound {
				conn.State = TCPStateFinWait1
			} else {
				conn.State = TCPStateCloseWait
			}
			conn.established = false
		}

	case TCPStateFinWait1:
		if flags&TCPFin != 0 && flags&TCPAck != 0 {
			// Simultaneous close
			conn.State = TCPStateClosing
		} else if flags&TCPFin != 0 {
			conn.State = TCPStateFinWait2
		} else if flags&TCPAck != 0 {
			conn.State = TCPStateFinWait2
		}

	case TCPStateFinWait2:
		if flags&TCPFin != 0 {
			conn.State = TCPStateTimeWait
		}

	case TCPStateClosing:
		if flags&TCPAck != 0 {
			conn.State = TCPStateTimeWait
		}

	case TCPStateCloseWait:
		if flags&TCPFin != 0 {
			conn.State = TCPStateLastAck
		}

	case TCPStateLastAck:
		if flags&TCPAck != 0 {
			conn.State = TCPStateClosed
		}

	case TCPStateTimeWait:
		// Stay in TIME-WAIT for 2MSL before transitioning to closed
		// This is handled by the cleanup routine
	}
}

// isValidStateForFlags checks if the TCP flags are valid for the current connection state
func (t *TCPTracker) isValidStateForFlags(state TCPState, flags uint8) bool {
	switch state {
	case TCPStateSynSent:
		return flags&TCPSyn != 0 && flags&TCPAck != 0
	case TCPStateSynReceived:
		return flags&TCPAck != 0
	case TCPStateEstablished:
		return true // Allow all flags in established state
	case TCPStateFinWait1, TCPStateFinWait2:
		return flags&TCPFin != 0 || flags&TCPAck != 0
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

	now := time.Now()
	for key, conn := range t.connections {
		var timeout time.Duration
		switch {
		case conn.State == TCPStateTimeWait:
			timeout = TimeWaitTimeout
		case conn.established:
			timeout = t.timeout
		default:
			timeout = TCPHandshakeTimeout
		}

		if now.Sub(conn.LastSeen) > timeout {
			delete(t.connections, key)
		}
	}
}

// Close stops the cleanup routine and releases resources
func (t *TCPTracker) Close() {
	t.cleanupTicker.Stop()
	close(t.done)
}

func makeTCPKey(srcIP net.IP, dstIP net.IP, srcPort uint16, dstPort uint16) TCPConnKey {
	var srcAddr, dstAddr [16]byte
	copy(srcAddr[:], srcIP.To16())
	copy(dstAddr[:], dstIP.To16())
	return TCPConnKey{
		SrcIP:   srcAddr,
		DstIP:   dstAddr,
		SrcPort: srcPort,
		DstPort: dstPort,
	}
}
