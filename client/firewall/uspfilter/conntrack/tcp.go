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
	// FinWaitTimeout bounds FIN_WAIT_1 / FIN_WAIT_2 / CLOSING states.
	// Matches Linux netfilter nf_conntrack_tcp_timeout_fin_wait.
	FinWaitTimeout = 60 * time.Second
	// CloseWaitTimeout bounds CLOSE_WAIT. Matches Linux default; apps
	// holding CloseWait longer than this should bump the env var.
	CloseWaitTimeout = 60 * time.Second
	// LastAckTimeout bounds LAST_ACK. Matches Linux default.
	LastAckTimeout = 30 * time.Second
)

// Env vars to override per-state teardown timeouts. Values parsed by
// time.ParseDuration (e.g. "120s", "2m"). Invalid values fall back to the
// defaults above with a warning.
const (
	EnvTCPFinWaitTimeout   = "NB_CONNTRACK_TCP_FIN_WAIT_TIMEOUT"
	EnvTCPCloseWaitTimeout = "NB_CONNTRACK_TCP_CLOSE_WAIT_TIMEOUT"
	EnvTCPLastAckTimeout   = "NB_CONNTRACK_TCP_LAST_ACK_TIMEOUT"

	// EnvTCPMaxEntries caps the TCP conntrack table size. Oldest entries
	// (tombstones first) are evicted when the cap is reached.
	EnvTCPMaxEntries = "NB_CONNTRACK_TCP_MAX"
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
	logger           *nblog.Logger
	connections      map[ConnKey]*TCPConnTrack
	mutex            sync.RWMutex
	cleanupTicker    *time.Ticker
	tickerCancel     context.CancelFunc
	timeout          time.Duration
	waitTimeout      time.Duration
	finWaitTimeout   time.Duration
	closeWaitTimeout time.Duration
	lastAckTimeout   time.Duration
	maxEntries       int
	flowLogger       nftypes.FlowLogger
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
		logger:           logger,
		connections:      make(map[ConnKey]*TCPConnTrack),
		cleanupTicker:    time.NewTicker(TCPCleanupInterval),
		tickerCancel:     cancel,
		timeout:          timeout,
		waitTimeout:      waitTimeout,
		finWaitTimeout:   envDuration(logger, EnvTCPFinWaitTimeout, FinWaitTimeout),
		closeWaitTimeout: envDuration(logger, EnvTCPCloseWaitTimeout, CloseWaitTimeout),
		lastAckTimeout:   envDuration(logger, EnvTCPLastAckTimeout, LastAckTimeout),
		maxEntries:       envInt(logger, EnvTCPMaxEntries, DefaultMaxTCPEntries),
		flowLogger:       flowLogger,
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
	// Reject illegal SYN combinations (SYN+FIN, SYN+RST, …) so they don't
	// create spurious conntrack entries. Not mandated by RFC 9293 but a
	// common hardening (Linux netfilter/nftables rejects these too).
	if !isValidFlagCombination(flags) {
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

	if t.logger.Enabled(nblog.LevelTrace) {
		if origPort != 0 {
			t.logger.Trace4("New %s TCP connection: %s (port DNAT %d -> %d)", direction, key, origPort, dstPort)
		} else {
			t.logger.Trace2("New %s TCP connection: %s", direction, key)
		}
	}
	t.updateState(key, conn, flags, direction, size)

	t.mutex.Lock()
	if t.maxEntries > 0 && len(t.connections) >= t.maxEntries {
		t.evictOneLocked()
	}
	t.connections[key] = conn
	t.mutex.Unlock()

	t.sendEvent(nftypes.TypeStart, conn, ruleID)
}

// evictOneLocked removes one entry to make room. Caller must hold t.mutex.
// Bounded scan: samples up to evictSampleSize pseudo-random entries (Go map
// iteration order is randomized), preferring a tombstone. If no tombstone
// found in the sample, evicts the oldest among the sampled entries. O(1)
// worst case — cheap enough to run on every insert at cap during abuse.
func (t *TCPTracker) evictOneLocked() {
	var candKey ConnKey
	var candSeen int64
	haveCand := false
	sampled := 0

	for k, c := range t.connections {
		if c.IsTombstone() {
			delete(t.connections, k)
			return
		}
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
			// TypeEnd is already emitted at the state transition to
			// TimeWait and when a connection is tombstoned. Only emit
			// here when we're reaping a still-active flow.
			if evicted.GetState() != TCPStateTimeWait && !evicted.IsTombstone() {
				t.sendEvent(nftypes.TypeEnd, evicted, nil)
			}
		}
		delete(t.connections, candKey)
	}
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

	// Reject illegal flag combinations regardless of state. These never belong
	// to a legitimate flow and must not advance or tear down state.
	if !isValidFlagCombination(flags) {
		if t.logger.Enabled(nblog.LevelWarn) {
			t.logger.Warn3("TCP illegal flag combination %x for connection %s (state %s)", flags, key, conn.GetState())
		}
		return false
	}

	currentState := conn.GetState()
	if !t.isValidStateForFlags(currentState, flags) {
		if t.logger.Enabled(nblog.LevelWarn) {
			t.logger.Warn3("TCP state %s is not valid with flags %x for connection %s", currentState, flags, key)
		}
		return false
	}

	t.updateState(key, conn, flags, nftypes.Ingress, size)
	return true
}

// updateState updates the TCP connection state based on flags.
func (t *TCPTracker) updateState(key ConnKey, conn *TCPConnTrack, flags uint8, packetDir nftypes.Direction, size int) {
	conn.UpdateCounters(packetDir, size)

	// Malformed flag combinations must not refresh lastSeen or drive state,
	// otherwise spoofed packets keep a dead flow alive past its timeout.
	if !isValidFlagCombination(flags) {
		return
	}

	conn.UpdateLastSeen()

	currentState := conn.GetState()

	if flags&TCPRst != 0 {
		// Hardening beyond RFC 9293 §3.10.7.4: without sequence tracking we
		// cannot apply the RFC 5961 in-window RST check, so we conservatively
		// reject RSTs that the spec would accept (TIME-WAIT with in-window
		// SEQ, SynSent from same direction as own SYN, etc.).
		t.handleRst(key, conn, currentState, packetDir)
		return
	}

	newState := nextState(currentState, conn.Direction, packetDir, flags)
	if newState == 0 || !conn.CompareAndSwapState(currentState, newState) {
		return
	}
	t.onTransition(key, conn, currentState, newState, packetDir)
}

// handleRst processes a RST segment. Late RSTs in TimeWait and spoofed RSTs
// from the SYN direction are ignored; otherwise the flow is tombstoned.
func (t *TCPTracker) handleRst(key ConnKey, conn *TCPConnTrack, currentState TCPState, packetDir nftypes.Direction) {
	// TimeWait exists to absorb late segments; don't let a late RST
	// tombstone the entry and break same-4-tuple reuse.
	if currentState == TCPStateTimeWait {
		return
	}
	// A RST from the same direction as the SYN cannot be a legitimate
	// response and must not tear down a half-open connection.
	if currentState == TCPStateSynSent && packetDir == conn.Direction {
		return
	}
	if !conn.CompareAndSwapState(currentState, TCPStateClosed) {
		return
	}
	conn.SetTombstone()
	if t.logger.Enabled(nblog.LevelTrace) {
		t.logger.Trace6("TCP connection reset: %s (dir: %s) [in: %d Pkts/%d B, out: %d Pkts/%d B]",
			key, packetDir, conn.PacketsRx.Load(), conn.BytesRx.Load(), conn.PacketsTx.Load(), conn.BytesTx.Load())
	}
	t.sendEvent(nftypes.TypeEnd, conn, nil)
}

// stateTransition describes one state's transition logic. It receives the
// packet's flags plus whether the packet direction matches the connection's
// origin direction (same=true means same side as the SYN initiator). Return 0
// for no transition.
type stateTransition func(flags uint8, connDir nftypes.Direction, same bool) TCPState

// stateTable maps each state to its transition function. Centralized here so
// nextState stays trivial and each rule is easy to read in isolation.
var stateTable = map[TCPState]stateTransition{
	TCPStateNew:         transNew,
	TCPStateSynSent:     transSynSent,
	TCPStateSynReceived: transSynReceived,
	TCPStateEstablished: transEstablished,
	TCPStateFinWait1:    transFinWait1,
	TCPStateFinWait2:    transFinWait2,
	TCPStateClosing:     transClosing,
	TCPStateCloseWait:   transCloseWait,
	TCPStateLastAck:     transLastAck,
}

// nextState returns the target TCP state for the given current state and
// packet, or 0 if the packet does not trigger a transition.
func nextState(currentState TCPState, connDir, packetDir nftypes.Direction, flags uint8) TCPState {
	fn, ok := stateTable[currentState]
	if !ok {
		return 0
	}
	return fn(flags, connDir, packetDir == connDir)
}

func transNew(flags uint8, connDir nftypes.Direction, _ bool) TCPState {
	if flags&TCPSyn != 0 && flags&TCPAck == 0 {
		if connDir == nftypes.Egress {
			return TCPStateSynSent
		}
		return TCPStateSynReceived
	}
	return 0
}

func transSynSent(flags uint8, _ nftypes.Direction, same bool) TCPState {
	if flags&TCPSyn != 0 && flags&TCPAck != 0 {
		if same {
			return TCPStateSynReceived // simultaneous open
		}
		return TCPStateEstablished
	}
	return 0
}

func transSynReceived(flags uint8, _ nftypes.Direction, same bool) TCPState {
	if flags&TCPAck != 0 && flags&TCPSyn == 0 && same {
		return TCPStateEstablished
	}
	return 0
}

func transEstablished(flags uint8, _ nftypes.Direction, same bool) TCPState {
	if flags&TCPFin == 0 {
		return 0
	}
	if same {
		return TCPStateFinWait1
	}
	return TCPStateCloseWait
}

// transFinWait1 handles the active-close peer response. A FIN carrying our
// ACK piggybacked goes straight to TIME-WAIT (RFC 9293 §3.10.7.4, FIN-WAIT-1:
// "if our FIN has been ACKed... enter the TIME-WAIT state"); a lone FIN moves
// to CLOSING; a pure ACK of our FIN moves to FIN-WAIT-2.
func transFinWait1(flags uint8, _ nftypes.Direction, same bool) TCPState {
	if same {
		return 0
	}
	if flags&TCPFin != 0 && flags&TCPAck != 0 {
		return TCPStateTimeWait
	}
	switch {
	case flags&TCPFin != 0:
		return TCPStateClosing
	case flags&TCPAck != 0:
		return TCPStateFinWait2
	}
	return 0
}

// transFinWait2 ignores own-side FIN retransmits; only the peer's FIN advances.
func transFinWait2(flags uint8, _ nftypes.Direction, same bool) TCPState {
	if flags&TCPFin != 0 && !same {
		return TCPStateTimeWait
	}
	return 0
}

// transClosing completes a simultaneous close on the peer's ACK.
func transClosing(flags uint8, _ nftypes.Direction, same bool) TCPState {
	if flags&TCPAck != 0 && !same {
		return TCPStateTimeWait
	}
	return 0
}

// transCloseWait only advances to LastAck when WE send FIN, ignoring peer retransmits.
func transCloseWait(flags uint8, _ nftypes.Direction, same bool) TCPState {
	if flags&TCPFin != 0 && same {
		return TCPStateLastAck
	}
	return 0
}

// transLastAck closes the flow only on the peer's ACK (not our own ACK retransmits).
func transLastAck(flags uint8, _ nftypes.Direction, same bool) TCPState {
	if flags&TCPAck != 0 && !same {
		return TCPStateClosed
	}
	return 0
}

// onTransition handles logging and flow-event emission after a successful
// state transition. TimeWait and Closed are terminal for flow accounting.
func (t *TCPTracker) onTransition(key ConnKey, conn *TCPConnTrack, from, to TCPState, packetDir nftypes.Direction) {
	traceOn := t.logger.Enabled(nblog.LevelTrace)
	if traceOn {
		t.logger.Trace4("TCP connection %s transitioned from %s to %s (dir: %s)", key, from, to, packetDir)
	}

	switch to {
	case TCPStateTimeWait:
		if traceOn {
			t.logger.Trace5("TCP connection %s completed [in: %d Pkts/%d B, out: %d Pkts/%d B]",
				key, conn.PacketsRx.Load(), conn.BytesRx.Load(), conn.PacketsTx.Load(), conn.BytesTx.Load())
		}
		t.sendEvent(nftypes.TypeEnd, conn, nil)
	case TCPStateClosed:
		conn.SetTombstone()
		if traceOn {
			t.logger.Trace5("TCP connection %s closed gracefully [in: %d Pkts/%d, B out: %d Pkts/%d B]",
				key, conn.PacketsRx.Load(), conn.BytesRx.Load(), conn.PacketsTx.Load(), conn.BytesTx.Load())
		}
		t.sendEvent(nftypes.TypeEnd, conn, nil)
	}
}

// isValidStateForFlags checks if the TCP flags are valid for the current
// connection state. Caller must have already verified the flag combination is
// legal via isValidFlagCombination.
func (t *TCPTracker) isValidStateForFlags(state TCPState, flags uint8) bool {
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
		case TCPStateFinWait1, TCPStateFinWait2, TCPStateClosing:
			timeout = t.finWaitTimeout
		case TCPStateCloseWait:
			timeout = t.closeWaitTimeout
		case TCPStateLastAck:
			timeout = t.lastAckTimeout
		default:
			// SynSent / SynReceived / New
			timeout = TCPHandshakeTimeout
		}

		if conn.timeoutExceeded(timeout) {
			delete(t.connections, key)

			if t.logger.Enabled(nblog.LevelTrace) {
				t.logger.Trace6("Cleaned up timed-out TCP connection %s (%s) [in: %d Pkts/%d, B out: %d Pkts/%d B]",
					key, conn.GetState(), conn.PacketsRx.Load(), conn.BytesRx.Load(), conn.PacketsTx.Load(), conn.BytesTx.Load())
			}

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
