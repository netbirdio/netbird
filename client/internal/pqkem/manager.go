package pqkem

import (
	"context"
	"crypto/rand"
	"fmt"
	"log/slog"
	"net/netip"
	"sync"
	"time"
)

const (
	// DefaultRetryInterval is how often the initiator retransmits its outstanding
	// data-path offer while awaiting the answer.
	DefaultRetryInterval = 2 * time.Second
	// DefaultMaxRetries bounds how many ticks an exchange may run before it is
	// declared failed. The convergence deadline is thus MaxRetries * RetryInterval.
	DefaultMaxRetries = 10
	// DefaultMaxRekeyFailures is how many consecutive rekey (non-initial) failures
	// are tolerated before OnRekeyFailed. The initial exchange fails immediately.
	DefaultMaxRekeyFailures = 3

	// rotationActivityWindow gates rotation on recent real-data activity: a rekey
	// clocks a rotation only if the peer exchanged user data within this window. It
	// must stay shorter than the data path's rekey interval (WireGuard
	// REKEY_AFTER_TIME ~120s) so the rotation's own traffic — which itself renews the
	// activity signal — ages out before the next rekey, letting an idle tunnel stop
	// rotating instead of self-sustaining.
	rotationActivityWindow = 90 * time.Second
)

// LocalID and RemoteID are peer identity keys (e.g. WireGuard public keys). They are
// distinct types so the local and a remote identity cannot be mixed up.
type (
	LocalID  string
	RemoteID string
)

// Transport is the data-path socket the Manager drives (the analogue of
// go-rosenpass's Conn). It is a dumb mover of bytes to/from endpoints: the Manager
// owns the remoteID<->endpoint routing and hands the transport a resolved endpoint
// to Send, and reverse-resolves the source of each inbound datagram. Its lifecycle
// belongs to the Manager (Run at Start, Close at Stop).
type Transport interface {
	// Send delivers msg to the given data-path endpoint.
	Send(endpoint netip.AddrPort, msg []byte) error
	// LocalPort is the bound local UDP port, announced to peers so they know where
	// to send data-path messages.
	LocalPort() int
	// Run starts delivering inbound datagrams as (source endpoint, msg) to onInbound
	// and returns immediately; it runs until Close.
	Run(onInbound func(src netip.AddrPort, msg []byte))
	// Close stops delivery and releases the socket.
	Close() error
}

// exchangeState is the single source of truth for an exchange's role and phase.
type exchangeState uint8

const (
	stateReserved       exchangeState = iota // responder: deriving the answer
	stateAwaitingAnswer                      // initiator: offer sent, awaiting the answer
	stateAwaitingRekey                       // initiator: PSK derived+set, awaiting OnDataPathRekeyed to chain the next offer
	stateAwaitingAck                         // responder: answer sent, awaiting the next offer that acks this exchange
)

// exchangeCtl holds all state for one in-flight exchange with a peer, under the
// Manager's single lock. state drives every decision. lastSent is the current
// data-path retransmit payload (the offer, for the initiator). initiator is the
// ephemeral handle used at Finish; pendingPSK is the responder's derived key.
// viaSignal records that the offer went to the host for the signalling channel, so
// the loop does not retransmit it on the data path. Only the initiator runs a
// retransmit loop, so only it sets cancel.
type exchangeCtl struct {
	id         ExchangeID
	state      exchangeState
	startedAt  time.Time
	cancel     context.CancelFunc
	lastSent   []byte
	initiator  *Initiator
	pendingPSK PSK
	viaSignal  bool
}

// Manager is the stateful orchestrator — the analogue of go-rosenpass's Server. It
// drives the X25519MLKEM768 exchange, owns the peer endpoint routing and the data-path
// transport, and surfaces the derived PSK and convergence to the host via
// CallbackHandler. It is event-driven: the bootstrap is triggered by the host
// (SignalOffer) and each rotation is clocked by OnDataPathRekeyed. The cryptography is
// the pure kem.go primitives; all state lives here under one lock.
type Manager struct {
	localID   LocalID
	cbHandler CallbackHandler
	logger    *slog.Logger

	retryInterval    time.Duration
	maxRetries       int
	maxRekeyFailures int

	rootCtx    context.Context
	rootCancel context.CancelFunc

	mu          sync.Mutex
	transport   Transport
	exchanges   map[RemoteID]*exchangeCtl   // in-flight exchange per peer
	established map[RemoteID]bool           // peer has completed at least one exchange
	failures    map[RemoteID]int            // consecutive rekey failures per peer
	psks        map[RemoteID]PSK            // latest derived PSK per peer (pulled at WG peer-config time)
	capable     map[RemoteID]bool           // peer runs the KEM (advertised a PQ port); false = known non-capable
	peerAddrs   map[RemoteID]netip.AddrPort // remoteID -> data-path endpoint (send routing)
	peersByAddr map[netip.AddrPort]RemoteID // reverse: source endpoint -> remoteID (inbound)
	wait        sync.WaitGroup
}

// NewManager builds a manager for the local peer identified by its peer identity key
// (used for the deterministic initiator role and the identity binding). A nil logger
// falls back to slog.Default(). Install the data-path transport with Start.
func NewManager(localID LocalID, h CallbackHandler, logger *slog.Logger) *Manager {
	if logger == nil {
		logger = slog.Default()
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Manager{
		localID:          localID,
		cbHandler:        h,
		logger:           logger,
		retryInterval:    DefaultRetryInterval,
		maxRetries:       DefaultMaxRetries,
		maxRekeyFailures: DefaultMaxRekeyFailures,
		rootCtx:          ctx,
		rootCancel:       cancel,
		exchanges:        make(map[RemoteID]*exchangeCtl),
		established:      make(map[RemoteID]bool),
		failures:         make(map[RemoteID]int),
		psks:             make(map[RemoteID]PSK),
		capable:          make(map[RemoteID]bool),
		peerAddrs:        make(map[RemoteID]netip.AddrPort),
		peersByAddr:      make(map[netip.AddrPort]RemoteID),
	}
}

// Start installs the data-path transport and begins its inbound delivery. The Manager
// owns it from here; Stop closes it.
func (m *Manager) Start(t Transport) {
	m.mu.Lock()
	m.transport = t
	m.mu.Unlock()
	if t != nil {
		t.Run(m.onDataPathInbound)
	}
}

// LocalPort is the data-path transport's bound UDP port (0 if no transport), to be
// announced to peers.
func (m *Manager) LocalPort() int {
	m.mu.Lock()
	t := m.transport
	m.mu.Unlock()
	if t == nil {
		return 0
	}
	return t.LocalPort()
}

// IsInitiator reports whether the local peer drives the exchange for this remote
// peer. Roles are deterministic (lexicographic identity-key compare) so exactly one
// side initiates, mirroring how Rosenpass picks its handshake initiator.
func (m *Manager) IsInitiator(remoteID RemoteID) bool {
	return string(m.localID) > string(remoteID)
}

// PSK returns the latest PSK derived for the peer, for the host to program at WG
// peer-config time (the pull path). ok is false until an exchange has derived one.
func (m *Manager) PSK(remoteID RemoteID) (PSK, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	psk, ok := m.psks[remoteID]
	return psk, ok
}

// trace logs at LevelTrace, the verbose per-exchange lifecycle level gated by
// NB_PQ_MLKEM_LOG_LEVEL=trace.
func (m *Manager) trace(msg string, args ...any) {
	m.logger.Log(context.Background(), LevelTrace, msg, args...)
}

// AddPeer registers where a peer's data-path messages are sent and received: its
// overlay endpoint (IP:port). This is pure routing and says nothing about capability —
// PQ capability is decided solely from the peer's KEM payload (see processOffer /
// processAnswer / MarkNonCapable), never from an endpoint or port.
func (m *Manager) AddPeer(remoteID RemoteID, endpoint netip.AddrPort) {
	if !endpoint.IsValid() {
		return
	}
	m.mu.Lock()
	if old, ok := m.peerAddrs[remoteID]; ok {
		delete(m.peersByAddr, old)
	}
	m.peerAddrs[remoteID] = endpoint
	m.peersByAddr[endpoint] = remoteID
	m.mu.Unlock()
}

// MarkNonCapable records that a peer does not run the KEM: it answered our offer with
// no KEM material over signalling (the capability signal is the peer's payload, not its
// optional data-path port). Any in-flight exchange is cancelled and further offers are
// suppressed (see SignalOffer), so a non-PQ peer never drives the rekey-recovery storm.
// An already-established peer is left untouched — a stray empty answer must not tear
// down a working PQ session.
func (m *Manager) MarkNonCapable(remoteID RemoteID) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.established[remoteID] {
		return
	}
	if prev, ok := m.capable[remoteID]; ok && !prev {
		return // already known non-capable, nothing to do
	}
	m.capable[remoteID] = false
	if ex := m.exchanges[remoteID]; ex != nil {
		if ex.cancel != nil {
			ex.cancel()
		}
		delete(m.exchanges, remoteID)
	}
	m.trace("pqkem: peer advertises no PQ service — treating as non-capable, no KEM attempted", "peer", remoteID)
}

// RemovePeer stops any in-flight exchange for a peer and drops its state and routing.
func (m *Manager) RemovePeer(remoteID RemoteID) {
	m.mu.Lock()
	if ex, ok := m.exchanges[remoteID]; ok {
		if ex.cancel != nil {
			ex.cancel()
		}
		delete(m.exchanges, remoteID)
	}
	delete(m.established, remoteID)
	delete(m.failures, remoteID)
	delete(m.psks, remoteID)
	delete(m.capable, remoteID)
	if ep, ok := m.peerAddrs[remoteID]; ok {
		delete(m.peersByAddr, ep)
		delete(m.peerAddrs, remoteID)
	}
	m.mu.Unlock()
}

// Stop cancels all in-flight exchanges, closes the transport, and waits for the
// exchange goroutines to exit.
func (m *Manager) Stop() {
	m.rootCancel()
	m.wait.Wait()
	m.mu.Lock()
	t := m.transport
	m.transport = nil
	m.exchanges = make(map[RemoteID]*exchangeCtl)
	m.psks = make(map[RemoteID]PSK)
	m.mu.Unlock()
	if t != nil {
		if err := t.Close(); err != nil {
			m.logger.Warn("pqkem: closing data-path transport", "err", err)
		}
	}
}

// ---- Signalling channel (host-driven; rides the host's negotiation) ----

// SignalOffer returns the KEM offer for the host to embed in its outgoing offer to
// remoteID (bootstrap). It returns (nil, nil) when the local peer is not the
// initiator. It is idempotent for an in-flight bootstrap: a repeat call returns the
// same offer rather than starting a new exchange.
//
// A signal re-negotiation always re-bootstraps (fresh exchange): the remote may have
// restarted and lost its PSK, so reusing a locally frozen one would desync. The derived
// PSK still survives idle in the manager (dropped only on account-level peer removal),
// so a pure lazy wake with no re-negotiation reuses it via the conn's WG-config pull.
func (m *Manager) SignalOffer(remoteID RemoteID) ([]byte, error) {
	if !m.IsInitiator(remoteID) {
		return nil, nil
	}
	m.mu.Lock()
	if capable, ok := m.capable[remoteID]; ok && !capable {
		m.mu.Unlock()
		return nil, nil // peer does not run the KEM; do not offer (avoids a failure/reoffer loop)
	}
	if ex := m.exchanges[remoteID]; ex != nil && ex.viaSignal && ex.state == stateAwaitingAnswer {
		last := ex.lastSent
		m.mu.Unlock()
		return last, nil
	}
	m.mu.Unlock()
	// bootstrap offer acknowledges nothing (zero AckID).
	return m.startExchange(remoteID, true, ExchangeID{})
}

// SignalOnOffer processes a KEM offer the host extracted from an incoming offer and
// returns the KEM answer for the host to embed in its outgoing answer.
func (m *Manager) SignalOnOffer(remoteID RemoteID, offer []byte) ([]byte, error) {
	typ, msg, err := Decode(offer)
	if err != nil {
		return nil, fmt.Errorf("decode signal offer from %s: %w", remoteID, err)
	}
	if typ != MsgOffer {
		return nil, fmt.Errorf("expected offer from %s, got type %d", remoteID, typ)
	}
	return m.processOffer(remoteID, msg.(*OfferMsg))
}

// SignalOnAnswer processes a KEM answer the host extracted from an incoming answer.
// There is no reply: the next offer (over the data path) acknowledges this exchange.
func (m *Manager) SignalOnAnswer(remoteID RemoteID, answer []byte) error {
	typ, msg, err := Decode(answer)
	if err != nil {
		return fmt.Errorf("decode signal answer from %s: %w", remoteID, err)
	}
	if typ != MsgAnswer {
		return fmt.Errorf("expected answer from %s, got type %d", remoteID, typ)
	}
	return m.processAnswer(remoteID, msg.(*AnswerMsg))
}

// ---- Data path ----

// onDataPathInbound is the transport's inbound handler: it reverse-resolves the
// source endpoint to a peer and dispatches. Unknown sources are dropped.
func (m *Manager) onDataPathInbound(src netip.AddrPort, msg []byte) {
	m.mu.Lock()
	remoteID, ok := m.peersByAddr[src]
	m.mu.Unlock()
	if !ok {
		return
	}
	if err := m.OnDataPathMessage(remoteID, msg); err != nil {
		m.trace("pqkem: inbound", "peer", remoteID, "err", err)
	}
}

// OnDataPathMessage handles a KEM message received over the data path from remoteID
// and pushes any reply back over the data path.
func (m *Manager) OnDataPathMessage(remoteID RemoteID, raw []byte) error {
	typ, msg, err := Decode(raw)
	if err != nil {
		return fmt.Errorf("decode data-path msg from %s: %w", remoteID, err)
	}
	switch typ {
	case MsgOffer:
		answer, err := m.processOffer(remoteID, msg.(*OfferMsg))
		if err != nil {
			return err
		}
		if answer == nil {
			return nil
		}
		return m.pushDataPath(remoteID, answer)
	case MsgAnswer:
		return m.processAnswer(remoteID, msg.(*AnswerMsg))
	default:
		return fmt.Errorf("unhandled data-path message type %d from %s", typ, remoteID)
	}
}

// OnDataPathRekeyed clocks the next chained PSK rotation on a fresh data-path rekey
// (fired on first establishment AND every rekey). If we are the initiator that just
// derived a PSK, it chains the next exchange: a fresh offer over the data path that
// acknowledges the just-completed one (its arrival under the new key proves to the
// responder the key works). sinceActivity is how long ago the peer last exchanged real
// user data; past rotationActivityWindow the tunnel is treated as idle and rotation is
// skipped — an idle tunnel has nothing to protect, and rotating would emit data-path
// traffic that keeps the peer artificially active (see conn.onWGCheckSuccess).
func (m *Manager) OnDataPathRekeyed(remoteID RemoteID, sinceActivity time.Duration) {
	if sinceActivity >= rotationActivityWindow {
		m.trace("pqkem: peer idle, skipping data-path rotation", "peer", remoteID, "since_activity", sinceActivity)
		return
	}

	m.mu.Lock()
	ex := m.exchanges[remoteID]
	chain := ex != nil && ex.state == stateAwaitingRekey
	var ackID ExchangeID
	if chain {
		ackID = ex.id
	}
	m.mu.Unlock()

	m.trace("pqkem: data-path rekey signal", "peer", remoteID, "chaining", chain)
	if !chain {
		return
	}
	offer, err := m.startExchange(remoteID, false, ackID)
	if err != nil {
		m.logger.Error("pqkem: chain offer failed to start", "peer", remoteID, "err", err)
		return
	}
	if err := m.pushDataPath(remoteID, offer); err != nil {
		m.logger.Warn("pqkem: send chain offer failed", "peer", remoteID, "err", err)
		return
	}
	m.trace("pqkem: chain offer sent over data path", "peer", remoteID)
}

// OnDataPathDown notifies that the peer's data path went down. Rotations resume once
// the host re-bootstraps over signalling on reconnect; in-flight data-path sends will
// simply fail until then. Reserved as an explicit hook.
func (m *Manager) OnDataPathDown(remoteID RemoteID) {}

// ---- internals ----

// pushDataPath resolves the peer's endpoint and sends over the data-path transport,
// erroring if the peer is unknown or no transport is set.
func (m *Manager) pushDataPath(remoteID RemoteID, msg []byte) error {
	m.mu.Lock()
	ep, ok := m.peerAddrs[remoteID]
	t := m.transport
	m.mu.Unlock()
	if !ok {
		return fmt.Errorf("no data-path endpoint for peer %s", remoteID)
	}
	if t == nil {
		return fmt.Errorf("no data-path transport")
	}
	return t.Send(ep, msg)
}

func (m *Manager) binding(remoteID RemoteID) Binding {
	return Binding{LocalID: []byte(m.localID), RemoteID: []byte(remoteID)}
}

func newExchangeID() (ExchangeID, error) {
	var id ExchangeID
	if _, err := rand.Read(id[:]); err != nil {
		return ExchangeID{}, fmt.Errorf("generate exchange id: %w", err)
	}
	return id, nil
}
