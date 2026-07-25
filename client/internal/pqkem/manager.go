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
)

// Transport is the data-path socket the Manager drives (the analogue of
// go-rosenpass's Conn). It is a dumb mover of bytes to/from endpoints: the Manager
// owns the remoteID<->endpoint routing and hands the transport a resolved endpoint
// to Send, and reverse-resolves the source of each inbound datagram. Its lifecycle
// belongs to the Manager (Run at SetTransport, Close at Stop).
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
	localID   string
	cbHandler CallbackHandler
	logger    *slog.Logger

	retryInterval    time.Duration
	maxRetries       int
	maxRekeyFailures int

	rootCtx    context.Context
	rootCancel context.CancelFunc

	mu          sync.Mutex
	transport   Transport
	exchanges   map[string]*exchangeCtl   // in-flight exchange per peer
	established  map[string]bool          // peer has completed at least one exchange
	failures    map[string]int            // consecutive rekey failures per peer
	peers       map[string]netip.AddrPort // remoteID -> data-path endpoint (send routing)
	peersByAddr map[netip.AddrPort]string // reverse: source endpoint -> remoteID (inbound)
	wait        sync.WaitGroup
}

// NewManager builds a manager for the local peer identified by its peer identity key
// (used for the deterministic initiator role and the identity binding). A nil logger
// falls back to slog.Default(). Set the data-path transport with SetTransport.
func NewManager(localID string, h CallbackHandler, logger *slog.Logger) *Manager {
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
		exchanges:        make(map[string]*exchangeCtl),
		established:      make(map[string]bool),
		failures:         make(map[string]int),
		peers:            make(map[string]netip.AddrPort),
		peersByAddr:      make(map[netip.AddrPort]string),
	}
}

// SetTransport installs the data-path transport and starts its inbound delivery. The
// Manager owns it from here: Stop closes it.
func (m *Manager) SetTransport(t Transport) {
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
func (m *Manager) IsInitiator(remoteID string) bool {
	return m.localID > remoteID
}

// AddPeer registers where a peer's data-path messages are sent and received: its
// overlay endpoint (IP:port). Re-adding updates the endpoint.
func (m *Manager) AddPeer(remoteID string, endpoint netip.AddrPort) {
	if !endpoint.IsValid() {
		return
	}
	m.mu.Lock()
	if old, ok := m.peers[remoteID]; ok {
		delete(m.peersByAddr, old)
	}
	m.peers[remoteID] = endpoint
	m.peersByAddr[endpoint] = remoteID
	m.mu.Unlock()
}

// RemovePeer stops any in-flight exchange for a peer and drops its state and routing.
func (m *Manager) RemovePeer(remoteID string) {
	m.mu.Lock()
	if ex, ok := m.exchanges[remoteID]; ok {
		if ex.cancel != nil {
			ex.cancel()
		}
		delete(m.exchanges, remoteID)
	}
	delete(m.established, remoteID)
	delete(m.failures, remoteID)
	if ep, ok := m.peers[remoteID]; ok {
		delete(m.peersByAddr, ep)
		delete(m.peers, remoteID)
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
	m.exchanges = make(map[string]*exchangeCtl)
	m.mu.Unlock()
	if t != nil {
		_ = t.Close()
	}
}

// ---- Signalling channel (host-driven; rides the host's negotiation) ----

// SignalOffer returns the KEM offer for the host to embed in its outgoing offer to
// remoteID (bootstrap). It returns (nil, nil) when the local peer is not the
// initiator. It is idempotent for an in-flight bootstrap: a repeat call returns the
// same offer rather than starting a new exchange.
func (m *Manager) SignalOffer(remoteID string) ([]byte, error) {
	if !m.IsInitiator(remoteID) {
		return nil, nil
	}
	m.mu.Lock()
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
func (m *Manager) SignalOnOffer(remoteID string, offer []byte) ([]byte, error) {
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
func (m *Manager) SignalOnAnswer(remoteID string, answer []byte) error {
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
	remoteID := m.peersByAddr[src]
	m.mu.Unlock()
	if remoteID == "" {
		return
	}
	if err := m.OnDataPathMessage(remoteID, msg); err != nil {
		m.logger.Debug("pqkem inbound", "peer", remoteID, "err", err)
	}
}

// OnDataPathMessage handles a KEM message received over the data path from remoteID
// and pushes any reply back over the data path.
func (m *Manager) OnDataPathMessage(remoteID string, raw []byte) error {
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

// OnDataPathRekeyed notifies that the peer's data path is up and freshly keyed with
// the latest PSK (fired on first establishment AND every rekey). If we are the
// initiator that just derived a PSK, it chains the next exchange: a fresh offer over
// the data path that acknowledges the just-completed one (its arrival under the new
// key proves to the responder that the key works).
func (m *Manager) OnDataPathRekeyed(remoteID string) {
	m.mu.Lock()
	ex := m.exchanges[remoteID]
	chain := ex != nil && ex.state == stateAwaitingRekey
	var ackID ExchangeID
	if chain {
		ackID = ex.id
	}
	m.mu.Unlock()

	if !chain {
		return
	}
	offer, err := m.startExchange(remoteID, false, ackID)
	if err != nil {
		m.logger.Error("pqkem chain offer failed to start", "peer", remoteID, "err", err)
		return
	}
	if err := m.pushDataPath(remoteID, offer); err != nil {
		m.logger.Warn("pqkem send chain offer failed", "peer", remoteID, "err", err)
	}
}

// OnDataPathDown notifies that the peer's data path went down. Rotations resume once
// the host re-bootstraps over signalling on reconnect; in-flight data-path sends will
// simply fail until then. Reserved as an explicit hook.
func (m *Manager) OnDataPathDown(remoteID string) {}

// ---- internals ----

// pushDataPath resolves the peer's endpoint and sends over the data-path transport,
// erroring if the peer is unknown or no transport is set.
func (m *Manager) pushDataPath(remoteID string, msg []byte) error {
	m.mu.Lock()
	ep, ok := m.peers[remoteID]
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

func (m *Manager) binding(remoteID string) Binding {
	return Binding{LocalID: []byte(m.localID), RemoteID: []byte(remoteID)}
}

func newExchangeID() (ExchangeID, error) {
	var id ExchangeID
	if _, err := rand.Read(id[:]); err != nil {
		return ExchangeID{}, fmt.Errorf("generate exchange id: %w", err)
	}
	return id, nil
}
