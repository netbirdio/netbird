package pqkem

import (
	"context"
	"crypto/rand"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

const (
	// DefaultRekeyInterval is the default PSK rotation cadence (~2 min), chosen so a
	// rotated PSK is adopted by the consumer's next transport handshake without
	// forcing one.
	DefaultRekeyInterval = 2 * time.Minute
	// DefaultRetryInterval is how often the initiator retransmits its outstanding
	// message (offer, then confirm) while an exchange is in flight.
	DefaultRetryInterval = 2 * time.Second
	// DefaultMaxRetries bounds how many times the offer is retransmitted before the
	// exchange is declared failed. The convergence deadline is thus derived as
	// MaxRetries * RetryInterval — there is no separate deadline timer.
	DefaultMaxRetries = 10
	// DefaultMaxRekeyFailures is how many consecutive rekey (non-initial) failures
	// are tolerated before OnRekeyFailed. The initial exchange fails immediately.
	DefaultMaxRekeyFailures = 3
	// confirmRetransmits is how many times the initiator best-effort resends the
	// confirm after converging, to cover its loss without a dedicated goroutine.
	confirmRetransmits = 3
)

// Transport hands an already-encoded exchange message to the peer. The host routes
// it over the appropriate channel — a signalling channel before the tunnel is up,
// the data tunnel for rekeys — so the Manager never needs to know which is in use.
// It is the analogue of go-rosenpass's Conn seam.
type Transport interface {
	Send(remoteID string, msg []byte) error
}

// exchangeState is the single source of truth for an exchange's role and phase.
// Every handler and the retransmit loop key off it, so no role/phase is re-derived
// from other fields.
type exchangeState uint8

const (
	stateReserved        exchangeState = iota // responder: deriving the answer
	stateAwaitingAnswer                       // initiator: offer sent, awaiting the answer
	stateAwaitingConfirm                      // responder: answer sent, awaiting the confirm
	stateConfirming                           // initiator: answer in, PSK committed, flushing the confirm
)

// exchangeCtl holds all state for one in-flight exchange with a peer, under the
// Manager's single lock. state drives every decision. lastSent is the message
// currently being (re)transmitted. The crypto payloads live here too: initiator is
// the ephemeral handle used at Finish (initiator side); pendingPSK is the derived
// key held until the confirm commits it (responder side). Only the initiator runs a
// retransmit loop, so only it sets cancel.
type exchangeCtl struct {
	id         ExchangeID
	state      exchangeState
	startedAt  time.Time
	cancel     context.CancelFunc
	lastSent   []byte
	initiator  *Initiator
	pendingPSK PSK
}

// Manager is the stateful orchestrator — the analogue of go-rosenpass's Server. It
// runs the per-peer rekey timer, drives the X25519MLKEM768 exchange over a pluggable
// Transport, and surfaces the derived PSK to the host via CallbackHandler. The
// cryptography is the pure kem.go primitives; all per-exchange and per-peer state
// lives here under one lock.
type Manager struct {
	localID   string
	transport Transport
	cbHandler CallbackHandler
	logger    *slog.Logger

	rekeyInterval    time.Duration
	retryInterval    time.Duration
	maxRetries       int
	maxRekeyFailures int

	rootCtx    context.Context
	rootCancel context.CancelFunc

	mu          sync.Mutex
	peers       map[string]context.CancelFunc // per-peer rekey loop
	exchanges   map[string]*exchangeCtl       // in-flight exchange per peer
	established map[string]bool               // peer has completed at least one exchange
	failures    map[string]int                // consecutive rekey failures per peer
	wait        sync.WaitGroup
}

// NewManager builds a manager for the local peer identified by its peer identity
// key (used for the deterministic initiator role and the identity binding). A zero
// interval falls back to DefaultRekeyInterval; a nil logger to slog.Default().
// Retry/retries/K use their defaults and can be overridden before use.
func NewManager(localID string, t Transport, h CallbackHandler, interval time.Duration, logger *slog.Logger) *Manager {
	if interval <= 0 {
		interval = DefaultRekeyInterval
	}
	if logger == nil {
		logger = slog.Default()
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Manager{
		localID:          localID,
		transport:        t,
		cbHandler:        h,
		logger:           logger,
		rekeyInterval:    interval,
		retryInterval:    DefaultRetryInterval,
		maxRetries:       DefaultMaxRetries,
		maxRekeyFailures: DefaultMaxRekeyFailures,
		rootCtx:          ctx,
		rootCancel:       cancel,
		peers:            make(map[string]context.CancelFunc),
		exchanges:        make(map[string]*exchangeCtl),
		established:      make(map[string]bool),
		failures:         make(map[string]int),
	}
}

// IsInitiator reports whether the local peer drives the exchange for this remote
// peer. Roles are deterministic (lexicographic identity-key compare) so exactly one
// side initiates, mirroring how Rosenpass picks its handshake initiator.
func (m *Manager) IsInitiator(remoteID string) bool {
	return m.localID > remoteID
}

// AddPeer registers a remote peer and starts its rekey timer. Re-adding is a no-op.
func (m *Manager) AddPeer(remoteID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.peers[remoteID]; ok {
		return
	}
	ctx, cancel := context.WithCancel(m.rootCtx)
	m.peers[remoteID] = cancel
	m.wait.Add(1)
	go m.rekeyLoop(ctx, remoteID)
}

// RemovePeer stops a peer's rekey timer and any in-flight exchange, and drops state.
func (m *Manager) RemovePeer(remoteID string) {
	m.mu.Lock()
	if cancel, ok := m.peers[remoteID]; ok {
		cancel()
		delete(m.peers, remoteID)
	}
	if ex, ok := m.exchanges[remoteID]; ok {
		if ex.cancel != nil {
			ex.cancel()
		}
		delete(m.exchanges, remoteID)
	}
	delete(m.established, remoteID)
	delete(m.failures, remoteID)
	m.mu.Unlock()
}

// Stop cancels all timers and in-flight exchanges and waits for goroutines to exit.
func (m *Manager) Stop() {
	m.rootCancel()
	m.wait.Wait()
	m.mu.Lock()
	m.peers = make(map[string]context.CancelFunc)
	m.exchanges = make(map[string]*exchangeCtl)
	m.mu.Unlock()
}

// HandleInbound decodes an incoming message and drives the exchange, sending any
// response via the transport and surfacing derived PSKs / convergence to the host.
func (m *Manager) HandleInbound(remoteID string, raw []byte) error {
	typ, msg, err := Decode(raw)
	if err != nil {
		return fmt.Errorf("decode from %s: %w", remoteID, err)
	}
	switch typ {
	case MsgOffer:
		return m.handleOffer(remoteID, msg.(*OfferMsg))
	case MsgAnswer:
		return m.handleAnswer(remoteID, msg.(*AnswerMsg))
	case MsgConfirm:
		return m.handleConfirm(remoteID, msg.(*ConfirmMsg))
	default:
		return fmt.Errorf("unhandled message type %d from %s", typ, remoteID)
	}
}

// initiateRekey starts a fresh exchange when the local peer is the initiator for
// this remote peer; the responder waits for the offer instead. Exposed (unexported
// but directly callable) so tests can drive a rekey without waiting on the ticker.
func (m *Manager) initiateRekey(remoteID string) error {
	if !m.IsInitiator(remoteID) {
		return nil
	}
	init, err := NewInitiator()
	if err != nil {
		return err
	}
	id, err := newExchangeID()
	if err != nil {
		return err
	}
	raw, err := (&OfferMsg{ExchangeID: id, KEMOffer: init.Offer()}).Encode()
	if err != nil {
		return err
	}

	ctx, cancel := context.WithCancel(m.rootCtx)
	m.mu.Lock()
	if old := m.exchanges[remoteID]; old != nil && old.cancel != nil {
		old.cancel()
	}
	m.exchanges[remoteID] = &exchangeCtl{
		id:        id,
		state:     stateAwaitingAnswer,
		startedAt: time.Now(),
		cancel:    cancel,
		lastSent:  raw,
		initiator: init,
	}
	m.mu.Unlock()

	m.wait.Add(1)
	go m.initiatorLoop(ctx, remoteID, id)

	return m.transport.Send(remoteID, raw)
}

func (m *Manager) rekeyLoop(ctx context.Context, remoteID string) {
	defer m.wait.Done()
	t := time.NewTicker(m.rekeyInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := m.initiateRekey(remoteID); err != nil {
				m.logger.Error("pqkem rekey failed to start", "peer", remoteID, "err", err)
			}
		}
	}
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
