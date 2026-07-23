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
	// DefaultMaxRetries bounds how many ticks an exchange may run before the offer
	// or the wait for the data-path rekey is declared failed. The convergence
	// deadline is thus derived as MaxRetries * RetryInterval — no separate timer.
	DefaultMaxRetries = 10
	// DefaultMaxRekeyFailures is how many consecutive rekey (non-initial) failures
	// are tolerated before OnRekeyFailed. The initial exchange fails immediately.
	DefaultMaxRekeyFailures = 3
	// confirmRetransmits is how many times the initiator best-effort resends the
	// confirm over the data path, to cover its loss without a dedicated goroutine.
	confirmRetransmits = 3
)

// Transport carries exchange messages over the two available channels; the library
// picks which. It is the analogue of go-rosenpass's Conn seam.
//
// Model: a message rides the channel keyed with the CURRENTLY valid key. Before a
// data path exists (initial bootstrap) that is the out-of-band signalling channel;
// once the data path is up (after OnDataPathRekeyed) offers/answers ride it, and the
// confirm ALWAYS rides the data path (so its arrival proves the new key works).
type Transport interface {
	// SendDataPath sends over the peer's established data path (e.g. a WireGuard
	// tunnel). The consumer routes it accordingly.
	SendDataPath(remoteID string, msg []byte) error
	// SendSignal sends over the out-of-band signalling channel, handled outside the
	// library by the consumer.
	SendSignal(remoteID string, msg []byte) error
}

// exchangeState is the single source of truth for an exchange's role and phase.
type exchangeState uint8

const (
	stateReserved        exchangeState = iota // responder: deriving the answer
	stateAwaitingAnswer                       // initiator: offer sent, awaiting the answer
	stateAwaitingRekey                        // initiator: PSK derived+set, awaiting OnDataPathRekeyed to send the confirm
	stateConfirming                           // initiator: confirm sent over the data path, best-effort retransmit
	stateAwaitingConfirm                      // responder: answer sent, awaiting the confirm over the data path
)

// exchangeCtl holds all state for one in-flight exchange with a peer, under the
// Manager's single lock. state drives every decision. lastSent is the current
// retransmit payload (offer, then confirm). initiator is the ephemeral handle used
// at Finish; pendingPSK is the responder's derived key. Only the initiator runs a
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
// runs the per-peer rekey timer, drives the X25519MLKEM768 exchange over the
// Transport, and surfaces the derived PSK and convergence to the host via
// CallbackHandler. The cryptography is the pure kem.go primitives; all state lives
// here under one lock.
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
	dataPathUp  map[string]bool               // peer's data path is up (offers/answers may ride it)
	wait        sync.WaitGroup
}

// NewManager builds a manager for the local peer identified by its peer identity
// key (used for the deterministic initiator role and the identity binding). A zero
// interval falls back to DefaultRekeyInterval; a nil logger to slog.Default().
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
		dataPathUp:       make(map[string]bool),
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
	delete(m.dataPathUp, remoteID)
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

// OnDataPathRekeyed notifies the library that the peer's data path is up and freshly
// keyed with the latest PSK (fired on first establishment AND every rekey — the same
// event). It marks the data path usable and, if we are the initiator waiting to
// confirm, sends the confirm over the data path (its arrival proves to the responder
// that we operate on the new key, correlated by exchangeID).
func (m *Manager) OnDataPathRekeyed(remoteID string) {
	m.mu.Lock()
	m.dataPathUp[remoteID] = true
	ex := m.exchanges[remoteID]
	if ex == nil || ex.state != stateAwaitingRekey {
		m.mu.Unlock()
		return
	}
	confirm, err := (&ConfirmMsg{ExchangeID: ex.id}).Encode()
	if err != nil {
		m.mu.Unlock()
		m.logger.Error("pqkem encode confirm", "peer", remoteID, "err", err)
		return
	}
	ex.state = stateConfirming
	ex.lastSent = confirm
	m.established[remoteID] = true
	m.failures[remoteID] = 0
	_ = time.Since(ex.startedAt) // convergence latency (metrics hook, later step)
	m.mu.Unlock()

	if err := m.transport.SendDataPath(remoteID, confirm); err != nil {
		m.logger.Warn("pqkem send confirm failed", "peer", remoteID, "err", err)
	}
}

// HandleInbound decodes an incoming message and drives the exchange.
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

// initiateRekey starts a fresh exchange when the local peer is the initiator. The
// offer rides the data path if it is up (rekey) or the signalling channel otherwise
// (initial bootstrap).
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

	return m.send(remoteID, raw)
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

// send routes offer/answer over the data path when it is up, else the signalling
// channel. The confirm never goes through here — it always uses SendDataPath.
func (m *Manager) send(remoteID string, msg []byte) error {
	m.mu.Lock()
	viaDataPath := m.dataPathUp[remoteID]
	m.mu.Unlock()
	if viaDataPath {
		return m.transport.SendDataPath(remoteID, msg)
	}
	return m.transport.SendSignal(remoteID, msg)
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
