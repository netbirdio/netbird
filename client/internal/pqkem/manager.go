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
	// data-path message while an exchange is in flight.
	DefaultRetryInterval = 2 * time.Second
	// DefaultMaxRetries bounds how many ticks an exchange may run before it is
	// declared failed. The convergence deadline is thus MaxRetries * RetryInterval.
	DefaultMaxRetries = 10
	// DefaultMaxRekeyFailures is how many consecutive rekey (non-initial) failures
	// are tolerated before OnRekeyFailed. The initial exchange fails immediately.
	DefaultMaxRekeyFailures = 3
	// confirmRetransmits is how many times the initiator best-effort resends the
	// confirm over the data path, to cover its loss.
	confirmRetransmits = 3
)

// Transport pushes a message over the peer's data path (e.g. a WireGuard tunnel).
// It is the library's only outbound send: the control-plane (signalling) channel is
// host-driven — the library hands the host offer/answer payloads to piggyback on the
// host's own offer/answer, it never pushes there itself (that would drive the host's
// connection negotiation, which is not the library's to control).
type Transport interface {
	SendDataPath(remoteID string, msg []byte) error
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
// data-path retransmit payload. initiator is the ephemeral handle used at Finish;
// pendingPSK is the responder's derived key. viaSignal records that the offer was
// handed to the host for the signalling channel (bootstrap), so the loop does not
// retransmit it on the data path (the host retransmits it with its own negotiation).
// Only the initiator runs a retransmit loop, so only it sets cancel.
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
// runs the per-peer rekey timer, drives the X25519MLKEM768 exchange, and surfaces the
// derived PSK and convergence to the host via CallbackHandler. The cryptography is
// the pure kem.go primitives; all state lives here under one lock.
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
	// dataSend holds the peer's data-path sender when the data path is up; nil (absent)
	// means it is down. Toggled by OnDataPathRekeyed / OnDataPathDown. Its presence is
	// the "a data path exists" signal.
	dataSend map[string]func(string, []byte) error
	wait     sync.WaitGroup
}

// NewManager builds a manager for the local peer identified by its peer identity key
// (used for the deterministic initiator role and the identity binding). A zero
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
		dataSend:         make(map[string]func(string, []byte) error),
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
	delete(m.dataSend, remoteID)
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

// ---- Signalling channel (host-driven; rides the host's offer/answer) ----

// SignalOffer returns the KEM offer for the host to embed in its outgoing offer to
// remoteID (bootstrap). It returns (nil, nil) when the local peer is not the
// initiator. It is idempotent for an in-flight bootstrap: a repeat call (e.g. the
// host retransmitting its offer) returns the same offer rather than starting a new
// exchange.
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
	return m.startExchange(remoteID, true)
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
// There is no reply: the confirm rides the data path after OnDataPathRekeyed.
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

// ---- Data path (library-driven push) ----

// OnDataPathMessage feeds a KEM message received over the data path (tunnel) and
// pushes any reply back over the data path.
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
	case MsgConfirm:
		return m.processConfirm(remoteID, msg.(*ConfirmMsg))
	default:
		return fmt.Errorf("unhandled data-path message type %d from %s", typ, remoteID)
	}
}

// OnDataPathRekeyed notifies that the peer's data path is up and freshly keyed with
// the latest PSK (fired on first establishment AND every rekey — the same event). It
// marks the data path usable and, if we are the initiator waiting to confirm, sends
// the confirm over the data path (its arrival proves to the responder that we operate
// on the new key, correlated by exchangeID).
func (m *Manager) OnDataPathRekeyed(remoteID string) {
	m.mu.Lock()
	m.dataSend[remoteID] = m.transport.SendDataPath
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

	if err := m.pushDataPath(remoteID, confirm); err != nil {
		m.logger.Warn("pqkem send confirm failed", "peer", remoteID, "err", err)
	}
}

// OnDataPathDown notifies that the peer's data path went down; further rekeys wait
// until it is up again (the host re-bootstraps over signalling on reconnect).
func (m *Manager) OnDataPathDown(remoteID string) {
	m.mu.Lock()
	delete(m.dataSend, remoteID)
	m.mu.Unlock()
}

// ---- internals ----

func (m *Manager) rekeyLoop(ctx context.Context, remoteID string) {
	defer m.wait.Done()
	t := time.NewTicker(m.rekeyInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			m.mu.Lock()
			_, dpUp := m.dataSend[remoteID]
			_, inFlight := m.exchanges[remoteID]
			m.mu.Unlock()
			// Rekeys ride the data path only; skip when it is down (the host will
			// re-bootstrap over signalling on reconnect) or an exchange is in flight.
			if !dpUp || inFlight || !m.IsInitiator(remoteID) {
				continue
			}
			offer, err := m.startExchange(remoteID, false)
			if err != nil {
				m.logger.Error("pqkem rekey failed to start", "peer", remoteID, "err", err)
				continue
			}
			if err := m.pushDataPath(remoteID, offer); err != nil {
				m.logger.Warn("pqkem send rekey offer failed", "peer", remoteID, "err", err)
			}
		}
	}
}

// pushDataPath sends over the peer's data path, erroring if it is down.
func (m *Manager) pushDataPath(remoteID string, msg []byte) error {
	m.mu.Lock()
	send := m.dataSend[remoteID]
	m.mu.Unlock()
	if send == nil {
		return fmt.Errorf("no data path for peer %s", remoteID)
	}
	return send(remoteID, msg)
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
