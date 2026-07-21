package pqkem

import (
	"crypto/rand"
	"fmt"
	"sync"
)

// Manager drives the PQ-KEM exchange per remote peer. It is a pure state machine:
// it consumes and produces messages and returns the derived PSK at the point each
// side must commit it (initiator on the answer, responder on the confirm). It does
// no I/O — transport (Signal / tunnel) and the WireGuard SetPSK live in the caller
// (network module + wiring), so this stays extraction-ready as a standalone library.
//
// Commit ordering (see ConfirmMsg): the responder derives the PSK on the offer but
// must NOT commit it until the confirm arrives, otherwise a lost answer would leave
// it on a new PSK the initiator never got, breaking the tunnel at the next rekey.

type sessionState uint8

const (
	stateIdle            sessionState = iota
	stateAwaitingAnswer               // initiator: sent offer, waiting for answer
	stateAwaitingConfirm              // responder: sent answer, holding pending PSK until confirm
	stateEstablished
)

type peerSession struct {
	state      sessionState
	exchangeID ExchangeID

	// initiator side: in-flight ephemeral keypair between offer and answer.
	initiator *Initiator
	// responder side: the derived PSK and the answer for this exchange. Both are
	// retained after establishment so retransmitted offers/confirms (same exchangeID)
	// are handled idempotently — never re-derive a different key.
	pendingPSK PSK
	answer     *AnswerMsg
}

type Manager struct {
	localWgKey string

	mu       sync.Mutex
	sessions map[string]*peerSession
}

// NewManager creates a KEM manager for the local peer identified by its WireGuard
// public key (base64), used both for the deterministic initiator role and the
// identity binding of the derived PSK.
func NewManager(localWgKey string) *Manager {
	return &Manager{
		localWgKey: localWgKey,
		sessions:   make(map[string]*peerSession),
	}
}

// IsInitiator reports whether the local peer drives the exchange for this remote
// peer. Roles are deterministic (lexicographic WG-key compare) so exactly one side
// initiates, mirroring how Rosenpass picks its handshake initiator.
func (m *Manager) IsInitiator(remoteWgKey string) bool {
	return m.localWgKey > remoteWgKey
}

// StartExchange begins (or restarts, on rotation) an exchange as the initiator and
// returns the offer to send. Any previous in-flight exchange for the peer is dropped.
func (m *Manager) StartExchange(remoteWgKey string) (*OfferMsg, error) {
	init, err := NewInitiator()
	if err != nil {
		return nil, err
	}
	id, err := newExchangeID()
	if err != nil {
		return nil, err
	}

	m.mu.Lock()
	m.sessions[remoteWgKey] = &peerSession{
		state:      stateAwaitingAnswer,
		exchangeID: id,
		initiator:  init,
	}
	m.mu.Unlock()

	return &OfferMsg{ExchangeID: id, KEMOffer: init.Offer()}, nil
}

// HandleOffer processes a received offer as the responder, derives the PSK, and
// returns the answer to send. The PSK is held pending and NOT returned: the caller
// must not program it until HandleConfirm. A retransmitted offer (same exchangeID)
// returns the cached answer without re-deriving, so both sides keep the same key.
func (m *Manager) HandleOffer(remoteWgKey string, o *OfferMsg) (*AnswerMsg, error) {
	m.mu.Lock()
	if s, ok := m.sessions[remoteWgKey]; ok && s.exchangeID == o.ExchangeID && s.answer != nil {
		ans := s.answer
		m.mu.Unlock()
		return ans, nil
	}
	m.mu.Unlock()

	answer, psk, err := Respond(o.KEMOffer, m.binding(remoteWgKey))
	if err != nil {
		return nil, err
	}
	ansMsg := &AnswerMsg{ExchangeID: o.ExchangeID, KEMAnswer: answer}

	m.mu.Lock()
	m.sessions[remoteWgKey] = &peerSession{
		state:      stateAwaitingConfirm,
		exchangeID: o.ExchangeID,
		pendingPSK: psk,
		answer:     ansMsg,
	}
	m.mu.Unlock()

	return ansMsg, nil
}

// HandleAnswer processes a received answer as the initiator. On success it returns
// the derived PSK (which the caller commits now) and the confirm to send.
func (m *Manager) HandleAnswer(remoteWgKey string, a *AnswerMsg) (PSK, *ConfirmMsg, error) {
	m.mu.Lock()
	s, ok := m.sessions[remoteWgKey]
	m.mu.Unlock()

	if !ok || s.state != stateAwaitingAnswer {
		return PSK{}, nil, fmt.Errorf("no pending offer for peer %s", remoteWgKey)
	}
	if s.exchangeID != a.ExchangeID {
		// stale answer (e.g. to a pre-restart offer) — drop, keep waiting.
		return PSK{}, nil, fmt.Errorf("answer exchangeID mismatch for peer %s", remoteWgKey)
	}

	psk, err := s.initiator.Finish(a.KEMAnswer, m.binding(remoteWgKey))
	if err != nil {
		return PSK{}, nil, err
	}

	m.mu.Lock()
	s.state = stateEstablished
	s.initiator = nil
	m.mu.Unlock()

	return psk, &ConfirmMsg{ExchangeID: a.ExchangeID}, nil
}

// HandleConfirm processes a received confirm as the responder and returns the PSK
// to commit now. It is idempotent for the current exchangeID: a retransmitted
// confirm returns the same PSK again (programming the same PSK is harmless). It
// errors on a stale/unknown confirm so the caller ignores it.
func (m *Manager) HandleConfirm(remoteWgKey string, c *ConfirmMsg) (PSK, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	s, ok := m.sessions[remoteWgKey]
	if !ok || (s.state != stateAwaitingConfirm && s.state != stateEstablished) {
		return PSK{}, fmt.Errorf("no pending answer for peer %s", remoteWgKey)
	}
	if s.exchangeID != c.ExchangeID {
		return PSK{}, fmt.Errorf("confirm exchangeID mismatch for peer %s", remoteWgKey)
	}

	s.state = stateEstablished
	return s.pendingPSK, nil
}

func (m *Manager) binding(remoteWgKey string) Binding {
	return Binding{LocalWgPub: []byte(m.localWgKey), RemoteWgPub: []byte(remoteWgKey)}
}

func newExchangeID() (ExchangeID, error) {
	var id ExchangeID
	if _, err := rand.Read(id[:]); err != nil {
		return ExchangeID{}, fmt.Errorf("generate exchange id: %w", err)
	}
	return id, nil
}
