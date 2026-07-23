package pqkem

import (
	"context"
	"time"
)

// startExchange creates a fresh initiator exchange and returns the framed offer for
// the caller to send (pushed over the data path for a rekey, or handed to the host
// for the signalling channel when viaSignal is set). Any previous in-flight exchange
// for the peer is cancelled.
func (m *Manager) startExchange(remoteID string, viaSignal bool) ([]byte, error) {
	init, err := NewInitiator()
	if err != nil {
		return nil, err
	}
	id, err := newExchangeID()
	if err != nil {
		return nil, err
	}
	raw, err := (&OfferMsg{ExchangeID: id, KEMOffer: init.Offer()}).Encode()
	if err != nil {
		return nil, err
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
		viaSignal: viaSignal,
	}
	m.mu.Unlock()

	m.wait.Add(1)
	go m.initiatorLoop(ctx, remoteID, id)
	return raw, nil
}

// processOffer (responder) derives the PSK, commits it optimistically, and returns
// the framed answer for the caller to send. A duplicate offer (same exchangeID)
// returns the cached answer without re-deriving; a still-reserved slot returns nil.
func (m *Manager) processOffer(remoteID string, o *OfferMsg) ([]byte, error) {
	m.mu.Lock()
	if ex := m.exchanges[remoteID]; ex != nil && ex.id == o.ExchangeID {
		state, last := ex.state, ex.lastSent
		m.mu.Unlock()
		if state == stateReserved {
			return nil, nil
		}
		return last, nil
	}
	// Reserve the slot so a concurrent duplicate offer bails.
	m.exchanges[remoteID] = &exchangeCtl{id: o.ExchangeID, state: stateReserved, startedAt: time.Now()}
	m.mu.Unlock()

	answerBytes, psk, err := Respond(o.KEMOffer, m.binding(remoteID))
	if err != nil {
		return nil, err
	}
	raw, err := (&AnswerMsg{ExchangeID: o.ExchangeID, KEMAnswer: answerBytes}).Encode()
	if err != nil {
		return nil, err
	}

	m.mu.Lock()
	ex := m.exchanges[remoteID]
	if ex == nil || ex.id != o.ExchangeID {
		m.mu.Unlock()
		return nil, nil
	}
	ex.state = stateAwaitingConfirm
	ex.lastSent = raw
	ex.pendingPSK = psk
	m.mu.Unlock()

	// Commit optimistically so our data path can rekey to the new PSK.
	if err := m.cbHandler.OnNewPSKReady(remoteID, psk); err != nil {
		return nil, err
	}
	return raw, nil
}

// processAnswer (initiator) derives and commits the PSK, then parks in
// stateAwaitingRekey; the confirm is sent later, over the data path, from
// OnDataPathRekeyed. Only valid in stateAwaitingAnswer; advancing the state under the
// lock makes a concurrent/duplicate answer bail.
func (m *Manager) processAnswer(remoteID string, a *AnswerMsg) error {
	m.mu.Lock()
	ex := m.exchanges[remoteID]
	if ex == nil || ex.id != a.ExchangeID || ex.state != stateAwaitingAnswer {
		m.mu.Unlock()
		return nil
	}
	ex.state = stateAwaitingRekey
	init := ex.initiator
	ex.initiator = nil
	m.mu.Unlock()

	psk, err := init.Finish(a.KEMAnswer, m.binding(remoteID))
	if err != nil {
		return err
	}
	return m.cbHandler.OnNewPSKReady(remoteID, psk)
}

// processConfirm (responder) records convergence. The PSK was already committed in
// processOffer; a confirm arriving over the data path with a matching exchangeID
// proves we operate on the new key from this exchange. Stale/duplicate confirms find
// the exchange gone and are ignored.
func (m *Manager) processConfirm(remoteID string, c *ConfirmMsg) error {
	m.mu.Lock()
	ex := m.exchanges[remoteID]
	if ex == nil || ex.id != c.ExchangeID || ex.state != stateAwaitingConfirm {
		m.mu.Unlock()
		return nil
	}
	delete(m.exchanges, remoteID)
	m.established[remoteID] = true
	m.failures[remoteID] = 0
	_ = time.Since(ex.startedAt) // convergence latency (metrics hook, later step)
	m.mu.Unlock()
	return nil
}

// initiatorLoop enforces the convergence deadline and retransmits the initiator's
// outstanding DATA-PATH message: it resends the offer while awaiting the answer only
// when the offer went over the data path (a signalling-bootstrapped offer is
// retransmitted by the host with its own negotiation); it waits, counting toward the
// deadline, while awaiting the data-path rekey; it resends the confirm a few times
// once sent. Exhausting the deadline before the confirm phase is a failure.
func (m *Manager) initiatorLoop(ctx context.Context, remoteID string, id ExchangeID) {
	defer m.wait.Done()
	t := time.NewTicker(m.retryInterval)
	defer t.Stop()

	attempts, confirmsSent := 0, 0
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			m.mu.Lock()
			ex := m.exchanges[remoteID]
			if ex == nil || ex.id != id {
				m.mu.Unlock()
				return
			}

			switch ex.state {
			case stateAwaitingAnswer:
				if attempts >= m.maxRetries {
					delete(m.exchanges, remoteID)
					fail := m.registerFailureLocked(remoteID)
					m.mu.Unlock()
					m.raiseFailure(remoteID, fail)
					return
				}
				viaSignal := ex.viaSignal
				msg := ex.lastSent
				attempts++
				m.mu.Unlock()
				if !viaSignal {
					if err := m.pushDataPath(remoteID, msg); err != nil {
						m.logger.Warn("pqkem offer retransmit failed", "peer", remoteID, "err", err)
					}
				}

			case stateAwaitingRekey:
				// Waiting for OnDataPathRekeyed; nothing to send, but the deadline
				// still applies (the data path may never come up with the new key).
				if attempts >= m.maxRetries {
					delete(m.exchanges, remoteID)
					fail := m.registerFailureLocked(remoteID)
					m.mu.Unlock()
					m.raiseFailure(remoteID, fail)
					return
				}
				attempts++
				m.mu.Unlock()

			case stateConfirming:
				if confirmsSent >= confirmRetransmits {
					delete(m.exchanges, remoteID)
					m.mu.Unlock()
					return
				}
				msg := ex.lastSent
				confirmsSent++
				m.mu.Unlock()
				if err := m.pushDataPath(remoteID, msg); err != nil {
					m.logger.Warn("pqkem confirm retransmit failed", "peer", remoteID, "err", err)
				}

			default:
				m.mu.Unlock()
				return
			}
		}
	}
}

// registerFailureLocked applies policy B and reports whether OnRekeyFailed is due:
// an initial exchange (peer never established) fails immediately; a rekey tolerates
// up to maxRekeyFailures consecutive misses (we stay on the still-valid previous
// PSK) before failing. Assumes m.mu is held.
func (m *Manager) registerFailureLocked(remoteID string) bool {
	if !m.established[remoteID] {
		return true
	}
	m.failures[remoteID]++
	if m.failures[remoteID] >= m.maxRekeyFailures {
		m.failures[remoteID] = 0
		return true
	}
	return false
}

func (m *Manager) raiseFailure(remoteID string, fail bool) {
	if !fail {
		m.logger.Warn("pqkem rekey attempt timed out, will retry next cycle", "peer", remoteID)
		return
	}
	if err := m.cbHandler.OnRekeyFailed(remoteID); err != nil {
		m.logger.Error("pqkem OnRekeyFailed handler error", "peer", remoteID, "err", err)
	}
}
