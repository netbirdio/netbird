package pqkem

import (
	"context"
	"time"
)

// handleOffer (responder) derives and sends the answer for a new exchange, or
// resends the cached answer for a duplicate offer (same exchangeID) without
// re-deriving. The responder is purely reactive: no retransmit loop, no deadline.
func (m *Manager) handleOffer(remoteID string, o *OfferMsg) error {
	m.mu.Lock()
	if ex := m.exchanges[remoteID]; ex != nil && ex.id == o.ExchangeID {
		state, last := ex.state, ex.lastSent
		m.mu.Unlock()
		if state == stateReserved {
			// another goroutine reserved this exchange and is deriving the answer;
			// dropping avoids a second (randomized -> divergent) derivation.
			return nil
		}
		return m.transport.Send(remoteID, last)
	}
	// Reserve the slot so a concurrent duplicate offer bails.
	m.exchanges[remoteID] = &exchangeCtl{id: o.ExchangeID, state: stateReserved, startedAt: time.Now()}
	m.mu.Unlock()

	answerBytes, psk, err := Respond(o.KEMOffer, m.binding(remoteID))
	if err != nil {
		return err
	}
	raw, err := (&AnswerMsg{ExchangeID: o.ExchangeID, KEMAnswer: answerBytes}).Encode()
	if err != nil {
		return err
	}

	m.mu.Lock()
	if ex := m.exchanges[remoteID]; ex != nil && ex.id == o.ExchangeID {
		ex.state = stateAwaitingConfirm
		ex.lastSent = raw
		ex.pendingPSK = psk
	}
	m.mu.Unlock()

	return m.transport.Send(remoteID, raw)
}

// handleAnswer (initiator) derives the PSK, surfaces it, and sends the confirm, then
// switches the retransmit payload to the confirm. Only valid in stateAwaitingAnswer;
// advancing the state under the lock makes a concurrent/duplicate answer bail.
func (m *Manager) handleAnswer(remoteID string, a *AnswerMsg) error {
	m.mu.Lock()
	ex := m.exchanges[remoteID]
	if ex == nil || ex.id != a.ExchangeID || ex.state != stateAwaitingAnswer {
		m.mu.Unlock()
		return nil
	}
	ex.state = stateConfirming
	init := ex.initiator
	ex.initiator = nil
	m.mu.Unlock()

	psk, err := init.Finish(a.KEMAnswer, m.binding(remoteID))
	if err != nil {
		return err
	}
	if err := m.cbHandler.OnNewPSKReady(remoteID, psk); err != nil {
		return err
	}
	raw, err := (&ConfirmMsg{ExchangeID: a.ExchangeID}).Encode()
	if err != nil {
		return err
	}

	m.mu.Lock()
	if ex := m.exchanges[remoteID]; ex != nil && ex.id == a.ExchangeID {
		ex.lastSent = raw // loop now retransmits the confirm
		m.established[remoteID] = true
		m.failures[remoteID] = 0
		_ = time.Since(ex.startedAt) // convergence latency (metrics hook, later step)
	}
	m.mu.Unlock()

	return m.transport.Send(remoteID, raw)
}

// handleConfirm (responder) commits the pending PSK. Only valid in
// stateAwaitingConfirm; duplicate confirms (the initiator best-effort resends it)
// find the exchange gone and are ignored.
func (m *Manager) handleConfirm(remoteID string, c *ConfirmMsg) error {
	m.mu.Lock()
	ex := m.exchanges[remoteID]
	if ex == nil || ex.id != c.ExchangeID || ex.state != stateAwaitingConfirm {
		m.mu.Unlock()
		return nil
	}
	psk := ex.pendingPSK
	delete(m.exchanges, remoteID)
	m.established[remoteID] = true
	m.failures[remoteID] = 0
	_ = time.Since(ex.startedAt) // convergence latency (metrics hook, later step)
	m.mu.Unlock()

	return m.cbHandler.OnNewPSKReady(remoteID, psk)
}

// initiatorLoop retransmits the initiator's outstanding message, keyed off the
// exchange state: the offer while awaiting the answer (bounded by maxRetries ->
// failure), then the confirm a few best-effort times before stopping. The
// convergence deadline is thus derived from maxRetries * retryInterval.
func (m *Manager) initiatorLoop(ctx context.Context, remoteID string, id ExchangeID) {
	defer m.wait.Done()
	t := time.NewTicker(m.retryInterval)
	defer t.Stop()

	offerAttempts, confirmsSent := 0, 0
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
				if offerAttempts >= m.maxRetries {
					delete(m.exchanges, remoteID)
					fail := m.registerFailureLocked(remoteID)
					m.mu.Unlock()
					m.raiseFailure(remoteID, fail)
					return
				}
				msg := ex.lastSent
				offerAttempts++
				m.mu.Unlock()
				m.retransmit(remoteID, msg)

			case stateConfirming:
				if confirmsSent >= confirmRetransmits {
					delete(m.exchanges, remoteID)
					m.mu.Unlock()
					return
				}
				msg := ex.lastSent
				confirmsSent++
				m.mu.Unlock()
				m.retransmit(remoteID, msg)

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

func (m *Manager) retransmit(remoteID string, msg []byte) {
	if err := m.transport.Send(remoteID, msg); err != nil {
		m.logger.Warn("pqkem retransmit failed", "peer", remoteID, "err", err)
	}
}
