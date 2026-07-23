package pqkem

import (
	"context"
	"time"
)

// handleOffer (responder) derives and sends the answer for a new exchange, or
// resends the cached answer for a duplicate offer (same exchangeID) without
// re-deriving. The responder is purely reactive: no retransmit loop, no deadline.
func (m *Manager) handleOffer(remoteWgKey string, o *OfferMsg) error {
	m.mu.Lock()
	if ex := m.exchanges[remoteWgKey]; ex != nil && ex.id == o.ExchangeID {
		state, last := ex.state, ex.lastSent
		m.mu.Unlock()
		if state == stateReserved {
			// another goroutine reserved this exchange and is deriving the answer;
			// dropping avoids a second (randomized -> divergent) derivation.
			return nil
		}
		return m.transport.Send(remoteWgKey, last)
	}
	// Reserve the slot so a concurrent duplicate offer bails.
	m.exchanges[remoteWgKey] = &exchangeCtl{id: o.ExchangeID, state: stateReserved, startedAt: time.Now()}
	m.mu.Unlock()

	answerBytes, psk, err := Respond(o.KEMOffer, m.binding(remoteWgKey))
	if err != nil {
		return err
	}
	raw, err := (&AnswerMsg{ExchangeID: o.ExchangeID, KEMAnswer: answerBytes}).Encode()
	if err != nil {
		return err
	}

	m.mu.Lock()
	if ex := m.exchanges[remoteWgKey]; ex != nil && ex.id == o.ExchangeID {
		ex.state = stateAwaitingConfirm
		ex.lastSent = raw
		ex.pendingPSK = psk
	}
	m.mu.Unlock()

	return m.transport.Send(remoteWgKey, raw)
}

// handleAnswer (initiator) derives the PSK, surfaces it, and sends the confirm, then
// switches the retransmit payload to the confirm. Only valid in stateAwaitingAnswer;
// advancing the state under the lock makes a concurrent/duplicate answer bail.
func (m *Manager) handleAnswer(remoteWgKey string, a *AnswerMsg) error {
	m.mu.Lock()
	ex := m.exchanges[remoteWgKey]
	if ex == nil || ex.id != a.ExchangeID || ex.state != stateAwaitingAnswer {
		m.mu.Unlock()
		return nil
	}
	ex.state = stateConfirming
	init := ex.initiator
	ex.initiator = nil
	m.mu.Unlock()

	psk, err := init.Finish(a.KEMAnswer, m.binding(remoteWgKey))
	if err != nil {
		return err
	}
	if err := m.wg.OnNewPSKReady(remoteWgKey, psk); err != nil {
		return err
	}
	raw, err := (&ConfirmMsg{ExchangeID: a.ExchangeID}).Encode()
	if err != nil {
		return err
	}

	m.mu.Lock()
	if ex := m.exchanges[remoteWgKey]; ex != nil && ex.id == a.ExchangeID {
		ex.lastSent = raw // loop now retransmits the confirm
		m.established[remoteWgKey] = true
		m.failures[remoteWgKey] = 0
		_ = time.Since(ex.startedAt) // convergence latency (metrics hook, later step)
	}
	m.mu.Unlock()

	return m.transport.Send(remoteWgKey, raw)
}

// handleConfirm (responder) commits the pending PSK. Only valid in
// stateAwaitingConfirm; duplicate confirms (the initiator best-effort resends it)
// find the exchange gone and are ignored.
func (m *Manager) handleConfirm(remoteWgKey string, c *ConfirmMsg) error {
	m.mu.Lock()
	ex := m.exchanges[remoteWgKey]
	if ex == nil || ex.id != c.ExchangeID || ex.state != stateAwaitingConfirm {
		m.mu.Unlock()
		return nil
	}
	psk := ex.pendingPSK
	delete(m.exchanges, remoteWgKey)
	m.established[remoteWgKey] = true
	m.failures[remoteWgKey] = 0
	_ = time.Since(ex.startedAt) // convergence latency (metrics hook, later step)
	m.mu.Unlock()

	return m.wg.OnNewPSKReady(remoteWgKey, psk)
}

// initiatorLoop retransmits the initiator's outstanding message, keyed off the
// exchange state: the offer while awaiting the answer (bounded by maxRetries ->
// failure), then the confirm a few best-effort times before stopping. The
// convergence deadline is thus derived from maxRetries * retryInterval.
func (m *Manager) initiatorLoop(ctx context.Context, remoteWgKey string, id ExchangeID) {
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
			ex := m.exchanges[remoteWgKey]
			if ex == nil || ex.id != id {
				m.mu.Unlock()
				return
			}

			switch ex.state {
			case stateAwaitingAnswer:
				if offerAttempts >= m.maxRetries {
					delete(m.exchanges, remoteWgKey)
					fail := m.registerFailureLocked(remoteWgKey)
					m.mu.Unlock()
					m.raiseFailure(remoteWgKey, fail)
					return
				}
				msg := ex.lastSent
				offerAttempts++
				m.mu.Unlock()
				m.retransmit(remoteWgKey, msg)

			case stateConfirming:
				if confirmsSent >= confirmRetransmits {
					delete(m.exchanges, remoteWgKey)
					m.mu.Unlock()
					return
				}
				msg := ex.lastSent
				confirmsSent++
				m.mu.Unlock()
				m.retransmit(remoteWgKey, msg)

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
func (m *Manager) registerFailureLocked(remoteWgKey string) bool {
	if !m.established[remoteWgKey] {
		return true
	}
	m.failures[remoteWgKey]++
	if m.failures[remoteWgKey] >= m.maxRekeyFailures {
		m.failures[remoteWgKey] = 0
		return true
	}
	return false
}

func (m *Manager) raiseFailure(remoteWgKey string, fail bool) {
	if !fail {
		m.logger.Warn("pqkem rekey attempt timed out, will retry next cycle", "peer", remoteWgKey)
		return
	}
	if err := m.wg.OnRekeyFailed(remoteWgKey); err != nil {
		m.logger.Error("pqkem OnRekeyFailed handler error", "peer", remoteWgKey, "err", err)
	}
}

func (m *Manager) retransmit(remoteWgKey string, msg []byte) {
	if err := m.transport.Send(remoteWgKey, msg); err != nil {
		m.logger.Warn("pqkem retransmit failed", "peer", remoteWgKey, "err", err)
	}
}
