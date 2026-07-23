package pqkem

import (
	"context"
	"time"
)

// handleOffer (responder) derives the PSK, commits it optimistically, and sends the
// answer over the current channel. A duplicate offer (same exchangeID) resends the
// cached answer without re-deriving. The responder is otherwise reactive: no
// retransmit loop.
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
		return m.send(remoteID, last)
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
	ex := m.exchanges[remoteID]
	if ex == nil || ex.id != o.ExchangeID {
		m.mu.Unlock()
		return nil
	}
	ex.state = stateAwaitingConfirm
	ex.lastSent = raw
	ex.pendingPSK = psk
	m.mu.Unlock()

	// Commit optimistically so our data path can rekey to the new PSK; a lost answer
	// simply means the data path won't come up (initial) or the previous PSK keeps
	// working until it does (rekey grace) — both self-heal via retry.
	if err := m.cbHandler.OnNewPSKReady(remoteID, psk); err != nil {
		return err
	}
	return m.send(remoteID, raw)
}

// handleAnswer (initiator) derives and commits the PSK, then waits for
// OnDataPathRekeyed to send the confirm. Only valid in stateAwaitingAnswer;
// advancing the state under the lock makes a concurrent/duplicate answer bail.
func (m *Manager) handleAnswer(remoteID string, a *AnswerMsg) error {
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
	// Commit now; the confirm is deferred until OnDataPathRekeyed so it rides the
	// data path under the new key.
	return m.cbHandler.OnNewPSKReady(remoteID, psk)
}

// handleConfirm (responder) records convergence. The PSK was already committed in
// handleOffer; a confirm arriving over the data path with a matching exchangeID
// proves we operate on the new key from this exchange. Stale/duplicate confirms find
// the exchange gone and are ignored.
func (m *Manager) handleConfirm(remoteID string, c *ConfirmMsg) error {
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

// initiatorLoop retransmits the initiator's outstanding message and enforces the
// convergence deadline, keyed off the exchange state: resend the offer while
// awaiting the answer; wait (counting toward the deadline) while awaiting the data
// path rekey; resend the confirm a few best-effort times once sent. Exhausting the
// deadline before reaching the confirm phase is a failure.
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
				msg := ex.lastSent
				attempts++
				m.mu.Unlock()
				if err := m.send(remoteID, msg); err != nil {
					m.logger.Warn("pqkem offer retransmit failed", "peer", remoteID, "err", err)
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
				if err := m.transport.SendDataPath(remoteID, msg); err != nil {
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
