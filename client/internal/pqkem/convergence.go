package pqkem

import (
	"context"
	"time"
)

// startExchange creates a fresh initiator exchange (acknowledging ackID, zero for a
// bootstrap) and returns the framed offer for the caller to send — pushed over the
// data path for a chained rekey, or handed to the host for signalling when viaSignal
// is set. Any previous in-flight exchange for the peer is cancelled.
func (m *Manager) startExchange(remoteID RemoteID, viaSignal bool, ackID ExchangeID) ([]byte, error) {
	init, err := NewInitiator()
	if err != nil {
		return nil, err
	}
	id, err := newExchangeID()
	if err != nil {
		return nil, err
	}
	raw, err := (&OfferMsg{ExchangeID: id, AckID: ackID, KEMOffer: init.Offer()}).Encode()
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

// processOffer (responder) first acknowledges the previous exchange the offer names
// (that offer riding the data path under the freshly adopted key proves it worked),
// then derives the PSK for the new offer, commits it optimistically, and returns the
// framed answer. A duplicate offer returns the cached answer without re-deriving.
func (m *Manager) processOffer(remoteID RemoteID, o *OfferMsg) ([]byte, error) {
	if o.AckID != (ExchangeID{}) {
		m.ackConverged(remoteID, o.AckID)
	}

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
	ex.state = stateAwaitingAck
	ex.lastSent = raw
	ex.pendingPSK = psk
	m.psks[remoteID] = psk
	m.mu.Unlock()

	// Commit optimistically so our data path can rekey to the new PSK.
	if err := m.cbHandler.OnNewPSKReady(remoteID, psk); err != nil {
		return nil, err
	}
	return raw, nil
}

// processAnswer (initiator) derives and commits the PSK and parks in
// stateAwaitingRekey; the next offer (chained from OnDataPathRekeyed) will acknowledge
// this exchange. Only valid in stateAwaitingAnswer; advancing the state under the
// lock makes a concurrent/duplicate answer bail.
func (m *Manager) processAnswer(remoteID RemoteID, a *AnswerMsg) error {
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

	// The initiator has converged: the responder must have derived the key to answer.
	m.mu.Lock()
	m.established[remoteID] = true
	m.failures[remoteID] = 0
	m.psks[remoteID] = psk
	m.mu.Unlock()

	return m.cbHandler.OnNewPSKReady(remoteID, psk)
}

// ackConverged (responder) records convergence of the exchange named by ackID: a
// later offer acknowledging it proves both sides operate on that exchange's key. Only
// acts on a matching stateAwaitingAck exchange; anything else is ignored.
func (m *Manager) ackConverged(remoteID RemoteID, ackID ExchangeID) {
	m.mu.Lock()
	ex := m.exchanges[remoteID]
	if ex == nil || ex.id != ackID || ex.state != stateAwaitingAck {
		m.mu.Unlock()
		return
	}
	delete(m.exchanges, remoteID)
	m.established[remoteID] = true
	m.failures[remoteID] = 0
	_ = time.Since(ex.startedAt) // convergence latency (metrics hook, later step)
	m.mu.Unlock()
}

// initiatorLoop enforces the offer->answer convergence deadline and retransmits the
// initiator's outstanding data-path offer while awaiting the answer (a
// signalling-bootstrapped offer is retransmitted by the host, so it is not resent
// here). Exhausting the deadline before the answer arrives is a failure. Once the
// answer is in (state past awaitingAnswer) the loop exits: the next rotation is driven
// by OnDataPathRekeyed, and the idle wait for it has no deadline.
func (m *Manager) initiatorLoop(ctx context.Context, remoteID RemoteID, id ExchangeID) {
	defer m.wait.Done()
	t := time.NewTicker(m.retryInterval)
	defer t.Stop()

	attempts := 0
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
						m.logger.Warn("pqkem: offer retransmit failed", "peer", remoteID, "err", err)
					}
				}

			default:
				// Past awaiting the answer (converged) or superseded: the loop's job
				// is done. The next rotation is driven externally by OnDataPathRekeyed,
				// so there is no deadline while idle-waiting for it (that wait can be
				// as long as the transport's natural rekey interval).
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
func (m *Manager) registerFailureLocked(remoteID RemoteID) bool {
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

func (m *Manager) raiseFailure(remoteID RemoteID, fail bool) {
	if !fail {
		m.logger.Warn("pqkem: rekey attempt timed out, will retry next cycle", "peer", remoteID)
		return
	}
	if err := m.cbHandler.OnRekeyFailed(remoteID); err != nil {
		m.logger.Error("pqkem: OnRekeyFailed handler error", "peer", remoteID, "err", err)
	}
}
