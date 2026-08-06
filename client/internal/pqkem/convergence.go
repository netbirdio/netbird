package pqkem

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"time"
)

// idHex renders an exchange ID for logs.
func idHex(id ExchangeID) string { return hex.EncodeToString(id[:]) }

// pskFingerprint is a short, non-secret digest of a derived PSK: identical on both
// peers iff they derived the same key. Logged instead of the raw PSK so debug logs
// never carry the actual WireGuard preshared key.
func pskFingerprint(psk PSK) string {
	sum := sha256.Sum256(psk[:])
	return hex.EncodeToString(sum[:8])
}

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

	via := "data-path"
	if viaSignal {
		via = "signal"
	}
	m.trace("pqkem: offer sent", "peer", remoteID, "exchange", idHex(id), "acks", idHex(ackID), "via", via)
	return raw, nil
}

// processOffer (responder) first acknowledges the previous exchange the offer names
// (that offer riding the data path under the freshly adopted key proves it worked),
// then derives the PSK for the new offer, commits it optimistically, and returns the
// framed answer. A duplicate offer returns the cached answer without re-deriving.
func (m *Manager) processOffer(remoteID RemoteID, o *OfferMsg, viaSignal bool) ([]byte, error) {
	m.trace("pqkem: offer received", "peer", remoteID, "exchange", idHex(o.ExchangeID), "acks", idHex(o.AckID))

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
		m.trace("pqkem: duplicate offer, resending cached answer", "peer", remoteID, "exchange", idHex(o.ExchangeID))
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
		m.trace("pqkem: exchange superseded during respond, dropping answer", "peer", remoteID, "exchange", idHex(o.ExchangeID))
		return nil, nil
	}
	ex.state = stateAwaitingAck
	ex.lastSent = raw
	ex.pendingPSK = psk
	m.psks[remoteID] = psk
	m.capable[remoteID] = true // a real KEM offer proves the peer runs the exchange
	m.mu.Unlock()

	m.trace("pqkem: new PSK derived", "peer", remoteID, "exchange", idHex(o.ExchangeID), "role", "responder", "psk_fp", pskFingerprint(psk))

	// Commit optimistically so our data path can rekey to the new PSK.
	if err := m.cbHandler.OnNewPSKReady(remoteID, psk, viaSignal); err != nil {
		return nil, err
	}
	m.trace("pqkem: answer sent", "peer", remoteID, "exchange", idHex(o.ExchangeID))
	return raw, nil
}

// processAnswer (initiator) derives and commits the PSK and parks in
// stateAwaitingRekey; the next offer (chained from OnDataPathRekeyed) will acknowledge
// this exchange. Only valid in stateAwaitingAnswer; advancing the state under the
// lock makes a concurrent/duplicate answer bail.
func (m *Manager) processAnswer(remoteID RemoteID, a *AnswerMsg, viaSignal bool) error {
	m.mu.Lock()
	ex := m.exchanges[remoteID]
	if ex == nil || ex.id != a.ExchangeID || ex.state != stateAwaitingAnswer {
		haveID := "none"
		if ex != nil {
			haveID = idHex(ex.id)
		}
		m.mu.Unlock()
		m.trace("pqkem: unexpected answer dropped (inconsistency)", "peer", remoteID, "answer_for", idHex(a.ExchangeID), "have_exchange", haveID)
		return nil
	}
	ex.state = stateAwaitingRekey
	init := ex.initiator
	ex.initiator = nil
	m.mu.Unlock()

	m.trace("pqkem: answer received", "peer", remoteID, "exchange", idHex(a.ExchangeID))

	psk, err := init.Finish(a.KEMAnswer, m.binding(remoteID))
	if err != nil {
		return err
	}

	// The initiator has converged: the responder must have derived the key to answer.
	m.mu.Lock()
	m.established[remoteID] = true
	m.failures[remoteID] = 0
	m.psks[remoteID] = psk
	m.capable[remoteID] = true // a real KEM answer proves the peer runs the exchange
	m.mu.Unlock()

	m.trace("pqkem: new PSK derived", "peer", remoteID, "exchange", idHex(a.ExchangeID), "role", "initiator", "psk_fp", pskFingerprint(psk))

	return m.cbHandler.OnNewPSKReady(remoteID, psk, viaSignal)
}

// ackConverged (responder) records convergence of the exchange named by ackID: a
// later offer acknowledging it proves both sides operate on that exchange's key. Only
// acts on a matching stateAwaitingAck exchange; anything else is ignored.
func (m *Manager) ackConverged(remoteID RemoteID, ackID ExchangeID) {
	m.mu.Lock()
	ex := m.exchanges[remoteID]
	if ex == nil || ex.id != ackID || ex.state != stateAwaitingAck {
		m.mu.Unlock()
		m.trace("pqkem: ack for unknown/mismatched exchange, ignored (inconsistency)", "peer", remoteID, "acks", idHex(ackID))
		return
	}
	delete(m.exchanges, remoteID)
	m.established[remoteID] = true
	m.failures[remoteID] = 0
	_ = time.Since(ex.startedAt) // convergence latency (metrics hook, later step)
	m.mu.Unlock()

	m.trace("pqkem: previous exchange confirmed by ack", "peer", remoteID, "exchange", idHex(ackID))
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
					initial := !m.established[remoteID]
					fail := m.registerFailureLocked(remoteID)
					m.mu.Unlock()
					m.raiseFailure(remoteID, fail, initial)
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

// raiseFailure reports a convergence failure. initial distinguishes a never-established
// peer (bootstrap failed → no PQ PSK at all; in strict mode the peer stays blocked =
// "stuck") from a rekey failure (a previous PSK is still in force and traffic continues).
func (m *Manager) raiseFailure(remoteID RemoteID, fail, initial bool) {
	if !fail {
		m.logger.Warn("pqkem: rekey attempt timed out, will retry next cycle", "peer", remoteID)
		return
	}
	if initial {
		m.logger.Warn("pqkem: initial exchange failed — no PQ PSK established for peer (strict mode keeps the peer blocked until it converges)", "peer", remoteID)
	} else {
		m.logger.Warn("pqkem: rekey failed after retries — staying on the previous PSK", "peer", remoteID)
	}
	if err := m.cbHandler.OnRekeyFailed(remoteID); err != nil {
		m.logger.Error("pqkem: OnRekeyFailed handler error", "peer", remoteID, "err", err)
	}
}
