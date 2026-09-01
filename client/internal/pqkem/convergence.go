package pqkem

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"
)

// idHex renders an exchange ID for logs.
func idHex(id ExchangeID) string { return hex.EncodeToString(id[:]) }

// exchangeKind labels an exchange for logs by whether it acknowledges a prior one: a
// zero AckID is a bootstrap (a new connection's first exchange, or a re-bootstrap after
// a reconnect), a non-zero AckID is a rotation (a rekey chained off the previous PSK).
func exchangeKind(ackID ExchangeID) string {
	if ackID == (ExchangeID{}) {
		return "bootstrap"
	}
	return "rotation"
}

// viaSignal maps the transport a message arrived on / goes out on to a log label.
const (
	viaSignalLabel   = "signal"
	viaDataPathLabel = "data-path"
)

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
// startExchangeLocked must be called with m.mu held: the caller's idempotency check and
// the exchange install stay under one lock acquisition so two concurrent starts for the
// same peer cannot both create an exchange. It also refuses to start (and to Add to the
// wait group) once the manager is stopping, so it never races Manager.Stop's Wait.
func (m *Manager) startExchangeLocked(remoteID RemoteID, viaSignal bool, ackID ExchangeID) ([]byte, error) {
	if m.rootCtx.Err() != nil {
		return nil, fmt.Errorf("manager stopping")
	}
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

	m.wait.Add(1)
	go m.initiatorLoop(ctx, remoteID, id)

	via := viaDataPathLabel
	if viaSignal {
		via = viaSignalLabel
	}
	m.debug("pqkem: sending offer", "peer", remoteID, "exchange", idHex(id), "role", "initiator", "via", via, "kind", exchangeKind(ackID), "acks", idHex(ackID))
	return raw, nil
}

// processOffer (responder) first acknowledges the previous exchange the offer names
// (that offer riding the data path under the freshly adopted key proves it worked),
// then derives the PSK for the new offer, commits it optimistically, and returns the
// framed answer. A duplicate offer returns the cached answer without re-deriving.
func (m *Manager) processOffer(remoteID RemoteID, o *OfferMsg, via string) ([]byte, error) {
	kind := exchangeKind(o.AckID)
	m.debug("pqkem: offer received", "peer", remoteID, "exchange", idHex(o.ExchangeID), "role", "responder", "via", via, "kind", kind, "acks", idHex(o.AckID))

	// Role guard: only the responder processes offers. The KEM is unidirectional — the
	// initiator sends offers, the responder answers — so an offer reaching the initiator
	// is anomalous (desync, duplicate, or an injected/spoofed packet). Processing it would
	// derive and commit a fresh PSK, overwriting a live one and silently discarding any
	// in-flight exchange (whose retry loop then exits without recovery). Drop it.
	if m.IsInitiator(remoteID) {
		m.debug("pqkem: dropping offer, we are the initiator for this peer (role violation)", "peer", remoteID, "exchange", idHex(o.ExchangeID), "via", via, "kind", kind)
		return nil, nil
	}

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

	m.debug("pqkem: PSK derived", "peer", remoteID, "exchange", idHex(o.ExchangeID), "role", "responder", "via", via, "kind", kind, "psk_fp", pskFingerprint(psk))

	// Commit optimistically so our data path can rekey to the new PSK.
	if err := m.cbHandler.OnNewPSKReady(remoteID, psk); err != nil {
		return nil, err
	}
	m.trace("pqkem: answer sent", "peer", remoteID, "exchange", idHex(o.ExchangeID))
	return raw, nil
}

// processAnswer (initiator) derives and commits the PSK and parks in
// stateAwaitingRekey; the next offer (chained from OnDataPathRekeyed) will acknowledge
// this exchange. Only valid in stateAwaitingAnswer; advancing the state under the
// lock makes a concurrent/duplicate answer bail.
func (m *Manager) processAnswer(remoteID RemoteID, a *AnswerMsg, via string) error {
	// Role guard: only the initiator processes answers. An answer reaching the responder
	// is anomalous (the responder sends answers, it never receives them) — drop it rather
	// than let a stray/injected answer disturb the responder's state.
	if !m.IsInitiator(remoteID) {
		m.debug("pqkem: dropping answer, we are the responder for this peer (role violation)", "peer", remoteID, "answer_for", idHex(a.ExchangeID), "via", via)
		return nil
	}

	m.mu.Lock()
	ex := m.exchanges[remoteID]
	if ex == nil || ex.id != a.ExchangeID || ex.state != stateAwaitingAnswer {
		haveID := "none"
		if ex != nil {
			haveID = idHex(ex.id)
		}
		m.mu.Unlock()
		m.trace("pqkem: unexpected answer dropped (inconsistency)", "peer", remoteID, "answer_for", idHex(a.ExchangeID), "have_exchange", haveID, "via", via)
		return nil
	}
	// The initiator's exchange kind: a signalling exchange is a bootstrap/re-bootstrap, a
	// data-path one is a rotation chained off the previous PSK.
	kind := "rotation"
	if ex.viaSignal {
		kind = "bootstrap"
	}
	ex.state = stateAwaitingRekey
	init := ex.initiator
	ex.initiator = nil
	m.mu.Unlock()

	m.trace("pqkem: answer received", "peer", remoteID, "exchange", idHex(a.ExchangeID), "via", via, "kind", kind)

	psk, err := init.Finish(a.KEMAnswer, m.binding(remoteID))
	if err != nil {
		// The state already advanced to stateAwaitingRekey and the initiator was cleared,
		// so initiatorLoop would exit its default branch without registering a failure —
		// leaving the peer desynced (the responder committed its PSK in processOffer).
		// Drop the exchange and raise the failure so recovery re-bootstraps.
		m.mu.Lock()
		if cur := m.exchanges[remoteID]; cur != nil && cur.id == a.ExchangeID {
			delete(m.exchanges, remoteID)
		}
		initial := !m.established[remoteID]
		fail := m.registerFailureLocked(remoteID)
		m.mu.Unlock()
		m.raiseFailure(remoteID, fail, initial)
		return err
	}

	// The initiator has converged: the responder must have derived the key to answer.
	m.mu.Lock()
	m.established[remoteID] = true
	m.failures[remoteID] = 0
	m.psks[remoteID] = psk
	m.capable[remoteID] = true // a real KEM answer proves the peer runs the exchange
	m.mu.Unlock()

	m.debug("pqkem: PSK derived", "peer", remoteID, "exchange", idHex(a.ExchangeID), "role", "initiator", "via", via, "kind", kind, "psk_fp", pskFingerprint(psk))

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
