package pqkem

import (
	"context"
	"time"
)

// handleOffer (responder) derives and sends the answer for a new exchange, or
// resends the cached answer for a duplicate offer (same exchangeID) without
// re-deriving. The responder is purely reactive: no retransmit loop, no deadline.
func (d *Driver) handleOffer(remoteWgKey string, o *OfferMsg) error {
	d.mu.Lock()
	if ex := d.exchanges[remoteWgKey]; ex != nil && ex.id == o.ExchangeID {
		last := ex.lastSent
		d.mu.Unlock()
		if last == nil {
			// another goroutine reserved this exchange and is deriving the answer;
			// it will send it. Dropping this duplicate avoids a second derivation
			// (Respond is randomized -> a different PSK).
			return nil
		}
		return d.transport.Send(remoteWgKey, last)
	}
	// Reserve the slot (lastSent nil = deriving) so a concurrent duplicate offer bails.
	d.exchanges[remoteWgKey] = &exchangeCtl{
		id:        o.ExchangeID,
		startedAt: time.Now(),
		isInitial: !d.established[remoteWgKey],
	}
	d.mu.Unlock()

	answer, err := d.mgr.HandleOffer(remoteWgKey, o)
	if err != nil {
		return err
	}
	raw, err := answer.Encode()
	if err != nil {
		return err
	}

	d.mu.Lock()
	if ex := d.exchanges[remoteWgKey]; ex != nil && ex.id == o.ExchangeID {
		ex.lastSent = raw
	}
	d.mu.Unlock()

	return d.transport.Send(remoteWgKey, raw)
}

// handleAnswer (initiator) derives the PSK, surfaces it, and sends the confirm. The
// exchange then switches its retransmit payload to the confirm. Stale or duplicate
// answers are ignored.
func (d *Driver) handleAnswer(remoteWgKey string, a *AnswerMsg) error {
	// Claim the answer under the lock (set answered) so a concurrent/duplicate answer
	// bails before calling the Manager.
	d.mu.Lock()
	ex := d.exchanges[remoteWgKey]
	if ex == nil || ex.id != a.ExchangeID || ex.cancel == nil || ex.answered {
		d.mu.Unlock()
		return nil
	}
	ex.answered = true
	d.mu.Unlock()

	psk, confirm, err := d.mgr.HandleAnswer(remoteWgKey, a)
	if err != nil {
		return err
	}
	if err := d.wg.OnNewPSKReady(remoteWgKey, psk); err != nil {
		return err
	}
	raw, err := confirm.Encode()
	if err != nil {
		return err
	}

	d.mu.Lock()
	if ex := d.exchanges[remoteWgKey]; ex != nil && ex.id == a.ExchangeID {
		ex.lastSent = raw // loop now retransmits the confirm
		d.established[remoteWgKey] = true
		d.failures[remoteWgKey] = 0
		_ = time.Since(ex.startedAt) // convergence latency (metrics hook, later step)
	}
	d.mu.Unlock()

	return d.transport.Send(remoteWgKey, raw)
}

// handleConfirm (responder) commits the pending PSK. Stale or duplicate confirms
// (the initiator best-effort resends it) are ignored.
func (d *Driver) handleConfirm(remoteWgKey string, c *ConfirmMsg) error {
	// Claim-and-remove the exchange under the lock so a duplicate confirm (the
	// initiator best-effort resends it) bails before calling the Manager.
	d.mu.Lock()
	ex := d.exchanges[remoteWgKey]
	if ex == nil || ex.id != c.ExchangeID {
		d.mu.Unlock()
		return nil
	}
	delete(d.exchanges, remoteWgKey)
	d.established[remoteWgKey] = true
	d.failures[remoteWgKey] = 0
	_ = time.Since(ex.startedAt) // convergence latency (metrics hook, later step)
	d.mu.Unlock()

	psk, err := d.mgr.HandleConfirm(remoteWgKey, c)
	if err != nil {
		return err
	}
	return d.wg.OnNewPSKReady(remoteWgKey, psk)
}

// initiatorLoop retransmits the initiator's outstanding message: the offer until
// the answer arrives (bounded by maxRetries -> failure), then the confirm a few
// best-effort times before stopping. The convergence deadline is thus derived from
// maxRetries * retryInterval; there is no separate deadline timer.
func (d *Driver) initiatorLoop(ctx context.Context, remoteWgKey string, id ExchangeID) {
	defer d.wait.Done()
	t := time.NewTicker(d.retryInterval)
	defer t.Stop()

	offerAttempts, confirmsSent := 0, 0
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			d.mu.Lock()
			ex := d.exchanges[remoteWgKey]
			if ex == nil || ex.id != id {
				d.mu.Unlock()
				return
			}

			if !ex.answered {
				if offerAttempts >= d.maxRetries {
					delete(d.exchanges, remoteWgKey)
					fail := d.registerFailureLocked(remoteWgKey, ex.isInitial)
					d.mu.Unlock()
					d.raiseFailure(remoteWgKey, fail)
					return
				}
				msg := ex.lastSent
				offerAttempts++
				d.mu.Unlock()
				d.retransmit(remoteWgKey, msg)
				continue
			}

			if confirmsSent >= confirmRetransmits {
				delete(d.exchanges, remoteWgKey)
				d.mu.Unlock()
				return
			}
			msg := ex.lastSent
			confirmsSent++
			d.mu.Unlock()
			d.retransmit(remoteWgKey, msg)
		}
	}
}

// registerFailureLocked applies policy B and reports whether OnRekeyFailed is due:
// the initial exchange fails immediately; a rekey tolerates up to maxRekeyFailures
// consecutive misses (we stay on the still-valid previous PSK) before failing.
// Assumes d.mu is held.
func (d *Driver) registerFailureLocked(remoteWgKey string, isInitial bool) bool {
	if isInitial {
		return true
	}
	d.failures[remoteWgKey]++
	if d.failures[remoteWgKey] >= d.maxRekeyFailures {
		d.failures[remoteWgKey] = 0
		return true
	}
	return false
}

func (d *Driver) raiseFailure(remoteWgKey string, fail bool) {
	if !fail {
		d.logger.Warn("pqkem rekey attempt timed out, will retry next cycle", "peer", remoteWgKey)
		return
	}
	if err := d.wg.OnRekeyFailed(remoteWgKey); err != nil {
		d.logger.Error("pqkem OnRekeyFailed handler error", "peer", remoteWgKey, "err", err)
	}
}

func (d *Driver) retransmit(remoteWgKey string, msg []byte) {
	if err := d.transport.Send(remoteWgKey, msg); err != nil {
		d.logger.Warn("pqkem retransmit failed", "peer", remoteWgKey, "err", err)
	}
}
