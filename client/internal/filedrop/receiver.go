package filedrop

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"time"

	log "github.com/sirupsen/logrus"
)

// ErrStorage indicates the receiver could not stage payload data locally.
var ErrStorage = errors.New("storage failure")

type senderIdentity struct {
	key  PeerKey
	name string
}

// receiver implements the transfer protocol independent of any transport. Every
// operation takes the already-authenticated sender identity and returns domain
// errors for the transport to map.
type receiver struct {
	policy      *PolicyStore
	resolver    PeerResolver
	notifier    Notifier
	offers      *OfferStore
	spool       Sink
	spoolMaxAge time.Duration
}

func newReceiver(cfg ServerConfig, spool Sink, maxAge time.Duration) *receiver {
	return &receiver{
		policy:      cfg.Policy,
		resolver:    cfg.Resolver,
		notifier:    cfg.Notifier,
		offers:      NewOfferStore(cfg.OfferTTL),
		spool:       spool,
		spoolMaxAge: maxAge,
	}
}

// identify maps a source overlay address to a known peer, refusing unknown ones.
func (r *receiver) identify(addr netip.Addr) (senderIdentity, bool) {
	key, name, ok := r.resolver.ResolvePeer(addr.Unmap())
	if !ok {
		return senderIdentity{}, false
	}
	return senderIdentity{key: key, name: name}, true
}

func (r *receiver) submitOffer(sender senderIdentity, req OfferRequest) (Offer, error) {
	if err := validateOffer(req.Files); err != nil {
		return Offer{}, fmt.Errorf("%w: %s", ErrInvalidOffer, err)
	}

	mode := r.policy.Evaluate(sender.key)
	if mode == ModeOff {
		return Offer{}, ErrRefused
	}

	senderName := sender.name
	if senderName == "" {
		senderName = req.SenderName
	}

	decision := DecisionPending
	if mode == ModeAutoAccept {
		decision = DecisionAccepted
	}

	offer := r.offers.Add(sender.key, senderName, req.Files, decision)
	if err := r.spool.Prepare(offer.ID); err != nil {
		r.offers.Remove(offer.ID)
		log.Errorf("prepare spool for offer: %v", err)
		return Offer{}, fmt.Errorf("%w: prepare spool", ErrStorage)
	}

	r.notifyOffer(offer)

	if offer.Decision == DecisionAccepted {
		if completed, done := r.offers.Complete(offer.ID); done {
			r.notifyCompleted(completed)
		}
	}
	return offer, nil
}

func (r *receiver) awaitDecision(ctx context.Context, sender senderIdentity, id OfferID) (Offer, error) {
	return r.offers.Await(ctx, sender.key, id)
}

func (r *receiver) withdraw(sender senderIdentity, id OfferID) error {
	offer, ok := r.offers.Get(sender.key, id)
	if !ok {
		return ErrOfferNotFound
	}

	r.offers.SetState(id, StateCancelled)
	r.offers.Remove(id)
	r.spool.Remove(id)

	offer.State = StateCancelled
	r.notifyWithdrawn(offer)
	return nil
}

func (r *receiver) receivedBytes(sender senderIdentity, id OfferID, index int) (int64, error) {
	offer, ok := r.offers.Get(sender.key, id)
	if !ok || index >= len(offer.Files) {
		return 0, ErrOfferNotFound
	}

	received, err := r.spool.Received(id, index)
	if err != nil {
		log.Debugf("probe spool file: %v", err)
		return 0, fmt.Errorf("%w: read staged size", ErrStorage)
	}
	return received, nil
}

func (r *receiver) upload(sender senderIdentity, id OfferID, index int, offset int64, body io.Reader) error {
	offer, ok := r.offers.Get(sender.key, id)
	if !ok || index >= len(offer.Files) {
		return ErrOfferNotFound
	}
	if offer.Decision != DecisionAccepted {
		return ErrNotAccepted
	}
	if offer.Files[index].Kind == KindText {
		return fmt.Errorf("%w: text payloads carry no body", ErrInvalidOffer)
	}

	size := offer.Files[index].Size
	if offset < 0 || offset > size {
		return fmt.Errorf("%w: offset out of range", ErrInvalidOffer)
	}

	// The decision is read once, at the top, but a whole file goes into this
	// one request: a receiver that declines halfway through would otherwise be
	// streamed the rest of it, into a spool it has already thrown away.
	watched := &acceptedReader{
		r: body,
		accepted: func() bool {
			current, ok := r.offers.Get(sender.key, id)
			return ok && current.Decision == DecisionAccepted
		},
	}

	// Write drains the whole body before returning, so without a reader in
	// between the only progress the receiver would ever report is the finished
	// file. Reports are thinned the same way the sender thins its own.
	staged := &progressReader{
		r:     watched,
		sent:  offset,
		total: size,
		report: func(sent int64) {
			r.offers.SetProgress(id, index, sent)
			r.notifyProgress(offer, index, sent)
		},
	}

	received, err := r.spool.Write(id, index, offer.Files[index].Name, offset, staged, size)

	// A withdrawn offer is an answer, not a failure: the state it moved to is
	// the one the user chose, and the spool is already gone.
	if errors.Is(err, ErrNotAccepted) {
		return err
	}

	r.offers.SetProgress(id, index, received)
	r.notifyProgress(offer, index, received)

	if err != nil {
		r.offers.SetState(id, StateFailed)
		r.notifyFailed(offer, err)
		log.Warnf("file drop receive %s from %s: stage payload %d (%s): %v",
			id, offer.SenderName, index, offer.Files[index].Name, err)
		return fmt.Errorf("%w: stage payload", ErrStorage)
	}

	if completed, ok := r.offers.Complete(id); ok {
		r.notifyCompleted(completed)
	}
	return nil
}

// expireOverdue reclaims offers past their decision deadline and stale spool data.
func (r *receiver) expireOverdue() {
	for _, offer := range r.offers.ExpireOverdue() {
		r.spool.Remove(offer.ID)
		r.notifyFailed(offer, ErrExpired)
	}
	r.spool.Cleanup(r.spoolMaxAge, time.Now())
}

func (r *receiver) close() {
	for _, offer := range r.offers.List() {
		r.offers.Remove(offer.ID)
	}
}

// acceptedReader stops a staged copy as soon as the offer behind it stops being
// accepted. The check runs on the same cadence as progress rather than on every
// read: it takes the offer store's lock, and a request that keeps going for one
// more chunk after a decline costs nothing.
type acceptedReader struct {
	r        io.Reader
	accepted func() bool
	last     time.Time
}

func (a *acceptedReader) Read(b []byte) (int, error) {
	now := time.Now()
	if now.Sub(a.last) >= progressInterval {
		a.last = now
		if !a.accepted() {
			return 0, ErrNotAccepted
		}
	}
	return a.r.Read(b)
}

func (r *receiver) notifyOffer(offer Offer) {
	if r.notifier != nil {
		r.notifier.OnOffer(offer)
	}
}

func (r *receiver) notifyProgress(offer Offer, index int, received int64) {
	if r.notifier != nil {
		r.notifier.OnProgress(offer, index, received)
	}
}

func (r *receiver) notifyCompleted(offer Offer) {
	if r.notifier != nil {
		r.notifier.OnCompleted(offer)
	}
}

func (r *receiver) notifyFailed(offer Offer, err error) {
	if r.notifier != nil {
		r.notifier.OnFailed(offer, err)
	}
}

func (r *receiver) notifyWithdrawn(offer Offer) {
	if r.notifier != nil {
		r.notifier.OnWithdrawn(offer)
	}
}

func validateOffer(files []FileMeta) error {
	if len(files) == 0 {
		return fmt.Errorf("offer announces no files")
	}
	if len(files) > MaxOfferFiles {
		return fmt.Errorf("offer announces more than %d files", MaxOfferFiles)
	}

	for _, f := range files {
		if !f.Kind.valid() {
			return fmt.Errorf("unknown payload kind %s", f.Kind)
		}
		if f.Kind == KindText {
			if len(f.Text) > MaxInlineTextSize {
				return fmt.Errorf("inline text exceeds %d bytes", MaxInlineTextSize)
			}
			continue
		}
		if f.Size < 0 {
			return fmt.Errorf("negative file size")
		}
	}
	return nil
}
