package peer

import (
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func newTestHandshaker(t *testing.T) *Handshaker {
	t.Helper()
	// The tests exercise the answer path, whose Listen branch dispatches to the
	// relay listener without sending an answer, so no signaler/ICE/relay is needed.
	return NewHandshaker(log.WithField("test", t.Name()), ConnConfig{}, nil, nil, nil, nil)
}

// TestHandshakerHoldsSignalArrivingBeforeListen covers the case where a peer is
// activated by an incoming signal: the remote's offer/answer arrives in the same
// step that opens the connection, before the Listen loop starts reading. The
// message must be held rather than dropped, or the connection cannot proceed until
// the remote re-sends. This is the path taken when an eager peer connects to a
// lazily-managed one.
func TestHandshakerHoldsSignalArrivingBeforeListen(t *testing.T) {
	h := newTestHandshaker(t)

	processed := make(chan *OfferAnswer, 4)
	h.AddRelayListener(func(o *OfferAnswer) { processed <- o })

	// Delivered before Listen is reading, as when the peer is woken by the remote's
	// signal and the message is delivered right after Open.
	h.OnRemoteAnswer(OfferAnswer{WgListenPort: 51820})

	go h.Listen(t.Context())

	select {
	case <-processed:
	case <-time.After(2 * time.Second):
		assert.Fail(t, "remote-answer dispatch: signal delivered before Listen was ready was dropped")
	}
}

// TestHandshakerKeepsLatestSignalBeforeListen covers several signals arriving
// before Listen reads: the newest must win (matching the latest-offer contract),
// rather than the first being kept and later ones discarded.
func TestHandshakerKeepsLatestSignalBeforeListen(t *testing.T) {
	h := newTestHandshaker(t)

	processed := make(chan *OfferAnswer, 4)
	h.AddRelayListener(func(o *OfferAnswer) { processed <- o })

	h.OnRemoteAnswer(OfferAnswer{WgListenPort: 1111})
	h.OnRemoteAnswer(OfferAnswer{WgListenPort: 2222})

	go h.Listen(t.Context())

	select {
	case got := <-processed:
		assert.Equal(t, 2222, got.WgListenPort, "remote-answer dispatch: the latest queued signal should be processed")
	case <-time.After(2 * time.Second):
		assert.Fail(t, "remote-answer dispatch: queued signal was dropped")
	}
}
