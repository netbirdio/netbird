package peer

import (
	"testing"

	"github.com/netbirdio/netbird/client/internal/peer/signaling"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMailbox_OfferCoalescing(t *testing.T) {
	mb := newMailbox()

	require.True(t, mb.post(evRemoteOffer{offer: signaling.OfferAnswer{WgListenPort: 1}}))
	require.True(t, mb.post(evRemoteOffer{offer: signaling.OfferAnswer{WgListenPort: 2}}))
	require.True(t, mb.post(evRemoteOffer{offer: signaling.OfferAnswer{WgListenPort: 3}}))

	evs := mb.drain()
	require.Len(t, evs, 1, "consecutive offers must coalesce to a single event")
	offer, ok := evs[0].(evRemoteOffer)
	require.True(t, ok, "coalesced event must be an offer")
	assert.Equal(t, 3, offer.offer.WgListenPort, "the newest offer must win")
}

func TestMailbox_OfferFlushesCandidates(t *testing.T) {
	mb := newMailbox()

	require.True(t, mb.post(evRemoteCandidate{}))
	require.True(t, mb.post(evRemoteCandidate{}))
	require.True(t, mb.post(evRemoteOffer{offer: signaling.OfferAnswer{}}))

	evs := mb.drain()
	require.Len(t, evs, 1, "candidates of the superseded session must be flushed")
	_, ok := evs[0].(evRemoteOffer)
	assert.True(t, ok, "only the offer must remain after the flush")
}

func TestMailbox_CandidatesKeepOrderAfterOffer(t *testing.T) {
	mb := newMailbox()

	require.True(t, mb.post(evRemoteOffer{offer: signaling.OfferAnswer{}}))
	require.True(t, mb.post(evRemoteCandidate{haRoutes: nil}))
	require.True(t, mb.post(evRemoteCandidate{haRoutes: nil}))

	evs := mb.drain()
	require.Len(t, evs, 3)
	_, ok := evs[0].(evRemoteOffer)
	assert.True(t, ok, "offer must be processed before the candidates")
	for _, ev := range evs[1:] {
		_, ok := ev.(evRemoteCandidate)
		assert.True(t, ok, "candidates posted after the offer must survive")
	}
}

func TestMailbox_CandidateQueueBounded(t *testing.T) {
	mb := newMailbox()

	for i := 0; i < maxQueuedCandidates+10; i++ {
		require.True(t, mb.post(evRemoteCandidate{}))
	}

	evs := mb.drain()
	assert.Len(t, evs, maxQueuedCandidates, "candidate queue must stay bounded")
}

func TestMailbox_DrainOrder(t *testing.T) {
	mb := newMailbox()

	require.True(t, mb.post(evGuardTick{}))
	require.True(t, mb.post(evRemoteAnswer{answer: signaling.OfferAnswer{}}))
	require.True(t, mb.post(evRemoteOffer{offer: signaling.OfferAnswer{}}))
	require.True(t, mb.post(evRelayDown{}))
	require.True(t, mb.post(evICEDown{sessionChanged: true}))
	require.True(t, mb.post(evClose{}))

	evs := mb.drain()
	require.Len(t, evs, 6)

	_, ok := evs[0].(evClose)
	assert.True(t, ok, "lifecycle events must come first")
	_, ok = evs[1].(evRelayDown)
	assert.True(t, ok, "transport events must keep FIFO order")
	_, ok = evs[2].(evICEDown)
	assert.True(t, ok, "transport events must keep FIFO order")
	_, ok = evs[3].(evRemoteOffer)
	assert.True(t, ok, "offer must come after transport events")
	_, ok = evs[4].(evRemoteAnswer)
	assert.True(t, ok, "answer must come after the offer")
	_, ok = evs[5].(evGuardTick)
	assert.True(t, ok, "guard tick must come last")
}

func TestMailbox_GuardTickCoalesced(t *testing.T) {
	mb := newMailbox()

	require.True(t, mb.post(evGuardTick{}))
	require.True(t, mb.post(evGuardTick{}))
	require.True(t, mb.post(evGuardTick{}))

	evs := mb.drain()
	assert.Len(t, evs, 1, "guard ticks must coalesce to a single event")
}

func TestMailbox_PostAfterCloseRejected(t *testing.T) {
	mb := newMailbox()

	require.True(t, mb.post(evRelayDown{}))
	leftovers := mb.closeAndDrain()
	assert.Len(t, leftovers, 1, "pending events must be returned on close")

	assert.False(t, mb.post(evRelayDown{}), "posts must be rejected after close")
	assert.Empty(t, mb.drain(), "no events must remain after close")
}

func TestMailbox_WakeSignal(t *testing.T) {
	mb := newMailbox()

	require.True(t, mb.post(evRelayDown{}))
	require.True(t, mb.post(evGuardTick{}))

	select {
	case <-mb.wake:
	default:
		t.Fatal("wake signal must be pending after posts")
	}

	assert.Len(t, mb.drain(), 2, "a single wake must deliver all pending events")
}
