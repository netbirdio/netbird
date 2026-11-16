package pqkem

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestManager_NonCapablePeerNotOffered: a peer known not to run the KEM (it answered our
// offer with an empty KEM payload over signalling) is never offered an exchange, and no
// failure is raised — this is what stops the recovery storm against non-PQ peers (e.g.
// Rosenpass peers).
func TestManager_NonCapablePeerNotOffered(t *testing.T) {
	wg := newFakeWG()
	d := NewManager("bbbb", wg, nil) // initiator vs "aaaa"
	d.Start(&loopback{ep: epB, sw: newSwitch()})
	defer d.Stop()

	d.MarkNonCapable("aaaa")

	offer, err := d.SignalOffer("aaaa")
	require.NoError(t, err)
	assert.Nil(t, offer, "a non-capable peer must not be offered a KEM exchange")
	assert.Empty(t, wg.failed, "a non-capable peer must not raise a rekey failure")
}

// TestManager_MarkNonCapableCancelsInFlight: if we start an exchange with a peer whose
// capability is not yet known and then learn it does not run the KEM, the in-flight
// exchange is cancelled and no further offer is produced (no timeout -> no failure).
func TestManager_MarkNonCapableCancelsInFlight(t *testing.T) {
	wg := newFakeWG()
	d := NewManager("bbbb", wg, nil)
	d.Start(&loopback{ep: epB, sw: newSwitch()})
	defer d.Stop()

	// Capability unknown -> the bootstrap offer goes out optimistically.
	offer, err := d.SignalOffer("aaaa")
	require.NoError(t, err)
	require.NotNil(t, offer)

	// Record the cancellation of the in-flight exchange's loop. Without it the loop would
	// time out and raise OnRekeyFailed, the re-bootstrap storm MarkNonCapable prevents.
	var cancelled atomic.Bool
	d.mu.Lock()
	ex := d.exchanges["aaaa"]
	if ex != nil {
		loopCancel := ex.cancel
		ex.cancel = func() {
			cancelled.Store(true)
			loopCancel()
		}
	}
	d.mu.Unlock()
	// Asserted after unlocking: a failing require stops the test, and the deferred Stop
	// would then block on the lock.
	require.NotNil(t, ex, "precondition: the bootstrap exchange is in flight")

	// Now we learn the peer is non-PQ: the exchange must be dropped.
	d.MarkNonCapable("aaaa")

	assert.True(t, cancelled.Load(), "the in-flight exchange's loop must be cancelled")
	d.mu.Lock()
	_, stillTracked := d.exchanges["aaaa"]
	d.mu.Unlock()
	assert.False(t, stillTracked, "the in-flight exchange must be dropped")

	next, err := d.SignalOffer("aaaa")
	require.NoError(t, err)
	assert.Nil(t, next, "after learning non-capability the peer is no longer offered")
	assert.Empty(t, wg.failed, "cancelling an in-flight exchange must not raise a failure")
}

// TestManager_EstablishedPeerDowngraded: every failure sends an error marker, so a missing
// KEM from an established peer means it restarted without the KEM. Keeping the PSK would
// program a key the peer no longer has and the tunnel would never come up, so it is dropped
// and the peer is no longer offered.
func TestManager_EstablishedPeerDowngraded(t *testing.T) {
	dA, dB, _, wgB, _ := pair(t)
	defer dA.Stop()
	defer dB.Stop()

	bootstrap(t, dA, dB)
	require.NotEqual(t, PSK{}, wgB.psk("aaaa"), "established a PSK")

	assert.True(t, dB.MarkNonCapable("aaaa"), "dropping an established PSK must be reported")

	_, ok := dB.PSK("aaaa")
	assert.False(t, ok, "a downgraded peer must not keep its PSK")
	offer, err := dB.SignalOffer("aaaa")
	require.NoError(t, err)
	assert.Nil(t, offer, "a downgraded peer must not be offered")
	assert.False(t, dB.MarkNonCapable("aaaa"), "a peer already downgraded has no PSK left to drop")
}

// TestManager_ClearNonCapableReoffers: a peer found non-capable is offered again once the
// host learns it runs the KEM, and the exchange converges.
func TestManager_ClearNonCapableReoffers(t *testing.T) {
	dA, dB, wgA, wgB, _ := pair(t)
	defer dA.Stop()
	defer dB.Stop()

	assert.False(t, dB.MarkNonCapable("aaaa"), "a peer never established is not a downgrade")
	require.False(t, dB.ShouldSendBootstrapOffer("aaaa"), "precondition: not offered")

	dB.ClearNonCapable("aaaa")

	assert.True(t, dB.ShouldSendBootstrapOffer("aaaa"), "a cleared peer must be offered again")
	bootstrap(t, dA, dB)
	assert.Equal(t, wgB.psk("aaaa"), wgA.psk("bbbb"), "the renewed exchange must converge")
}

// TestManager_ErrorMarkerIsBenign verifies finding F's wire half: a responder failure is
// signalled with an error marker (not an empty answer), so the initiator does not read it
// as "peer has no KEM". The marker must be benign — it must not disturb the in-flight
// exchange, which still converges when the real answer arrives.
func TestManager_ErrorMarkerIsBenign(t *testing.T) {
	dA, dB, wgA, wgB, _ := pair(t) // dB ("bbbb") initiator, dA ("aaaa") responder
	defer dA.Stop()
	defer dB.Stop()

	offer, err := dB.SignalOffer("aaaa")
	require.NoError(t, err)
	require.NotNil(t, offer)

	_, decoded, err := Decode(offer)
	require.NoError(t, err)
	offerID := decoded.(*OfferMsg).ExchangeID

	// An error marker for the in-flight offer must be accepted without error and must not
	// tear the exchange down (unlike an empty answer, which signals non-capability).
	marker := (&ErrorMsg{ExchangeID: offerID}).Encode()
	require.NoError(t, dB.SignalOnAnswer("aaaa", marker))

	// The real answer still converges both sides on the same PSK.
	answer, err := dA.SignalOnOffer("bbbb", offer)
	require.NoError(t, err)
	require.NotNil(t, answer)
	require.NoError(t, dB.SignalOnAnswer("aaaa", answer))

	assert.Equal(t, wgB.psk("aaaa"), wgA.psk("bbbb"), "the exchange must still converge after a benign error marker")
	assert.NotEqual(t, PSK{}, wgB.psk("aaaa"))
}

// TestManager_OfferErrorMarkerAnsweredWithMarker covers the other direction: the initiator
// failed to build its offer and sent a marker. The responder must answer with a marker of
// its own, never an empty answer, which the initiator would read as "peer has no KEM".
func TestManager_OfferErrorMarkerAnsweredWithMarker(t *testing.T) {
	dA, dB, _, _, _ := pair(t)
	defer dA.Stop()
	defer dB.Stop()

	reply, err := dA.SignalOnOffer("bbbb", (&ErrorMsg{}).Encode())
	require.NoError(t, err)
	require.NotEmpty(t, reply, "an empty reply would mark the responder non-capable")

	typ, _, err := Decode(reply)
	require.NoError(t, err)
	assert.Equal(t, MsgError, typ, "the reply to an offer marker must be a marker")

	_, established := dA.PSK("bbbb")
	assert.False(t, established, "a marker must not derive a PSK")
}

// TestManager_UnreadableOfferAnsweredWithMarker: an offer the responder cannot process, such
// as one from a newer protocol version, must get an error marker. An empty answer would make
// the initiator mark the responder non-capable for good and stay classical with it.
func TestManager_UnreadableOfferAnsweredWithMarker(t *testing.T) {
	dA, dB, _, _, _ := pair(t)
	defer dB.Stop()

	offer, err := dB.SignalOffer("aaaa")
	require.NoError(t, err)
	require.NotNil(t, offer)

	newerVersion := append([]byte(nil), offer...)
	newerVersion[1] = ProtocolVersion + 1
	answerType := (&ErrorMsg{}).Encode()
	answerType[0] = byte(MsgAnswer)

	cases := map[string][]byte{
		"garbage":        {1, 2, 3},
		"newer version":  newerVersion,
		"not an offer":   answerType,
		"truncated body": offer[:len(offer)-1],
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			reply, err := dA.SignalOnOffer("bbbb", in)
			assert.Error(t, err)
			assertErrorMarker(t, reply)
		})
	}

	t.Run("manager stopping", func(t *testing.T) {
		dA.Stop()
		reply, err := dA.SignalOnOffer("bbbb", offer)
		assert.Error(t, err)
		assertErrorMarker(t, reply)
	})
}

func assertErrorMarker(t *testing.T, reply []byte) {
	t.Helper()
	require.NotEmpty(t, reply, "an empty reply would mark the responder non-capable")
	typ, _, err := Decode(reply)
	require.NoError(t, err)
	assert.Equal(t, MsgError, typ, "the reply must be an error marker")
}

// levelRecorder keeps the warning-or-above records a manager logs.
type levelRecorder struct {
	mu    sync.Mutex
	warns []slog.Record
}

func (r *levelRecorder) Enabled(context.Context, slog.Level) bool { return true }
func (r *levelRecorder) Handle(_ context.Context, rec slog.Record) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if rec.Level >= slog.LevelWarn {
		r.warns = append(r.warns, rec)
	}
	return nil
}
func (r *levelRecorder) WithAttrs([]slog.Attr) slog.Handler { return r }
func (r *levelRecorder) WithGroup(string) slog.Handler      { return r }

func (r *levelRecorder) warnings() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var msgs []string
	for _, rec := range r.warns {
		msgs = append(msgs, rec.Message)
	}
	return msgs
}

// TestManager_InitialTimeoutNotWarned: with lazy connections off, every reconnect offer to
// an offline peer starts a bootstrap that can only time out. The manager cannot tell that
// from a real failure, so it must report it without a warning and leave the severity to
// the host, which knows whether the peer is connected.
func TestManager_InitialTimeoutNotWarned(t *testing.T) {
	wg := newFakeWG()
	rec := &levelRecorder{}
	d := NewManager("bbbb", wg, slog.New(rec)) // initiator vs "aaaa"
	d.retryInterval = 5 * time.Millisecond
	d.maxRetries = 1
	d.Start(&loopback{ep: epB, sw: newSwitch()})
	defer d.Stop()

	offer, err := d.SignalOffer("aaaa")
	require.NoError(t, err)
	require.NotNil(t, offer, "precondition: the bootstrap offer goes out")

	require.Eventually(t, func() bool {
		wg.mu.Lock()
		defer wg.mu.Unlock()
		return len(wg.failed) == 1
	}, 2*time.Second, 5*time.Millisecond, "the unanswered bootstrap must still be reported to the host")
	assert.Empty(t, rec.warnings(), "an unanswered bootstrap must not be logged as a warning")
}
