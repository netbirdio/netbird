package pqkem

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestManager_NonCapablePeerNotOffered: a peer known not to run the KEM (it answered our
// offer with an empty KEM payload over signalling) is never offered an exchange, and no
// failure is raised — this is what stops the reoffer storm against non-PQ peers (e.g.
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

	// Now we learn the peer is non-PQ: the exchange must be dropped.
	d.MarkNonCapable("aaaa")

	next, err := d.SignalOffer("aaaa")
	require.NoError(t, err)
	assert.Nil(t, next, "after learning non-capability the peer is no longer offered")
	assert.Empty(t, wg.failed, "cancelling an in-flight exchange must not raise a failure")
}

// TestManager_EstablishedPeerNotDowngraded: a stray zero-port observation must not tear
// down a peer we already have a working PQ session with.
func TestManager_EstablishedPeerNotDowngraded(t *testing.T) {
	dA, dB, _, wgB, _ := pair(t)
	defer dA.Stop()
	defer dB.Stop()

	bootstrap(t, dA, dB)
	require.NotEqual(t, PSK{}, wgB.psk("aaaa"), "established a PSK")

	dB.MarkNonCapable("aaaa") // stray zero after establishment

	// The peer keeps its derived PSK (MarkNonCapable is a no-op once established).
	psk, ok := dB.PSK("aaaa")
	assert.True(t, ok, "an established peer must keep its PSK despite a stray zero")
	assert.NotEqual(t, PSK{}, psk)
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
