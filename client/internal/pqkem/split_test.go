package pqkem

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestManager_ResponderOfferRebootstrapsSplitKeys reproduces a split PSK and checks that a
// reconnect started by the responder heals it. When every answer of a rotation is lost,
// the responder has committed the new PSK and the initiator has not, so WireGuard can no
// longer handshake. The connection layer then reconnects, and the reconnect offer may come
// from the responder, carrying no KEM. The controller used to answer it normally whenever
// it held a converged exchange, keeping its stale key, so the tunnel stayed down. A
// responder offer must instead be answered with a fresh KEM bootstrap.
func TestManager_ResponderOfferRebootstrapsSplitKeys(t *testing.T) {
	sw := newSwitch()
	wgA, wgB := newFakeWG(), newFakeWG()
	dA := NewManager("aaaa", wgA, nil) // responder
	dB := NewManager("bbbb", wgB, nil) // initiator (controller)
	dB.retryInterval = 10 * time.Millisecond
	dB.maxRetries = 2
	lbA := &loopback{ep: epA, sw: sw}
	dA.Start(lbA)
	dB.Start(&loopback{ep: epB, sw: sw})
	dA.AddPeer("bbbb", epB)
	dB.AddPeer("aaaa", epA)
	defer dA.Stop()
	defer dB.Stop()

	bootstrap(t, dA, dB)

	// Lose every answer of a rotation: the responder commits, the initiator times out.
	lbA.drop.Store(true)
	dB.OnDataPathRekeyed("aaaa", 0)
	require.Eventually(t, func() bool {
		dB.mu.Lock()
		defer dB.mu.Unlock()
		ex := dB.exchanges["aaaa"]
		return ex == nil || ex.state != stateAwaitingAnswer
	}, time.Second, 5*time.Millisecond, "the rotation must time out on the initiator")
	lbA.drop.Store(false)
	require.NotEqual(t, wgA.psk("bbbb"), wgB.psk("aaaa"), "precondition: the two PSKs are split")

	// The responder's reconnect offer carries no KEM: the controller must answer it with
	// a fresh bootstrap, which brings both peers back to one PSK.
	require.True(t, dB.ShouldSendBootstrapOffer("aaaa"),
		"a controller holding a converged exchange must still re-bootstrap on a responder offer")
	bootstrap(t, dA, dB)
	assert.Equal(t, wgA.psk("bbbb"), wgB.psk("aaaa"), "the re-bootstrap must heal the split PSKs")
}

// TestManager_NoRebootstrapWhileExchangeInFlight keeps the glare protection: while the
// controller's own exchange is waiting for its answer, a crossing responder offer must not
// start a second exchange, which would supersede the first and churn the keys.
func TestManager_NoRebootstrapWhileExchangeInFlight(t *testing.T) {
	dA, dB, _, _, _ := pair(t)
	defer dA.Stop()
	defer dB.Stop()

	offer, err := dB.SignalOffer("aaaa")
	require.NoError(t, err)
	require.NotNil(t, offer, "the controller's bootstrap must be in flight")

	assert.False(t, dB.ShouldSendBootstrapOffer("aaaa"),
		"no second exchange while the controller's own offer awaits its answer")
}

// TestManager_SignalOfferInFlight: only our own bootstrap offer over signalling, still
// awaiting its answer, makes a crossing responder offer a glare. A converged exchange, a
// data-path rotation, or the responder role must not.
func TestManager_SignalOfferInFlight(t *testing.T) {
	dA, dB, _, _, _ := pair(t) // dB ("bbbb") initiator
	defer dA.Stop()
	defer dB.Stop()

	assert.False(t, dB.SignalOfferInFlight("aaaa"), "no exchange yet: nothing in flight")

	offer, err := dB.SignalOffer("aaaa")
	require.NoError(t, err)
	require.NotNil(t, offer)
	assert.True(t, dB.SignalOfferInFlight("aaaa"), "our bootstrap offer awaits its answer")
	assert.False(t, dA.SignalOfferInFlight("bbbb"), "the responder never has a signalling offer in flight")

	answer, err := dA.SignalOnOffer("bbbb", offer)
	require.NoError(t, err)
	require.NoError(t, dB.SignalOnAnswer("aaaa", answer))
	assert.False(t, dB.SignalOfferInFlight("aaaa"), "a converged exchange is not in flight")

	_, err = dB.startExchangeTest("aaaa", false, ExchangeID{})
	require.NoError(t, err)
	assert.False(t, dB.SignalOfferInFlight("aaaa"), "a data-path rotation is not a signalling offer")
}
