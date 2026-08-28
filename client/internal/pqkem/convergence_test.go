package pqkem

import (
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// dropTransport is a pqkem.Transport that silently discards everything.
type dropTransport struct{}

func (dropTransport) Send(netip.AddrPort, []byte) error { return nil }
func (dropTransport) LocalPort() int                    { return 0 }
func (dropTransport) Run(func(netip.AddrPort, []byte))  {}
func (dropTransport) Close() error                      { return nil }

func failedCount(f *fakeWG) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.failed)
}

func TestManager_InitialTimeoutFailsImmediately(t *testing.T) {
	wg := newFakeWG()
	d := NewManager("bbbb", wg, nil) // bbbb > aaaa -> initiator
	d.Start(dropTransport{})
	d.retryInterval = 5 * time.Millisecond
	d.maxRetries = 3
	defer d.Stop()

	// Bootstrap offer is produced for signalling; no answer ever comes back -> the
	// initial exchange fails fast.
	offer, err := d.SignalOffer("aaaa")
	require.NoError(t, err)
	require.NotNil(t, offer)

	assert.Eventually(t, func() bool { return failedCount(wg) == 1 }, time.Second, 5*time.Millisecond)
}

func TestManager_RekeyToleratesKFailures(t *testing.T) {
	dA, dB, _, wgB, lbB := pair(t)
	defer dA.Stop()
	defer dB.Stop()

	// Tighten B's timings before any exchange loop spawns (the loop reads these
	// fields, so writing them after a loop is running would race).
	dB.retryInterval = 5 * time.Millisecond
	dB.maxRetries = 2

	// Establish: bootstrap + data-path-rekeyed so B becomes established and its data
	// path is usable.
	bootstrap(t, dA, dB)
	dA.OnDataPathRekeyed("bbbb", 0)
	dB.OnDataPathRekeyed("aaaa", 0)
	require.NotEqual(t, PSK{}, wgB.psk("aaaa"))

	// Drop B's outbound so rekeys can no longer converge.
	lbB.drop.Store(true)

	// K-1 data-path rekeys must NOT raise OnRekeyFailed.
	for i := 0; i < DefaultMaxRekeyFailures-1; i++ {
		_, err := dB.startExchangeTest("aaaa", false, ExchangeID{})
		require.NoError(t, err)
		time.Sleep(50 * time.Millisecond)
	}
	assert.Equal(t, 0, failedCount(wgB), "no failure before K attempts")

	// The K-th failure raises it once.
	_, err := dB.startExchangeTest("aaaa", false, ExchangeID{})
	require.NoError(t, err)
	assert.Eventually(t, func() bool { return failedCount(wgB) == 1 }, time.Second, 5*time.Millisecond)
}

// TestManager_InitiatorRejectsOfferFromResponderRole verifies the role guard: an offer
// reaching the peer that is the initiator (here dB) must be dropped, not adopted — else a
// stray/injected offer would overwrite the live PSK and silently drop any in-flight
// exchange. dA (the role-responder) crafts an offer and injects it into dB (the initiator).
func TestManager_InitiatorRejectsOfferFromResponderRole(t *testing.T) {
	dA, dB, _, wgB, _ := pair(t) // dB ("bbbb") is the initiator, dA ("aaaa") the responder
	defer dA.Stop()
	defer dB.Stop()

	bootstrap(t, dA, dB)
	psk1 := wgB.psk("aaaa")
	require.NotEqual(t, PSK{}, psk1, "bootstrap established a PSK")

	rogue, err := dA.startExchangeTest("bbbb", false, ExchangeID{})
	require.NoError(t, err)
	require.NoError(t, dB.OnDataPathMessage("aaaa", rogue))

	assert.Equal(t, psk1, wgB.psk("aaaa"),
		"the initiator must not adopt a PSK from an offer sent by the role-responder")
}
