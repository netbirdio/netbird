package pqkem

import (
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// dropTransport is a pqkem.Transport that silently discards everything.
type dropTransport struct{}

func (dropTransport) Send(netip.AddrPort, []byte) error       { return nil }
func (dropTransport) LocalPort() int                          { return 0 }
func (dropTransport) Run(func(netip.AddrPort, []byte))        {}
func (dropTransport) Close() error                            { return nil }

func failedCount(f *fakeWG) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.failed)
}

func TestManager_InitialTimeoutFailsImmediately(t *testing.T) {
	wg := newFakeWG()
	d := NewManager("bbbb", wg, nil) // bbbb > aaaa -> initiator
	d.SetTransport(dropTransport{})
	d.retryInterval = 5 * time.Millisecond
	d.maxRetries = 3
	defer d.Stop()

	// Bootstrap offer is produced for signalling; no answer ever comes back -> the
	// initial exchange fails fast.
	offer, err := d.SignalOffer("aaaa")
	require.NoError(t, err)
	require.NotNil(t, offer)

	require.Eventually(t, func() bool { return failedCount(wg) == 1 }, time.Second, 5*time.Millisecond)
}

func TestManager_RekeyToleratesKFailures(t *testing.T) {
	dA, dB, _, wgB, lbB := pair(t)
	defer dA.Stop()
	defer dB.Stop()

	// Establish: bootstrap + data-path-rekeyed so B becomes established and its data
	// path is usable.
	bootstrap(t, dA, dB)
	dA.OnDataPathRekeyed("bbbb")
	dB.OnDataPathRekeyed("aaaa")
	require.NotEqual(t, PSK{}, wgB.psk("aaaa"))

	// Tighten timings and drop B's outbound so rekeys can no longer converge.
	dB.retryInterval = 5 * time.Millisecond
	dB.maxRetries = 2
	lbB.drop.Store(true)

	// K-1 data-path rekeys must NOT raise OnRekeyFailed.
	for i := 0; i < DefaultMaxRekeyFailures-1; i++ {
		_, err := dB.startExchange("aaaa", false, ExchangeID{})
		require.NoError(t, err)
		time.Sleep(50 * time.Millisecond)
	}
	require.Equal(t, 0, failedCount(wgB), "no failure before K attempts")

	// The K-th failure raises it once.
	_, err := dB.startExchange("aaaa", false, ExchangeID{})
	require.NoError(t, err)
	require.Eventually(t, func() bool { return failedCount(wgB) == 1 }, time.Second, 5*time.Millisecond)
}
