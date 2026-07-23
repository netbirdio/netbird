package pqkem

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type dropTransport struct{}

func (dropTransport) SendDataPath(string, []byte) error { return nil }

// gate is a data-path loopback with a switchable drop flag. When dropping it reports
// success but does not deliver (mimics a lossy/broken tunnel).
type gate struct {
	localID string
	peer    *Manager
	drop    atomic.Bool
}

func (g *gate) SendDataPath(remoteID string, msg []byte) error {
	if g.drop.Load() {
		return nil
	}
	cp := append([]byte(nil), msg...)
	return g.peer.OnDataPathMessage(g.localID, cp)
}

func TestManager_InitialTimeoutFailsImmediately(t *testing.T) {
	wg := newFakeWG()
	d := NewManager("bbbb", dropTransport{}, wg, nil) // bbbb > aaaa -> initiator
	d.retryInterval = 5 * time.Millisecond
	d.maxRetries = 3
	defer d.Stop()

	// Bootstrap offer is produced for signalling; no answer ever comes back -> the
	// initial exchange fails fast.
	offer, err := d.SignalOffer("aaaa")
	require.NoError(t, err)
	require.NotNil(t, offer)

	require.Eventually(t, func() bool {
		wg.mu.Lock()
		defer wg.mu.Unlock()
		return len(wg.failed) == 1
	}, time.Second, 5*time.Millisecond)
}

func TestManager_RekeyToleratesKFailures(t *testing.T) {
	gA := &gate{localID: "aaaa"}
	gB := &gate{localID: "bbbb"}
	wgA := newFakeWG()
	wgB := newFakeWG()

	dA := NewManager("aaaa", gA, wgA, nil)
	dB := NewManager("bbbb", gB, wgB, nil)
	gA.peer = dB
	gB.peer = dA
	dB.retryInterval = 5 * time.Millisecond
	dB.maxRetries = 2
	defer dA.Stop()
	defer dB.Stop()

	// Bootstrap over signalling -> B becomes established.
	offer, err := dB.SignalOffer("aaaa")
	require.NoError(t, err)
	answer, err := dA.SignalOnOffer("bbbb", offer)
	require.NoError(t, err)
	require.NoError(t, dB.SignalOnAnswer("aaaa", answer))
	require.NotEqual(t, PSK{}, wgB.psk("aaaa"))

	// Bring the data path up on both, then drop B's delivery so rekeys can't converge.
	dA.OnDataPathRekeyed("bbbb")
	dB.OnDataPathRekeyed("aaaa")
	gB.drop.Store(true)

	// K-1 data-path rekeys must NOT raise OnRekeyFailed.
	for i := 0; i < DefaultMaxRekeyFailures-1; i++ {
		_, err := dB.startExchange("aaaa", false, ExchangeID{})
		require.NoError(t, err)
		time.Sleep(50 * time.Millisecond)
	}
	require.Equal(t, 0, failedCount(wgB), "no failure before K attempts")

	// The K-th failure raises it once.
	_, err = dB.startExchange("aaaa", false, ExchangeID{})
	require.NoError(t, err)
	require.Eventually(t, func() bool { return failedCount(wgB) == 1 }, time.Second, 5*time.Millisecond)
}

func failedCount(f *fakeWG) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.failed)
}
