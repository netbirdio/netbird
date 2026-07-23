package pqkem

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type dropTransport struct{}

func (dropTransport) SendDataPath(string, []byte) error { return nil }
func (dropTransport) SendSignal(string, []byte) error   { return nil }

// gate is a loopback transport with a switchable drop flag.
type gate struct {
	localID string
	peer    *Manager
	drop    atomic.Bool
}

func (g *gate) SendDataPath(remoteID string, msg []byte) error { return g.deliver(msg) }
func (g *gate) SendSignal(remoteID string, msg []byte) error   { return g.deliver(msg) }

func (g *gate) deliver(msg []byte) error {
	if g.drop.Load() {
		return nil
	}
	cp := append([]byte(nil), msg...)
	return g.peer.HandleInbound(g.localID, cp)
}

func TestManager_InitialTimeoutFailsImmediately(t *testing.T) {
	wg := newFakeWG()
	d := NewManager("bbbb", dropTransport{}, wg, time.Hour, nil) // bbbb > aaaa -> initiator
	d.retryInterval = 5 * time.Millisecond
	d.maxRetries = 3
	d.AddPeer("aaaa")
	defer d.Stop()

	require.NoError(t, d.initiateRekey("aaaa"))

	// no answer will ever come -> the initial exchange fails fast.
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

	dA := NewManager("aaaa", gA, wgA, time.Hour, nil)
	dB := NewManager("bbbb", gB, wgB, time.Hour, nil)
	gA.peer = dB
	gB.peer = dA
	dB.retryInterval = 5 * time.Millisecond
	dB.maxRetries = 2
	dA.AddPeer("bbbb")
	dB.AddPeer("aaaa")
	defer dA.Stop()
	defer dB.Stop()

	// First exchange succeeds -> peer becomes established (subsequent failures are
	// rekeys). Drive the data-path-rekeyed event so the confirm converges A.
	require.NoError(t, dB.initiateRekey("aaaa"))
	dA.OnDataPathRekeyed("bbbb")
	dB.OnDataPathRekeyed("aaaa")
	require.NotEqual(t, PSK{}, wgB.psk("aaaa"))

	// Now drop B's outbound: rekeys can no longer converge.
	gB.drop.Store(true)

	// K-1 failures must NOT raise OnRekeyFailed.
	for i := 0; i < DefaultMaxRekeyFailures-1; i++ {
		require.NoError(t, dB.initiateRekey("aaaa"))
		time.Sleep(50 * time.Millisecond)
	}
	require.Equal(t, 0, failedCount(wgB), "no failure before K attempts")

	// the K-th failure raises it once.
	require.NoError(t, dB.initiateRekey("aaaa"))
	require.Eventually(t, func() bool { return failedCount(wgB) == 1 }, time.Second, 5*time.Millisecond)
}

func failedCount(f *fakeWG) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.failed)
}
