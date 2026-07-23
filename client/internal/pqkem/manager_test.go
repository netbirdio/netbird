package pqkem

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

// loopback is a data-path transport: SendDataPath delivers synchronously to the peer
// manager's OnDataPathMessage, attributing it to localID (the sender). The signalling
// channel is driven by the test directly via the SignalX methods.
type loopback struct {
	localID string
	peer    *Manager
}

func (l *loopback) SendDataPath(remoteID string, msg []byte) error {
	cp := append([]byte(nil), msg...)
	return l.peer.OnDataPathMessage(l.localID, cp)
}

type fakeWG struct {
	mu     sync.Mutex
	psks   map[string]PSK
	failed []string
}

func newFakeWG() *fakeWG { return &fakeWG{psks: map[string]PSK{}} }

func (f *fakeWG) OnNewPSKReady(remoteID string, psk PSK) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.psks[remoteID] = psk
	return nil
}

func (f *fakeWG) OnRekeyFailed(remoteID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failed = append(f.failed, remoteID)
	return nil
}

func (f *fakeWG) psk(peer string) PSK {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.psks[peer]
}

// pair builds two wired managers (B is the initiator, "bbbb" > "aaaa").
func pair(t *testing.T) (dA, dB *Manager, wgA, wgB *fakeWG) {
	t.Helper()
	lbA := &loopback{localID: "aaaa"}
	lbB := &loopback{localID: "bbbb"}
	wgA = newFakeWG()
	wgB = newFakeWG()
	dA = NewManager("aaaa", lbA, wgA, nil)
	dB = NewManager("bbbb", lbB, wgB, nil)
	lbA.peer = dB
	lbB.peer = dA
	return dA, dB, wgA, wgB
}

// bootstrap runs the signalling offer/answer (the test plays the host carrying bytes).
func bootstrap(t *testing.T, dA, dB *Manager) {
	t.Helper()
	offer, err := dB.SignalOffer("aaaa")
	require.NoError(t, err)
	require.NotNil(t, offer)
	answer, err := dA.SignalOnOffer("bbbb", offer)
	require.NoError(t, err)
	require.NotNil(t, answer)
	require.NoError(t, dB.SignalOnAnswer("aaaa", answer))
}

func TestManager_BootstrapDerivesSamePSK(t *testing.T) {
	dA, dB, wgA, wgB := pair(t)
	defer dA.Stop()
	defer dB.Stop()

	bootstrap(t, dA, dB)

	pskA := wgA.psk("bbbb")
	pskB := wgB.psk("aaaa")
	require.NotEqual(t, PSK{}, pskA)
	require.Equal(t, pskB, pskA, "both sides derive the same PSK from the bootstrap exchange")
}

func TestManager_ChainRotatesAndAcks(t *testing.T) {
	dA, dB, wgA, wgB := pair(t)
	defer dA.Stop()
	defer dB.Stop()

	bootstrap(t, dA, dB)
	psk1 := wgB.psk("aaaa")

	// Data path up on both sides; B chains the next offer (acking exchange 1) over the
	// data path, which rotates both to a fresh PSK and acknowledges A.
	dA.OnDataPathRekeyed("bbbb")
	dB.OnDataPathRekeyed("aaaa")

	psk2A := wgA.psk("bbbb")
	psk2B := wgB.psk("aaaa")
	require.Equal(t, psk2B, psk2A, "both sides converge on the rotated PSK")
	require.NotEqual(t, psk1, psk2B, "the chain rotated to a new PSK")
}

func TestManager_NonInitiatorReturnsNoOffer(t *testing.T) {
	dA := NewManager("aaaa", &loopback{localID: "aaaa"}, newFakeWG(), nil)
	defer dA.Stop()

	offer, err := dA.SignalOffer("bbbb") // not the initiator vs "bbbb"
	require.NoError(t, err)
	require.Nil(t, offer)
}

func TestManager_StopIsIdempotent(t *testing.T) {
	dA := NewManager("aaaa", &loopback{localID: "aaaa"}, newFakeWG(), nil)
	dA.Stop()
	dA.Stop() // must not panic or hang
}
