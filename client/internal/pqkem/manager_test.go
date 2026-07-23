package pqkem

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// loopback is a data-path transport: a SendDataPath delivers synchronously to the
// peer manager's OnDataPathMessage, attributing it to localID (the sender). The
// signalling channel is driven by the test directly via the SignalX methods.
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

func TestManager_ExchangeConverges(t *testing.T) {
	lbA := &loopback{localID: "aaaa"}
	lbB := &loopback{localID: "bbbb"}
	wgA := newFakeWG()
	wgB := newFakeWG()

	dA := NewManager("aaaa", lbA, wgA, time.Hour, nil)
	dB := NewManager("bbbb", lbB, wgB, time.Hour, nil)
	lbA.peer = dB // A's data-path sends -> B receives
	lbB.peer = dA // B's data-path sends -> A receives

	dA.AddPeer("bbbb")
	dB.AddPeer("aaaa")
	defer dA.Stop()
	defer dB.Stop()

	// Bootstrap over the signalling channel (the test plays the host carrying bytes).
	// B is the initiator ("bbbb" > "aaaa").
	offer, err := dB.SignalOffer("aaaa")
	require.NoError(t, err)
	require.NotNil(t, offer)

	answer, err := dA.SignalOnOffer("bbbb", offer)
	require.NoError(t, err)
	require.NotNil(t, answer)

	require.NoError(t, dB.SignalOnAnswer("aaaa", answer))

	// Data path comes up on both sides; this makes B send the confirm over the data
	// path, converging A.
	dA.OnDataPathRekeyed("bbbb")
	dB.OnDataPathRekeyed("aaaa")

	pskB := wgB.psk("aaaa")
	pskA := wgA.psk("bbbb")
	require.NotEqual(t, PSK{}, pskA, "responder A must have a PSK")
	require.NotEqual(t, PSK{}, pskB, "initiator B must have a PSK")
	require.Equal(t, pskB, pskA, "both sides converge on the same PSK")
}

func TestManager_NonInitiatorReturnsNoOffer(t *testing.T) {
	dA := NewManager("aaaa", &loopback{localID: "aaaa"}, newFakeWG(), time.Hour, nil)
	dA.AddPeer("bbbb")
	defer dA.Stop()

	// A is NOT the initiator vs "bbbb" -> no offer to send.
	offer, err := dA.SignalOffer("bbbb")
	require.NoError(t, err)
	require.Nil(t, offer)
}

func TestManager_StopIsIdempotent(t *testing.T) {
	dA := NewManager("aaaa", &loopback{localID: "aaaa"}, newFakeWG(), time.Hour, nil)
	dA.AddPeer("bbbb")
	dA.Stop()
	dA.Stop() // must not panic or hang
}
