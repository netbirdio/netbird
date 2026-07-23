package pqkem

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// loopback delivers a sent message synchronously to the peer manager's HandleInbound,
// attributing it to localID (the sender). Both channels deliver the same way — the
// test does not care which physical channel is used.
type loopback struct {
	localID string
	peer    *Manager
}

func (l *loopback) SendDataPath(remoteID string, msg []byte) error { return l.deliver(msg) }
func (l *loopback) SendSignal(remoteID string, msg []byte) error   { return l.deliver(msg) }

func (l *loopback) deliver(msg []byte) error {
	cp := append([]byte(nil), msg...)
	return l.peer.HandleInbound(l.localID, cp)
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

	// long interval so the ticker never fires during the test; we drive manually.
	dA := NewManager("aaaa", lbA, wgA, time.Hour, nil)
	dB := NewManager("bbbb", lbB, wgB, time.Hour, nil)
	lbA.peer = dB // A sends -> B receives
	lbB.peer = dA // B sends -> A receives

	dA.AddPeer("bbbb")
	dB.AddPeer("aaaa")
	defer dA.Stop()
	defer dB.Stop()

	// B is the initiator ("bbbb" > "aaaa"). Offer/answer flow synchronously over the
	// loopback; both commit their PSK, and B parks in stateAwaitingRekey.
	require.NoError(t, dB.initiateRekey("aaaa"))

	// The consumer reports the data path is (re)keyed on both sides; this makes B
	// send the confirm, which converges A.
	dA.OnDataPathRekeyed("bbbb")
	dB.OnDataPathRekeyed("aaaa")

	pskB := wgB.psk("aaaa")
	pskA := wgA.psk("bbbb")
	require.NotEqual(t, PSK{}, pskA, "responder A must have a PSK")
	require.NotEqual(t, PSK{}, pskB, "initiator B must have a PSK")
	require.Equal(t, pskB, pskA, "both sides converge on the same PSK")
}

func TestManager_NonInitiatorDoesNothing(t *testing.T) {
	lbA := &loopback{localID: "aaaa"}
	wgA := newFakeWG()
	dA := NewManager("aaaa", lbA, wgA, time.Hour, nil)
	dA.AddPeer("bbbb")
	defer dA.Stop()

	// A is NOT the initiator vs "bbbb" -> initiateRekey is a no-op, no Send.
	require.NoError(t, dA.initiateRekey("bbbb"))
	require.Equal(t, PSK{}, wgA.psk("bbbb"))
}

func TestManager_StopIsIdempotent(t *testing.T) {
	dA := NewManager("aaaa", &loopback{localID: "aaaa"}, newFakeWG(), time.Hour, nil)
	dA.AddPeer("bbbb")
	dA.Stop()
	dA.Stop() // must not panic or hang
}
