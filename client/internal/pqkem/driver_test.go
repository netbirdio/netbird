package pqkem

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// loopback delivers a sent message synchronously to the peer driver's HandleInbound,
// attributing it to localKey (the sender).
type loopback struct {
	localKey string
	peer     *Driver
}

func (l *loopback) Send(remoteWgKey string, msg []byte) error {
	cp := append([]byte(nil), msg...)
	return l.peer.HandleInbound(l.localKey, cp)
}

type fakeWG struct {
	mu     sync.Mutex
	psks   map[string]PSK
	failed []string
}

func newFakeWG() *fakeWG { return &fakeWG{psks: map[string]PSK{}} }

func (f *fakeWG) OnNewPSKReady(remoteWgKey string, psk PSK) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.psks[remoteWgKey] = psk
	return nil
}

func (f *fakeWG) OnRekeyFailed(remoteWgKey string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failed = append(f.failed, remoteWgKey)
	return nil
}

func (f *fakeWG) psk(peer string) PSK {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.psks[peer]
}

func TestDriver_ExchangeConverges(t *testing.T) {
	lbA := &loopback{localKey: "aaaa"}
	lbB := &loopback{localKey: "bbbb"}
	wgA := newFakeWG()
	wgB := newFakeWG()

	// long interval so the ticker never fires during the test; we drive manually.
	dA := NewDriver("aaaa", lbA, wgA, time.Hour, nil)
	dB := NewDriver("bbbb", lbB, wgB, time.Hour, nil)
	lbA.peer = dB // A sends -> B receives
	lbB.peer = dA // B sends -> A receives

	dA.AddPeer("bbbb")
	dB.AddPeer("aaaa")
	defer dA.Stop()
	defer dB.Stop()

	// B is the initiator ("bbbb" > "aaaa").
	require.NoError(t, dB.initiateRekey("aaaa"))

	pskB := wgB.psk("aaaa") // B committed on the answer
	pskA := wgA.psk("bbbb") // A committed on the confirm
	require.NotEqual(t, PSK{}, pskA, "responder A must have a PSK")
	require.NotEqual(t, PSK{}, pskB, "initiator B must have a PSK")
	require.Equal(t, pskB, pskA, "both sides converge on the same PSK")
}

func TestDriver_NonInitiatorDoesNothing(t *testing.T) {
	lbA := &loopback{localKey: "aaaa"}
	wgA := newFakeWG()
	dA := NewDriver("aaaa", lbA, wgA, time.Hour, nil)
	// no peer driver wired; if A wrongly initiated, Send would nil-panic.
	dA.AddPeer("bbbb")
	defer dA.Stop()

	// A is NOT the initiator vs "bbbb" -> initiateRekey is a no-op, no Send.
	require.NoError(t, dA.initiateRekey("bbbb"))
	require.Equal(t, PSK{}, wgA.psk("bbbb"))
}

func TestDriver_StopIsIdempotent(t *testing.T) {
	dA := NewDriver("aaaa", &loopback{localKey: "aaaa"}, newFakeWG(), time.Hour, nil)
	dA.AddPeer("bbbb")
	dA.Stop()
	dA.Stop() // must not panic or hang
}
