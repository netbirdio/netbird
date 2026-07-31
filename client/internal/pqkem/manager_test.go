package pqkem

import (
	"fmt"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
)

// netSwitch is an in-memory UDP fabric: transports register their endpoint and get
// datagrams delivered to their inbound handler.
type netSwitch struct {
	mu sync.Mutex
	h  map[netip.AddrPort]func(netip.AddrPort, []byte)
}

func newSwitch() *netSwitch {
	return &netSwitch{h: map[netip.AddrPort]func(netip.AddrPort, []byte){}}
}

func (s *netSwitch) register(ep netip.AddrPort, fn func(netip.AddrPort, []byte)) {
	s.mu.Lock()
	s.h[ep] = fn
	s.mu.Unlock()
}

func (s *netSwitch) deliver(dst, src netip.AddrPort, msg []byte) error {
	s.mu.Lock()
	fn := s.h[dst]
	s.mu.Unlock()
	if fn == nil {
		return fmt.Errorf("no route to %s", dst)
	}
	fn(src, msg)
	return nil
}

// loopback is an endpoint-based pqkem.Transport over a netSwitch, with a switchable
// drop flag.
type loopback struct {
	ep   netip.AddrPort
	sw   *netSwitch
	drop atomic.Bool
}

func (l *loopback) Send(dst netip.AddrPort, msg []byte) error {
	if l.drop.Load() {
		return nil
	}
	return l.sw.deliver(dst, l.ep, append([]byte(nil), msg...))
}

func (l *loopback) LocalPort() int                             { return int(l.ep.Port()) }
func (l *loopback) Run(onInbound func(netip.AddrPort, []byte)) { l.sw.register(l.ep, onInbound) }
func (l *loopback) Close() error                               { return nil }

type fakeWG struct {
	mu     sync.Mutex
	psks   map[RemoteID]PSK
	failed []RemoteID
}

func newFakeWG() *fakeWG { return &fakeWG{psks: map[RemoteID]PSK{}} }

func (f *fakeWG) OnNewPSKReady(remoteID RemoteID, psk PSK) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.psks[remoteID] = psk
	return nil
}

func (f *fakeWG) OnRekeyFailed(remoteID RemoteID) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failed = append(f.failed, remoteID)
	return nil
}

func (f *fakeWG) psk(peer RemoteID) PSK {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.psks[peer]
}

var (
	epA = netip.MustParseAddrPort("100.64.0.1:51833")
	epB = netip.MustParseAddrPort("100.64.0.2:51833")
)

// pair builds two wired managers (B is the initiator, "bbbb" > "aaaa") sharing a
// netSwitch, with each peer's data-path endpoint registered. lbB is B's loopback
// (for toggling drop).
func pair(t *testing.T) (dA, dB *Manager, wgA, wgB *fakeWG, lbB *loopback) {
	t.Helper()
	sw := newSwitch()
	wgA = newFakeWG()
	wgB = newFakeWG()
	dA = NewManager("aaaa", wgA, nil)
	dB = NewManager("bbbb", wgB, nil)
	dA.Start(&loopback{ep: epA, sw: sw})
	lbB = &loopback{ep: epB, sw: sw}
	dB.Start(lbB)
	dA.AddPeer("bbbb", epB)
	dB.AddPeer("aaaa", epA)
	return dA, dB, wgA, wgB, lbB
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
	dA, dB, wgA, wgB, _ := pair(t)
	defer dA.Stop()
	defer dB.Stop()

	bootstrap(t, dA, dB)

	pskA := wgA.psk("bbbb")
	pskB := wgB.psk("aaaa")
	require.NotEqual(t, PSK{}, pskA)
	require.Equal(t, pskB, pskA, "both sides derive the same PSK from the bootstrap exchange")
}

func TestManager_ChainRotatesAndAcks(t *testing.T) {
	dA, dB, wgA, wgB, _ := pair(t)
	defer dA.Stop()
	defer dB.Stop()

	bootstrap(t, dA, dB)
	psk1 := wgB.psk("aaaa")

	// Data path up: B (initiator) chains the next offer over the data path, which
	// rotates both to a fresh PSK and acknowledges A.
	dA.OnDataPathRekeyed("bbbb", 0)
	dB.OnDataPathRekeyed("aaaa", 0)

	psk2A := wgA.psk("bbbb")
	psk2B := wgB.psk("aaaa")
	require.Equal(t, psk2B, psk2A, "both sides converge on the rotated PSK")
	require.NotEqual(t, psk1, psk2B, "the chain rotated to a new PSK")
}

func TestManager_RotationSkippedWhenIdle(t *testing.T) {
	dA, dB, wgA, wgB, _ := pair(t)
	defer dA.Stop()
	defer dB.Stop()

	bootstrap(t, dA, dB)
	psk1 := wgB.psk("aaaa")
	require.NotEqual(t, PSK{}, psk1)

	// Idle: the peer's last real-data activity is older than the window, so a rekey
	// must NOT clock a rotation.
	dA.OnDataPathRekeyed("bbbb", rotationActivityWindow)
	dB.OnDataPathRekeyed("aaaa", rotationActivityWindow)
	require.Equal(t, psk1, wgB.psk("aaaa"), "idle peer must not rotate the PSK")
	require.Equal(t, psk1, wgA.psk("bbbb"), "idle peer must not rotate the PSK")

	// Active: activity within the window clocks the rotation as usual.
	dA.OnDataPathRekeyed("bbbb", rotationActivityWindow-1)
	dB.OnDataPathRekeyed("aaaa", rotationActivityWindow-1)
	psk2 := wgB.psk("aaaa")
	require.NotEqual(t, psk1, psk2, "recent activity must clock a rotation")
	require.Equal(t, psk2, wgA.psk("bbbb"), "both sides converge on the rotated PSK")
}

func TestManager_NonInitiatorReturnsNoOffer(t *testing.T) {
	dA := NewManager("aaaa", newFakeWG(), nil)
	defer dA.Stop()

	offer, err := dA.SignalOffer("bbbb") // not the initiator vs "bbbb"
	require.NoError(t, err)
	require.Nil(t, offer)
}

func TestManager_StopIsIdempotent(t *testing.T) {
	dA := NewManager("aaaa", newFakeWG(), nil)
	dA.Start(&loopback{ep: epA, sw: newSwitch()})
	dA.Stop()
	dA.Stop() // must not panic or hang
}
