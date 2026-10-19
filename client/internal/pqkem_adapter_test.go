package internal

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/netbirdio/netbird/client/internal/peer"
	"github.com/netbirdio/netbird/client/internal/pqkem"
)

// fakePSKSetter records PSK programming and can be made to fail.
type fakePSKSetter struct {
	err   error
	calls int
}

func (f *fakePSKSetter) SetPresharedKey(string, wgtypes.Key, bool) error {
	f.calls++
	return f.err
}

const pqTestPeerKey = "eDQmZp9jhQGX7XdYpHGaFSpAouldr3Sbf7MZRcGTGGQ="

func newPQTestStatus(t *testing.T) *peer.Status {
	t.Helper()
	status := peer.NewRecorder("https://mgm")
	require.NoError(t, status.AddPeer(pqTestPeerKey, "peer.netbird.cloud", "100.64.0.2", ""))
	return status
}

// TestPQCallbackHandler_MarksPeerQuantumResistant reproduces the stale status flag: when
// the KEM answer lands after the connection was set up, the per-peer "Quantum resistance"
// flag was computed without a PSK and never refreshed. Programming the PSK must flag it.
func TestPQCallbackHandler_MarksPeerQuantumResistant(t *testing.T) {
	status := newPQTestStatus(t)
	setter := &fakePSKSetter{}
	h := pqCallbackHandler{wg: setter, applied: newAppliedGenerations(), status: status}

	require.NoError(t, h.OnNewPSKReady(pqkem.RemoteID(pqTestPeerKey), 1, pqkem.PSK{1}))

	st, err := status.GetPeer(pqTestPeerKey)
	require.NoError(t, err)
	assert.Equal(t, 1, setter.calls, "the PSK must be programmed once")
	assert.True(t, st.RosenpassEnabled, "a programmed PQ PSK must mark the peer quantum resistant")
}

// TestPQCallbackHandler_FailedApplyKeepsFlag verifies the flag only follows a PSK that was
// actually programmed: a failed SetPresharedKey must leave the peer unflagged.
func TestPQCallbackHandler_FailedApplyKeepsFlag(t *testing.T) {
	status := newPQTestStatus(t)
	h := pqCallbackHandler{wg: &fakePSKSetter{err: errors.New("boom")}, applied: newAppliedGenerations(), status: status}

	require.Error(t, h.OnNewPSKReady(pqkem.RemoteID(pqTestPeerKey), 1, pqkem.PSK{1}))

	st, err := status.GetPeer(pqTestPeerKey)
	require.NoError(t, err)
	assert.False(t, st.RosenpassEnabled, "a PSK that failed to program must not mark the peer quantum resistant")
}

// TestPQCallbackHandler_UnknownStatusPeerDoesNotFailApply verifies the status update is
// best-effort: a peer missing from the status recorder must not fail the PSK apply.
func TestPQCallbackHandler_UnknownStatusPeerDoesNotFailApply(t *testing.T) {
	setter := &fakePSKSetter{}
	h := pqCallbackHandler{wg: setter, applied: newAppliedGenerations(), status: peer.NewRecorder("https://mgm")}

	assert.NoError(t, h.OnNewPSKReady(pqkem.RemoteID(pqTestPeerKey), 1, pqkem.PSK{1}))
	assert.Equal(t, 1, setter.calls, "the PSK must still be programmed")
}

// TestAppliedGenerations_DropsStale verifies the out-of-order guard: a generation is
// accepted only when it is strictly newer than the last one applied for that peer, so a
// reordered PSK callback cannot restore an older key over a newer one.
func TestAppliedGenerations_DropsStale(t *testing.T) {
	a := newAppliedGenerations()
	accept := func(peer string, gen uint64) bool {
		ran, err := a.apply(peer, gen, func() error { return nil })
		require.NoError(t, err)
		return ran
	}

	if !accept("peerA", 1) {
		t.Fatal("first generation must be accepted")
	}
	if !accept("peerA", 2) {
		t.Fatal("a newer generation must be accepted")
	}
	if accept("peerA", 2) {
		t.Fatal("re-applying the same generation must be dropped")
	}
	if accept("peerA", 1) {
		t.Fatal("an older generation arriving late must be dropped")
	}
	if !accept("peerA", 3) {
		t.Fatal("a newer generation after a dropped stale one must still be accepted")
	}

	// Generations are tracked independently per peer.
	if !accept("peerB", 1) {
		t.Fatal("a different peer's first generation must be accepted")
	}
}

// blockingPSKSetter holds the first SetPresharedKey call until released, recording the
// key WireGuard ends up with.
type blockingPSKSetter struct {
	mu      sync.Mutex
	calls   int
	last    wgtypes.Key
	entered chan struct{}
	release chan struct{}
}

func (s *blockingPSKSetter) SetPresharedKey(_ string, psk wgtypes.Key, _ bool) error {
	s.mu.Lock()
	s.calls++
	first := s.calls == 1
	s.mu.Unlock()
	if first {
		close(s.entered)
		<-s.release
	}
	s.mu.Lock()
	s.last = psk
	s.mu.Unlock()
	return nil
}

// TestPQCallbackHandler_AppliesGenerationsInOrder covers two PSK callbacks for one peer
// overlapping. The newer generation must be the one WireGuard keeps: with the generation
// checked under a lock but the key set outside it, an older apply that was already
// writing could finish last and restore its stale key.
func TestPQCallbackHandler_AppliesGenerationsInOrder(t *testing.T) {
	setter := &blockingPSKSetter{entered: make(chan struct{}), release: make(chan struct{})}
	h := pqCallbackHandler{wg: setter, applied: newAppliedGenerations()}
	older, newer := pqkem.PSK{3}, pqkem.PSK{4}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		assert.NoError(t, h.OnNewPSKReady(pqkem.RemoteID(pqTestPeerKey), 3, older))
	}()
	<-setter.entered // the older apply is now inside SetPresharedKey

	go func() {
		defer wg.Done()
		assert.NoError(t, h.OnNewPSKReady(pqkem.RemoteID(pqTestPeerKey), 4, newer))
	}()
	// Give the newer apply the chance to overtake the blocked older one.
	time.Sleep(50 * time.Millisecond)
	close(setter.release)
	wg.Wait()

	setter.mu.Lock()
	defer setter.mu.Unlock()
	assert.Equal(t, wgtypes.Key(newer), setter.last, "WireGuard must keep the newest generation's PSK")
}
