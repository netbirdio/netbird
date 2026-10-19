package internal

import (
	"errors"
	"testing"

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

	if !a.claim("peerA", 1) {
		t.Fatal("first generation must be accepted")
	}
	if !a.claim("peerA", 2) {
		t.Fatal("a newer generation must be accepted")
	}
	if a.claim("peerA", 2) {
		t.Fatal("re-applying the same generation must be dropped")
	}
	if a.claim("peerA", 1) {
		t.Fatal("an older generation arriving late must be dropped")
	}
	if !a.claim("peerA", 3) {
		t.Fatal("a newer generation after a dropped stale one must still be accepted")
	}

	// Generations are tracked independently per peer.
	if !a.claim("peerB", 1) {
		t.Fatal("a different peer's first generation must be accepted")
	}
}
