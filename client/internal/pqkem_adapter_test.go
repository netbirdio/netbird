package internal

import "testing"

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
