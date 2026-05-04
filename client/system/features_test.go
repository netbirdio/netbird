package system

import (
	"slices"
	"testing"
)

// Phase 3.7i: this test pins down the exact list of capability keywords
// this NetBird build advertises. The list ships out to the management
// server in PeerSystemMeta.SupportedFeatures and the server uses it to
// decide whether to send legacy-compat fallback settings (e.g. downgrade
// to p2p-lazy when the client lacks "p2p_dynamic").
//
// Reviewers: when adding a new capability, also add a corresponding
// server-side branch (or document explicitly that none is needed).
func TestSupportedFeatures_PinsCurrentList(t *testing.T) {
	got := SupportedFeatures()
	want := []string{
		"p2p_dynamic",
	}
	if !slices.Equal(got, want) {
		t.Errorf("supported features changed:\n  got:  %v\n  want: %v", got, want)
	}
}

// SupportedFeatures must return a defensive copy so callers cannot
// mutate the global list.
func TestSupportedFeatures_ReturnsCopy(t *testing.T) {
	a := SupportedFeatures()
	b := SupportedFeatures()
	if len(a) > 0 && &a[0] == &b[0] {
		t.Fatal("SupportedFeatures must return a fresh slice each call")
	}
	if len(a) > 0 {
		a[0] = "mutated"
		if SupportedFeatures()[0] == "mutated" {
			t.Fatal("global list was mutated through caller's slice")
		}
	}
}
