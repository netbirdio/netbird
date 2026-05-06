package types

import "testing"

func TestSettings_Copy_P2pRetryMaxSeconds(t *testing.T) {
	v := uint32(900)
	src := &Settings{P2pRetryMaxSeconds: &v}
	dst := src.Copy()
	if dst.P2pRetryMaxSeconds == nil {
		t.Fatal("Copy lost P2pRetryMaxSeconds pointer")
	}
	if *dst.P2pRetryMaxSeconds != 900 {
		t.Fatalf("expected 900, got %d", *dst.P2pRetryMaxSeconds)
	}
	// Verify it's a deep copy (different pointers)
	*dst.P2pRetryMaxSeconds = 600
	if *src.P2pRetryMaxSeconds != 900 {
		t.Fatal("Copy did not deep-clone P2pRetryMaxSeconds")
	}
}

// Phase 3.7i (#5989): make sure Settings.Copy carries the new
// LegacyLazyFallback* fields. Forgetting either would silently reset
// the toggle / timeout to zero values whenever Copy is called (e.g.
// in the equality check on UpdateAccountSettings).
func TestSettings_Copy_LegacyLazyFallback(t *testing.T) {
	src := &Settings{
		LegacyLazyFallbackEnabled:        true,
		LegacyLazyFallbackTimeoutSeconds: 1800,
	}
	dst := src.Copy()
	if !dst.LegacyLazyFallbackEnabled {
		t.Fatal("Copy lost LegacyLazyFallbackEnabled (got false, want true)")
	}
	if dst.LegacyLazyFallbackTimeoutSeconds != 1800 {
		t.Fatalf("Copy lost LegacyLazyFallbackTimeoutSeconds: got %d, want 1800",
			dst.LegacyLazyFallbackTimeoutSeconds)
	}
}
