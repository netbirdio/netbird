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
