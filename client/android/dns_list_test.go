package android

import "testing"

func TestDNSList_Get(t *testing.T) {
	l := DNSList{}

	// Add a valid DNS address
	err := l.Add("8.8.8.8")
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}

	// Test getting valid index
	addr, err := l.Get(0)
	if err != nil {
		t.Errorf("invalid error: %s", err)
	}
	if addr != "8.8.8.8" {
		t.Errorf("expected 8.8.8.8, got %s", addr)
	}

	// Test negative index
	_, err = l.Get(-1)
	if err == nil {
		t.Errorf("expected error but got nil")
	}

	// Test out of bounds index
	_, err = l.Get(1)
	if err == nil {
		t.Errorf("expected error but got nil")
	}
}
