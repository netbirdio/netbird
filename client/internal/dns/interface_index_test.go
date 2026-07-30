package dns

import "testing"

func TestGetInterfaceIndexMissing(t *testing.T) {
	index, err := getInterfaceIndex("netbird-interface-that-does-not-exist")
	if index != 0 {
		t.Fatalf("expected missing interface index to be 0, got %d", index)
	}
	if err == nil {
		t.Fatal("expected missing interface lookup to return an error")
	}
}
