//go:build darwin || ios

package NetBirdSDK

import "testing"

func TestRequireRouteManagerNil(t *testing.T) {
	manager, err := requireRouteManager(nil)
	if manager != nil {
		t.Fatal("expected nil route manager")
	}
	if err == nil {
		t.Fatal("expected an error")
	}
	if got, want := err.Error(), "could not get route manager"; got != want {
		t.Errorf("unexpected error: got %q, want %q", got, want)
	}
}
