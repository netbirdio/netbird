//go:build js

package system

import (
	"context"
	"testing"
)

// TestGetInfoHonorsDeviceName covers a caller-provided device name reaching the
// reported hostname, so a peer registered over an API keeps reporting the name
// it was registered with instead of renaming itself on its first sync.
func TestGetInfoHonorsDeviceName(t *testing.T) {
	ctx := context.WithValue(context.Background(), DeviceNameCtxKey, "session-name")
	if got := GetInfo(ctx).Hostname; got != "session-name" {
		t.Errorf("hostname should carry the caller's device name, got %q", got)
	}
}

// TestGetInfoWithoutDeviceNameKeepsFallback covers the embed layer's habit of
// always setting the context value: an empty name must not blank the hostname.
func TestGetInfoWithoutDeviceNameKeepsFallback(t *testing.T) {
	ctx := context.WithValue(context.Background(), DeviceNameCtxKey, "")
	if got := GetInfo(ctx).Hostname; got == "" {
		t.Error("an empty device name must not blank the hostname")
	}
}
