//go:build windows

package dnsfw

import (
	"net/netip"
	"os"
	"testing"
)

func TestStrictMode(t *testing.T) {
	tests := []struct {
		name string
		val  string
		set  bool
		want bool
	}{
		{name: "unset", want: false},
		{name: "true", val: "true", set: true, want: true},
		{name: "1", val: "1", set: true, want: true},
		{name: "false", val: "false", set: true, want: false},
		{name: "invalid is false", val: "garbage", set: true, want: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(EnvStrict, tc.val)
			if !tc.set {
				os.Unsetenv(EnvStrict)
			}
			if got := strictMode(); got != tc.want {
				t.Fatalf("strictMode() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestWindowsManagerDisableIdempotent(t *testing.T) {
	m := &windowsManager{}
	if err := m.Disable(); err != nil {
		t.Fatalf("first Disable on fresh manager: %v", err)
	}
	if err := m.Disable(); err != nil {
		t.Fatalf("second Disable on fresh manager: %v", err)
	}
	if m.session != 0 {
		t.Fatalf("session should remain zero, got %d", m.session)
	}
}

func TestWindowsManagerEnableNoOpWhenDisabledByEnv(t *testing.T) {
	t.Setenv(EnvDisable, "true")

	m := &windowsManager{}
	if err := m.Enable("00000000-0000-0000-0000-000000000000", netip.Addr{}); err != nil {
		t.Fatalf("Enable should be a no-op when firewall disabled by env: %v", err)
	}
	if m.session != 0 {
		t.Fatalf("session must remain zero when env disables firewall, got %d", m.session)
	}
}

func TestWindowsManagerEnableNoOpWhenPortsEmpty(t *testing.T) {
	t.Setenv(EnvPorts, "")

	m := &windowsManager{}
	if err := m.Enable("00000000-0000-0000-0000-000000000000", netip.Addr{}); err != nil {
		t.Fatalf("Enable should be a no-op when ports list is empty: %v", err)
	}
	if m.session != 0 {
		t.Fatalf("session must remain zero when ports list is empty, got %d", m.session)
	}
}
