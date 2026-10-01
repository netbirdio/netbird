//go:build !js

package netstack

import (
	"net"
	"strconv"
	"testing"
)

func TestListenAddr_DefaultsToLoopback(t *testing.T) {
	// No env overrides: must bind loopback, never all interfaces.
	got := ListenAddr()
	want := net.JoinHostPort("127.0.0.1", strconv.Itoa(DefaultSocks5Port))
	if got != want {
		t.Fatalf("ListenAddr() = %q, want %q", got, want)
	}
}

func TestListenAddr_AddressOverride(t *testing.T) {
	tests := []struct {
		name string
		env  string
		want string
	}{
		{name: "valid override honored", env: "0.0.0.0", want: "0.0.0.0"},
		{name: "valid specific ip honored", env: "10.0.0.5", want: "10.0.0.5"},
		{name: "ipv6 loopback bracketed", env: "::1", want: "::1"},
		{name: "invalid falls back to loopback", env: "not-an-ip", want: "127.0.0.1"},
		{name: "empty falls back to loopback", env: "", want: "127.0.0.1"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(EnvSocks5ListenerAddress, tc.env)
			want := net.JoinHostPort(tc.want, strconv.Itoa(DefaultSocks5Port))
			if got := ListenAddr(); got != want {
				t.Fatalf("ListenAddr() = %q, want %q", got, want)
			}
		})
	}
}

func TestListenAddr_PortOverride(t *testing.T) {
	tests := []struct {
		name string
		env  string
		want int
	}{
		{name: "valid port honored", env: "1081", want: 1081},
		{name: "non-numeric falls back", env: "abc", want: DefaultSocks5Port},
		{name: "out of range falls back", env: "70000", want: DefaultSocks5Port},
		{name: "zero falls back", env: "0", want: DefaultSocks5Port},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(EnvSocks5ListenerPort, tc.env)
			want := net.JoinHostPort("127.0.0.1", strconv.Itoa(tc.want))
			if got := ListenAddr(); got != want {
				t.Fatalf("ListenAddr() = %q, want %q", got, want)
			}
		})
	}
}
