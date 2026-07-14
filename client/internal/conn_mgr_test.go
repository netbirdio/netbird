package internal

import (
	"os"
	"testing"

	"github.com/netbirdio/netbird/client/internal/lazyconn"
	mgmProto "github.com/netbirdio/netbird/shared/management/proto"
)

func TestResolveLazyForce(t *testing.T) {
	tests := []struct {
		name   string
		env    string
		envSet bool
		mdm    lazyconn.State
		want   lazyForce
	}{
		{name: "env unset, mdm unset -> defer to management", mdm: lazyconn.StateUnset, want: lazyForceNone},
		{name: "env on -> force on", env: "on", envSet: true, mdm: lazyconn.StateUnset, want: lazyForceOn},
		{name: "env off -> force off", env: "off", envSet: true, mdm: lazyconn.StateUnset, want: lazyForceOff},
		{name: "env unset, mdm on -> force on", mdm: lazyconn.StateOn, want: lazyForceOn},
		{name: "env unset, mdm off -> force off", mdm: lazyconn.StateOff, want: lazyForceOff},
		{name: "env on beats mdm off", env: "on", envSet: true, mdm: lazyconn.StateOff, want: lazyForceOn},
		{name: "env off beats mdm on", env: "off", envSet: true, mdm: lazyconn.StateOn, want: lazyForceOff},
		{name: "unrecognized env, mdm on -> mdm wins", env: "auto", envSet: true, mdm: lazyconn.StateOn, want: lazyForceOn},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv(lazyconn.EnvLazyConn, tt.env)
			if !tt.envSet {
				os.Unsetenv(lazyconn.EnvLazyConn)
			}

			if got := resolveLazyForce(tt.mdm); got != tt.want {
				t.Fatalf("resolveLazyForce(%v) = %v, want %v", tt.mdm, got, tt.want)
			}
		})
	}
}

func TestPeerLazyDefault(t *testing.T) {
	tests := []struct {
		name          string
		force         lazyForce
		remoteEnabled bool
		state         mgmProto.LazyState
		want          bool
	}{
		{name: "force on wins over eager state", force: lazyForceOn, state: mgmProto.LazyState_LazyStateEager, want: true},
		{name: "force off wins over lazy state", force: lazyForceOff, remoteEnabled: true, state: mgmProto.LazyState_LazyStateLazy, want: false},
		{name: "none, default, account off -> active", force: lazyForceNone, state: mgmProto.LazyState_LazyStateDefault, want: false},
		{name: "none, default, account on -> lazy", force: lazyForceNone, remoteEnabled: true, state: mgmProto.LazyState_LazyStateDefault, want: true},
		{name: "none, lazy state, account off -> lazy", force: lazyForceNone, state: mgmProto.LazyState_LazyStateLazy, want: true},
		{name: "none, eager state, account on -> active", force: lazyForceNone, remoteEnabled: true, state: mgmProto.LazyState_LazyStateEager, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := &ConnMgr{force: tt.force, remoteLazyEnabled: tt.remoteEnabled}
			if got := e.PeerLazyDefault(tt.state); got != tt.want {
				t.Fatalf("PeerLazyDefault(%v) = %v, want %v", tt.state, got, tt.want)
			}
		})
	}
}

// TestToExcludedLazyPeers covers the per-peer lazy classification (proxy vs
// normal, across the force/account-flag matrix). Forwarder-target exclusion is
// covered by TestToExcludedLazyPeers_ForwardTarget.
func TestToExcludedLazyPeers(t *testing.T) {
	const (
		normalKey = "normal"
		lazyKey   = "lazy-state"
		eagerKey  = "eager-state"
	)

	peers := []*mgmProto.RemotePeerConfig{
		{WgPubKey: normalKey, AllowedIps: []string{"100.64.0.1/32"}},
		{WgPubKey: lazyKey, AllowedIps: []string{"100.64.0.2/32"}, LazyState: mgmProto.LazyState_LazyStateLazy},
		{WgPubKey: eagerKey, AllowedIps: []string{"100.64.0.3/32"}, LazyState: mgmProto.LazyState_LazyStateEager},
	}

	tests := []struct {
		name          string
		force         lazyForce
		remoteEnabled bool
		want          map[string]bool
	}{
		{
			name:  "account off: lazy-state peer lazy, normal + eager active",
			force: lazyForceNone, remoteEnabled: false,
			want: map[string]bool{normalKey: true, eagerKey: true},
		},
		{
			name:  "account on: only eager-state peer active",
			force: lazyForceNone, remoteEnabled: true,
			want: map[string]bool{eagerKey: true},
		},
		{
			name:  "force off: everything active",
			force: lazyForceOff, remoteEnabled: true,
			want: map[string]bool{normalKey: true, lazyKey: true, eagerKey: true},
		},
		{
			name:  "force on: nothing active",
			force: lazyForceOn, remoteEnabled: false,
			want: map[string]bool{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := &Engine{connMgr: &ConnMgr{force: tt.force, remoteLazyEnabled: tt.remoteEnabled}}
			got := e.toExcludedLazyPeers(nil, peers)

			if len(got) != len(tt.want) {
				t.Fatalf("toExcludedLazyPeers() = %v, want %v", got, tt.want)
			}
			for k := range tt.want {
				if !got[k] {
					t.Fatalf("expected peer %s excluded, got %v", k, got)
				}
			}
		})
	}
}
