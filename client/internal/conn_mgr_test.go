package internal

import (
	"testing"

	"github.com/netbirdio/netbird/client/internal/peerstore"
	"github.com/netbirdio/netbird/shared/connectionmode"
	mgmProto "github.com/netbirdio/netbird/shared/management/proto"
)

func TestResolveConnectionMode(t *testing.T) {
	cases := []struct {
		name            string
		envMode         connectionmode.Mode
		envTimeout      uint32
		cfgMode         connectionmode.Mode
		cfgRelayTimeout uint32
		serverPC        *mgmProto.PeerConfig
		wantMode        connectionmode.Mode
		wantRelay       uint32
	}{
		{
			name:     "all unspecified, server says legacy false -> P2P",
			serverPC: &mgmProto.PeerConfig{LazyConnectionEnabled: false},
			wantMode: connectionmode.ModeP2P,
		},
		{
			name:     "all unspecified, server says legacy true -> P2P_LAZY",
			serverPC: &mgmProto.PeerConfig{LazyConnectionEnabled: true},
			wantMode: connectionmode.ModeP2PLazy,
		},
		{
			name: "server pushes new enum -> wins over legacy bool",
			serverPC: &mgmProto.PeerConfig{
				ConnectionMode:        mgmProto.ConnectionMode_CONNECTION_MODE_RELAY_FORCED,
				LazyConnectionEnabled: false,
			},
			wantMode: connectionmode.ModeRelayForced,
		},
		{
			name:    "client config overrides server",
			cfgMode: connectionmode.ModeP2PLazy,
			serverPC: &mgmProto.PeerConfig{
				ConnectionMode: mgmProto.ConnectionMode_CONNECTION_MODE_P2P,
			},
			wantMode: connectionmode.ModeP2PLazy,
		},
		{
			name:    "follow-server in client config clears local override",
			cfgMode: connectionmode.ModeFollowServer,
			serverPC: &mgmProto.PeerConfig{
				ConnectionMode: mgmProto.ConnectionMode_CONNECTION_MODE_P2P_LAZY,
			},
			wantMode: connectionmode.ModeP2PLazy,
		},
		{
			name:    "env var beats client config",
			envMode: connectionmode.ModeRelayForced,
			cfgMode: connectionmode.ModeP2PLazy,
			serverPC: &mgmProto.PeerConfig{
				ConnectionMode: mgmProto.ConnectionMode_CONNECTION_MODE_P2P,
			},
			wantMode: connectionmode.ModeRelayForced,
		},
		{
			name:       "env timeout beats server timeout",
			envTimeout: 42,
			serverPC:   &mgmProto.PeerConfig{RelayTimeoutSeconds: 100},
			wantMode:   connectionmode.ModeP2P,
			wantRelay:  42,
		},
		{
			name:            "client config timeout beats server",
			cfgRelayTimeout: 50,
			serverPC:        &mgmProto.PeerConfig{RelayTimeoutSeconds: 200},
			wantMode:        connectionmode.ModeP2P,
			wantRelay:       50,
		},
		{
			name:      "no env, no client, only server timeout",
			serverPC:  &mgmProto.PeerConfig{RelayTimeoutSeconds: 300},
			wantMode:  connectionmode.ModeP2P,
			wantRelay: 300,
		},
		{
			name:     "nil serverPC defaults to P2P",
			serverPC: nil,
			wantMode: connectionmode.ModeP2P,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			gotMode, gotRelay := resolveConnectionMode(c.envMode, c.envTimeout, c.cfgMode, c.cfgRelayTimeout, c.serverPC)
			if gotMode != c.wantMode {
				t.Errorf("mode = %v, want %v", gotMode, c.wantMode)
			}
			if gotRelay != c.wantRelay {
				t.Errorf("relay-timeout = %v, want %v", gotRelay, c.wantRelay)
			}
		})
	}
}

// TestConnMgr_DetachICEForPeer_NotFound verifies that detaching ICE
// for a peer not in the store is a no-op (no error). The lookup miss
// can happen if a peer is removed concurrently with a GO_IDLE signal
// or an inactivity-manager fire.
func TestConnMgr_DetachICEForPeer_NotFound(t *testing.T) {
	mgr := &ConnMgr{peerStore: peerstore.NewConnStore()}

	if err := mgr.DetachICEForPeer("unknown-peer-key"); err != nil {
		t.Fatalf("DetachICEForPeer for unknown peer should be no-op, got %v", err)
	}
}

// TestConnMgr_deactivatePeerAction verifies the per-mode dispatch rule:
// p2p-dynamic detaches ICE, p2p-lazy delegates to the lazy manager,
// eager modes (p2p, relay-forced) are silent no-ops. This is the core
// fix for the lazy/eager mismatch (Phase 2 #5989).
func TestConnMgr_deactivatePeerAction(t *testing.T) {
	cases := []struct {
		mode connectionmode.Mode
		want deactivateAction
	}{
		{connectionmode.ModeP2P, deactivateNoop},
		{connectionmode.ModeRelayForced, deactivateNoop},
		{connectionmode.ModeUnspecified, deactivateNoop},
		{connectionmode.ModeP2PLazy, deactivateLazy},
		{connectionmode.ModeP2PDynamic, deactivateICE},
	}
	for _, c := range cases {
		t.Run(c.mode.String(), func(t *testing.T) {
			mgr := &ConnMgr{mode: c.mode}
			if got := mgr.deactivatePeerAction(); got != c.want {
				t.Errorf("mode=%v action=%v want=%v", c.mode, got, c.want)
			}
		})
	}
}
