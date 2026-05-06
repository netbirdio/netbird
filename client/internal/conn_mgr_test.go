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
		cfgP2pTimeout   uint32
		serverPC        *mgmProto.PeerConfig
		wantMode        connectionmode.Mode
		wantRelay       uint32
		wantP2P         uint32
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
		{
			name:     "p2p-dynamic with server-pushed timeouts",
			serverPC: &mgmProto.PeerConfig{ConnectionMode: mgmProto.ConnectionMode_CONNECTION_MODE_P2P_DYNAMIC, P2PTimeoutSeconds: 10800, RelayTimeoutSeconds: 86400},
			wantMode: connectionmode.ModeP2PDynamic, wantRelay: 86400, wantP2P: 10800,
		},
		{
			name:          "client config p2p-timeout beats server",
			cfgP2pTimeout: 555,
			serverPC:      &mgmProto.PeerConfig{ConnectionMode: mgmProto.ConnectionMode_CONNECTION_MODE_P2P_DYNAMIC, P2PTimeoutSeconds: 9999},
			wantMode:      connectionmode.ModeP2PDynamic, wantP2P: 555,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			gotMode, gotRelay, gotP2P, _ := resolveConnectionMode(c.envMode, c.envTimeout, c.cfgMode, c.cfgRelayTimeout, c.cfgP2pTimeout, 0, c.serverPC)
			if gotMode != c.wantMode {
				t.Errorf("mode = %v, want %v", gotMode, c.wantMode)
			}
			if gotRelay != c.wantRelay {
				t.Errorf("relay-timeout = %v, want %v", gotRelay, c.wantRelay)
			}
			if gotP2P != c.wantP2P {
				t.Errorf("p2p-timeout = %v, want %v", gotP2P, c.wantP2P)
			}
		})
	}
}

func TestResolveConnectionMode_P2pRetryMax_NotSet(t *testing.T) {
	// serverPC has 0 (= "not set") -> result is 0, daemon will use default
	mode, _, _, retryMax := resolveConnectionMode(
		connectionmode.ModeUnspecified, 0,
		connectionmode.ModeUnspecified, 0, 0, 0,
		&mgmProto.PeerConfig{
			ConnectionMode:     mgmProto.ConnectionMode_CONNECTION_MODE_P2P_DYNAMIC,
			P2PRetryMaxSeconds: 0,
		},
	)
	if mode != connectionmode.ModeP2PDynamic {
		t.Errorf("expected p2p-dynamic, got %v", mode)
	}
	if retryMax != 0 {
		t.Errorf("server-pushed 0 should pass through as 0, got %d", retryMax)
	}
}

func TestResolveConnectionMode_P2pRetryMax_ServerSet(t *testing.T) {
	mode, _, _, retryMax := resolveConnectionMode(
		connectionmode.ModeUnspecified, 0,
		connectionmode.ModeUnspecified, 0, 0, 0,
		&mgmProto.PeerConfig{
			ConnectionMode:     mgmProto.ConnectionMode_CONNECTION_MODE_P2P_DYNAMIC,
			P2PRetryMaxSeconds: 600,
		},
	)
	if mode != connectionmode.ModeP2PDynamic {
		t.Fatalf("expected p2p-dynamic, got %v", mode)
	}
	if retryMax != 600 {
		t.Errorf("server-pushed 600 should win, got %d", retryMax)
	}
}

func TestResolveConnectionMode_P2pRetryMax_ClientCfgWins(t *testing.T) {
	_, _, _, retryMax := resolveConnectionMode(
		connectionmode.ModeUnspecified, 0,
		connectionmode.ModeUnspecified, 0, 0,
		300, // cfgP2pRetryMax (client-side override)
		&mgmProto.PeerConfig{
			P2PRetryMaxSeconds: 600,
		},
	)
	if retryMax != 300 {
		t.Errorf("client cfg should override server push, got %d", retryMax)
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

func TestConnMgr_ServerPushedFieldsAreRaceSafe(t *testing.T) {
	cm := &ConnMgr{}
	done := make(chan struct{})
	go func() {
		for i := 0; i < 1000; i++ {
			cm.spMu.Lock()
			cm.serverPushedRelayTimeoutSecs = uint32(i)
			cm.spMu.Unlock()
		}
		close(done)
	}()
	for i := 0; i < 1000; i++ {
		_ = cm.ServerPushedRelayTimeoutSecs()
	}
	<-done
}
