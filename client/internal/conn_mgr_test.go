package internal

import (
	"testing"

	"github.com/netbirdio/netbird/client/internal/peer/connectionmode"
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
