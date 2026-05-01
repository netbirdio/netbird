package peer

import (
	"testing"

	"github.com/netbirdio/netbird/client/internal/peer/connectionmode"
)

func TestResolveModeFromEnv(t *testing.T) {
	cases := []struct {
		name            string
		envConnMode     string
		envForceRelay   string
		envEnableLazy   string
		envInactivity   string
		wantMode        connectionmode.Mode
		wantTimeoutSecs uint32
	}{
		{"all unset", "", "", "", "", connectionmode.ModeUnspecified, 0},
		{"connection_mode wins", "p2p-dynamic", "true", "true", "10s", connectionmode.ModeP2PDynamic, 10},
		{"force_relay alone", "", "true", "", "", connectionmode.ModeRelayForced, 0},
		{"lazy alone", "", "", "true", "", connectionmode.ModeP2PLazy, 0},
		{"force_relay AND lazy: force_relay wins", "", "true", "true", "", connectionmode.ModeRelayForced, 0},
		{"only inactivity threshold", "", "", "", "30m", connectionmode.ModeUnspecified, 1800},
		{"connection_mode unparseable falls through to legacy", "garbage", "true", "", "", connectionmode.ModeRelayForced, 0},
		{"connection_mode parses p2p-lazy", "p2p-lazy", "", "", "", connectionmode.ModeP2PLazy, 0},
		{"force-relay value is true (case-insensitive)", "", "TRUE", "", "", connectionmode.ModeRelayForced, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Setenv(EnvKeyNBConnectionMode, c.envConnMode)
			t.Setenv(EnvKeyNBForceRelay, c.envForceRelay)
			t.Setenv("NB_ENABLE_EXPERIMENTAL_LAZY_CONN", c.envEnableLazy)
			t.Setenv("NB_LAZY_CONN_INACTIVITY_THRESHOLD", c.envInactivity)

			gotMode, gotTimeout := ResolveModeFromEnv()
			if gotMode != c.wantMode {
				t.Errorf("mode = %v, want %v", gotMode, c.wantMode)
			}
			if gotTimeout != c.wantTimeoutSecs {
				t.Errorf("timeout = %v, want %v", gotTimeout, c.wantTimeoutSecs)
			}
		})
	}
}

func TestIsForceRelayedBackwardsCompat(t *testing.T) {
	// IsForceRelayed must remain functional for existing callers
	// during the migration window (env.go still exposes it).
	t.Setenv(EnvKeyNBForceRelay, "true")
	if !IsForceRelayed() {
		t.Error("IsForceRelayed() should return true when NB_FORCE_RELAY=true")
	}
	t.Setenv(EnvKeyNBForceRelay, "false")
	if IsForceRelayed() {
		t.Error("IsForceRelayed() should return false when NB_FORCE_RELAY=false")
	}
}
