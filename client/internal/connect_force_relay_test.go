package internal

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/netbirdio/netbird/client/internal/peer"
	"github.com/netbirdio/netbird/client/internal/profilemanager"
	"github.com/netbirdio/netbird/client/mdm"
)

// NB_FORCE_RELAY in the daemon environment wins over the profile when set, as
// environment variables do for every other option; unset or unparseable, the
// profile decides.
func TestForceRelayPrecedence(t *testing.T) {
	for _, tc := range []struct {
		name    string
		env     string
		unset   bool
		profile bool
		want    bool
	}{
		{name: "unset uses the profile (on)", unset: true, profile: true, want: true},
		{name: "unset uses the profile (off)", unset: true, profile: false, want: false},
		{name: "env true wins over profile off", env: "true", profile: false, want: true},
		{name: "env false wins over profile on", env: "false", profile: true, want: false},
		{name: "unparseable env falls back to the profile", env: "maybe", profile: true, want: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(peer.EnvKeyNBForceRelay, tc.env)
			if tc.unset {
				os.Unsetenv(peer.EnvKeyNBForceRelay)
			}
			got := forceRelay(&profilemanager.Config{ForceRelay: tc.profile})
			assert.Equal(t, tc.want, got, "effective force relay")
		})
	}
}

// An MDM policy wins over NB_FORCE_RELAY in the daemon environment, in both
// directions.
func TestForceRelayMDMWinsOverEnv(t *testing.T) {
	for _, tc := range []struct {
		name   string
		env    string
		policy bool
	}{
		{name: "policy off beats env on", env: "true", policy: false},
		{name: "policy on beats env off", env: "false", policy: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(peer.EnvKeyNBForceRelay, tc.env)
			cfg := (&profilemanager.Config{ForceRelay: !tc.policy}).WithMDMPolicy(
				mdm.NewPolicy(map[string]any{mdm.KeyForceRelay: tc.policy}))
			assert.Equal(t, tc.policy, forceRelay(cfg), "the policy decides")
		})
	}
}
