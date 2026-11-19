package internal

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/netbirdio/netbird/client/internal/peer"
	"github.com/netbirdio/netbird/client/internal/profilemanager"
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
