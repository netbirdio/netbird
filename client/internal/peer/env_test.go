//go:build !js

package peer

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestForceRelayFromEnv(t *testing.T) {
	tests := []struct {
		value      string
		wantForced bool
		wantSet    bool
	}{
		{value: "", wantForced: false, wantSet: false},
		{value: "true", wantForced: true, wantSet: true},
		{value: "TRUE", wantForced: true, wantSet: true},
		{value: "1", wantForced: true, wantSet: true},
		{value: "t", wantForced: true, wantSet: true},
		{value: "false", wantForced: false, wantSet: true},
		{value: "0", wantForced: false, wantSet: true},
		{value: "f", wantForced: false, wantSet: true},
		{value: "yes", wantForced: false, wantSet: false},
	}
	for _, tc := range tests {
		t.Run(tc.value, func(t *testing.T) {
			t.Setenv(EnvKeyNBForceRelay, tc.value)

			forced, set := ForceRelayFromEnv()

			assert.Equal(t, tc.wantForced, forced, "forced for NB_FORCE_RELAY=%q", tc.value)
			assert.Equal(t, tc.wantSet, set, "set for NB_FORCE_RELAY=%q", tc.value)
		})
	}
}
