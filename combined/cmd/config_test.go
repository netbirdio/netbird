package cmd

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestDisableLegacyPort(t *testing.T) {
	for _, tc := range []struct {
		name     string
		setting  string
		disabled bool
	}{
		{name: "unset"},
		{name: "false", setting: "  disableLegacyPort: false\n"},
		{name: "true", setting: "  disableLegacyPort: true\n", disabled: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := DefaultConfig()
			err := yaml.Unmarshal([]byte("server:\n  exposedAddress: https://netbird.example.com:443\n"+tc.setting), cfg)
			require.NoError(t, err)

			cfg.ApplySimplifiedDefaults()

			assert.Equal(t, tc.disabled, cfg.Management.DisableLegacyPort,
				"the combined server must preserve compatibility unless explicitly disabled")
		})
	}
}
