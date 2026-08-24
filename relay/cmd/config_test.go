package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadConfigPrecedence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "relay.yaml")
	require.NoError(t, os.WriteFile(path, []byte(`
listenAddress: ":8443"
exposedAddress: "relay.example.com:443"
authSecret: file-secret
metricsPort: 9091
enableSTUN: true
stunPorts: [3478, 3479]
`), 0o600))
	t.Setenv("NB_METRICS_PORT", "9191")
	require.NoError(t, rootCmd.ParseFlags(nil))

	listenFlag := rootCmd.Flags().Lookup("listen-address")
	oldListen := listenFlag.Value.String()
	oldChanged := listenFlag.Changed
	t.Cleanup(func() {
		require.NoError(t, listenFlag.Value.Set(oldListen))
		listenFlag.Changed = oldChanged
	})
	require.NoError(t, listenFlag.Value.Set(":7443"))
	listenFlag.Changed = true

	oldConfigPath := configPath
	configPath = path
	t.Cleanup(func() {
		configPath = oldConfigPath
	})

	cfg, err := loadConfig(rootCmd)
	require.NoError(t, err)
	assert.Equal(t, ":7443", cfg.ListenAddress, "Flags should override the configuration file")
	assert.Equal(t, 9191, cfg.MetricsPort, "Environment should override the configuration file")
	assert.Equal(t, "relay.example.com:443", cfg.ExposedAddress, "File values should override defaults")
	assert.True(t, cfg.EnableSTUN, "STUN should be configurable from the file")
	assert.Equal(t, []int{3478, 3479}, cfg.STUNPorts, "STUN ports should load from the file")
}
