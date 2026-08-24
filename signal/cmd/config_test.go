package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadConfigPrecedence(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "signal.yaml")
	require.NoError(t, os.WriteFile(configPath, []byte(`
port: 10001
metricsPort: 9091
logLevel: warn
pprofAddress: localhost:6060
`), 0o600))
	t.Setenv("NB_METRICS_PORT", "9191")
	t.Setenv("NB_SSL_DIR", "/legacy-certs")
	require.NoError(t, runCmd.ParseFlags(nil))

	portFlag := runCmd.Flags().Lookup("port")
	oldPort := portFlag.Value.String()
	oldChanged := portFlag.Changed
	t.Cleanup(func() {
		require.NoError(t, portFlag.Value.Set(oldPort))
		portFlag.Changed = oldChanged
	})
	require.NoError(t, portFlag.Value.Set("10002"))
	portFlag.Changed = true

	cfg, err := loadConfig(runCmd, configPath)
	require.NoError(t, err)
	assert.Equal(t, 10002, cfg.Port, "Flags should override the configuration file")
	assert.Equal(t, 9191, cfg.MetricsPort, "Environment should override the configuration file")
	assert.Equal(t, "warn", cfg.LogLevel, "File values should override defaults")
	assert.Equal(t, "/legacy-certs", cfg.LetsencryptDataDir, "Legacy environment aliases should remain supported")
	assert.Equal(t, "localhost:6060", cfg.PprofAddress, "Environment-only settings should load from the file")
}
