package cmd

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadConfigPrecedence(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "proxy.yaml")
	require.NoError(t, os.WriteFile(configPath, []byte(`
domain: file.example.com
trustedProxies: 192.0.2.0/24
maxDialTimeout: 5s
`), 0o600))
	t.Setenv("NB_PROXY_TOKEN", "environment-token")
	require.NoError(t, rootCmd.ParseFlags(nil))

	domainFlag := rootCmd.Flags().Lookup("domain")
	oldDomain := domainFlag.Value.String()
	oldChanged := domainFlag.Changed
	t.Cleanup(func() {
		require.NoError(t, domainFlag.Value.Set(oldDomain))
		domainFlag.Changed = oldChanged
	})
	require.NoError(t, domainFlag.Value.Set("flag.example.com"))
	domainFlag.Changed = true

	cfg, err := loadConfig(rootCmd, configPath)
	require.NoError(t, err)
	assert.Equal(t, "flag.example.com", cfg.ProxyURL, "Flags should override the configuration file")
	assert.Equal(t, "environment-token", cfg.ProxyToken, "Environment should populate secrets")
	assert.Equal(t, 5*time.Second, cfg.MaxDialTimeout, "Durations should be decoded from the file")
	require.NotNil(t, cfg.TrustedProxies, "Trusted proxies should be decoded")
	assert.False(t, cfg.TrustedProxies.Empty(), "Configured trusted proxies should not be empty")
}
