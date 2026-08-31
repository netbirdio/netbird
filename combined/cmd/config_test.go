package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadConfigEnvironmentWithoutFile(t *testing.T) {
	t.Setenv("NB_SERVER_LOGLEVEL", "debug")

	cfg, err := LoadConfig("")
	require.NoError(t, err)
	assert.Equal(t, "debug", cfg.Server.LogLevel, "Environment should override defaults without a file")
}

func TestLoadConfigEnvironmentOverridesFileAndDefaults(t *testing.T) {
	configPath := writeCombinedConfig(t, "config.yaml", `
server:
  exposedAddress: "https://netbird.example.com"
  authSecret: "file-secret"
  logLevel: "info"
relay:
  logLevel: "ignored-relay-level"
signal:
  logLevel: "ignored-signal-level"
management:
  logLevel: "ignored-management-level"
`)
	t.Setenv("NB_SERVER_LOGLEVEL", "debug")
	t.Setenv("NB_SERVER_METRICSPORT", "9191")

	cfg, err := LoadConfig(configPath)
	require.NoError(t, err)
	assert.Equal(t, "debug", cfg.Server.LogLevel, "Environment should override the config file")
	assert.Equal(t, 9191, cfg.Server.MetricsPort, "Environment should override a default absent from the file")
	assert.Equal(t, ":443", cfg.Server.ListenAddress, "Unchanged defaults should be preserved")
	assert.Equal(t, "debug", cfg.Relay.LogLevel, "Internal relay configuration should not be decoded")
	assert.Equal(t, "debug", cfg.Signal.LogLevel, "Internal signal configuration should not be decoded")
	assert.Equal(t, "debug", cfg.Management.LogLevel, "Internal management configuration should not be decoded")
}

func TestLoadConfigEnvironmentCreatesOptionalConfig(t *testing.T) {
	configPath := writeCombinedConfig(t, "config.yaml", `
server:
  exposedAddress: "https://netbird.example.com"
  authSecret: "file-secret"
`)
	t.Setenv("NB_SERVER_AUTH_OWNER_EMAIL", "owner@example.com")
	t.Setenv("NB_SERVER_AUTH_OWNER_PASSWORD", "password-hash")

	cfg, err := LoadConfig(configPath)
	require.NoError(t, err)
	require.NotNil(t, cfg.Server.Auth.Owner, "Environment should create the optional owner configuration")
	assert.Equal(t, "owner@example.com", cfg.Server.Auth.Owner.Email, "Owner email should come from the environment")
	assert.Equal(t, "password-hash", cfg.Server.Auth.Owner.Password, "Owner password should come from the environment")
}

func TestLoadConfigSupportsYAMLWithoutKnownExtension(t *testing.T) {
	for _, name := range []string{"config", "config.conf"} {
		t.Run(name, func(t *testing.T) {
			configPath := writeCombinedConfig(t, name, `
server:
  exposedAddress: "https://netbird.example.com"
  authSecret: "yaml-secret"
`)

			cfg, err := LoadConfig(configPath)
			require.NoError(t, err)
			assert.Equal(t, "yaml-secret", cfg.Server.AuthSecret, "Unknown extensions should remain YAML-compatible")
		})
	}
}

func TestLoadConfigSupportsLegacyYAMLBooleans(t *testing.T) {
	configPath := writeCombinedConfig(t, "config.yaml", `
server:
  exposedAddress: "https://netbird.example.com"
  authSecret: "file-secret"
  disableAnonymousMetrics: yes
`)

	cfg, err := LoadConfig(configPath)
	require.NoError(t, err)
	assert.True(t, cfg.Server.DisableAnonymousMetrics, "Legacy YAML boolean values should remain supported")
}

func TestLoadConfigSupportsTOML(t *testing.T) {
	configPath := writeCombinedConfig(t, "config.toml", `
[server]
exposedAddress = "https://netbird.example.com"
authSecret = "toml-secret"
logLevel = "warn"
`)

	cfg, err := LoadConfig(configPath)
	require.NoError(t, err)
	assert.Equal(t, "https://netbird.example.com", cfg.Server.ExposedAddress, "Exposed address should be decoded from TOML")
	assert.Equal(t, "toml-secret", cfg.Server.AuthSecret, "Auth secret should be decoded from TOML")
	assert.Equal(t, "warn", cfg.Server.LogLevel, "Log level should be decoded from TOML")
	assert.Equal(t, ":443", cfg.Server.ListenAddress, "Defaults should survive decoding")
}

func writeCombinedConfig(t *testing.T, name, contents string) string {
	t.Helper()

	configPath := filepath.Join(t.TempDir(), name)
	require.NoError(t, os.WriteFile(configPath, []byte(contents), 0o600))
	return configPath
}
