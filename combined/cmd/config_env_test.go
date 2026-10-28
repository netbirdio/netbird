package cmd

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func unsetSecretEnvs(t *testing.T) {
	t.Helper()
	t.Setenv(envRelayAuthSecret, "")
	t.Setenv(envStoreEncryptionKey, "")
	require.NoError(t, os.Unsetenv(envRelayAuthSecret))
	require.NoError(t, os.Unsetenv(envStoreEncryptionKey))
}

func writeCombinedConfig(t *testing.T, authSecret, encryptionKey string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	content := fmt.Sprintf(`
server:
  exposedAddress: "https://example.com:443"
  dataDir: %q
  authSecret: %q
  store:
    encryptionKey: %q
`, dir, authSecret, encryptionKey)
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	return path
}

func TestLoadConfigRelayAuthSecretEnv(t *testing.T) {
	envSecret := "env-relay-auth-secret"
	yamlSecret := "yaml-relay-auth-secret"

	tests := []struct {
		name       string
		yamlSecret string
		envValue   string
		envSet     bool
		wantSecret string
		wantErr    string
	}{
		{
			name:       "env unset uses YAML",
			yamlSecret: yamlSecret,
			wantSecret: yamlSecret,
		},
		{
			name:       "env overrides YAML",
			yamlSecret: yamlSecret,
			envValue:   envSecret,
			envSet:     true,
			wantSecret: envSecret,
		},
		{
			name:       "empty env leaves YAML",
			yamlSecret: yamlSecret,
			envValue:   "",
			envSet:     true,
			wantSecret: yamlSecret,
		},
		{
			name:       "env set with empty YAML passes validation",
			yamlSecret: "",
			envValue:   envSecret,
			envSet:     true,
			wantSecret: envSecret,
		},
		{
			name:       "neither set requires authSecret",
			yamlSecret: "",
			wantErr:    "server.authSecret is required when running local relay",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			unsetSecretEnvs(t)
			if tc.envSet {
				t.Setenv(envRelayAuthSecret, tc.envValue)
			}

			cfg, err := LoadConfig(writeCombinedConfig(t, tc.yamlSecret, "yaml-store-key"))
			require.NoError(t, err)

			err = cfg.Validate()
			if tc.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.wantErr, "validation error should mention authSecret")
				return
			}
			require.NoError(t, err)

			assert.Equal(t, tc.wantSecret, cfg.Server.AuthSecret, "server.authSecret")
			assert.Equal(t, tc.wantSecret, cfg.Relay.AuthSecret, "relay.authSecret")
			assert.Equal(t, tc.wantSecret, cfg.Management.Relays.Secret, "management.relays.secret")
		})
	}
}

func TestLoadConfigStoreEncryptionKeyEnv(t *testing.T) {
	envKey := "env-store-encryption-key"
	yamlKey := "yaml-store-encryption-key"

	tests := []struct {
		name     string
		yamlKey  string
		envValue string
		envSet   bool
		wantKey  string
	}{
		{
			name:    "env unset uses YAML",
			yamlKey: yamlKey,
			wantKey: yamlKey,
		},
		{
			name:     "env overrides YAML",
			yamlKey:  yamlKey,
			envValue: envKey,
			envSet:   true,
			wantKey:  envKey,
		},
		{
			name:     "empty env leaves YAML",
			yamlKey:  yamlKey,
			envValue: "",
			envSet:   true,
			wantKey:  yamlKey,
		},
		{
			name:     "env set with empty YAML",
			yamlKey:  "",
			envValue: envKey,
			envSet:   true,
			wantKey:  envKey,
		},
		{
			name:    "neither set leaves encryption key empty",
			yamlKey: "",
			wantKey: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			unsetSecretEnvs(t)
			if tc.envSet {
				t.Setenv(envStoreEncryptionKey, tc.envValue)
			}

			cfg, err := LoadConfig(writeCombinedConfig(t, "yaml-relay-secret", tc.yamlKey))
			require.NoError(t, err)
			require.NoError(t, cfg.Validate())

			assert.Equal(t, tc.wantKey, cfg.Server.Store.EncryptionKey, "server.store.encryptionKey")
			assert.Equal(t, tc.wantKey, cfg.Management.Store.EncryptionKey, "management.store.encryptionKey")

			mgmt, err := cfg.ToManagementConfig()
			require.NoError(t, err)
			assert.Equal(t, tc.wantKey, mgmt.DataStoreEncryptionKey, "management DataStoreEncryptionKey")
		})
	}
}

func TestApplyServerSecretEnvLogsNameNotValue(t *testing.T) {
	unsetSecretEnvs(t)
	secret := "relay-secret-must-not-appear"
	key := "store-key-must-not-appear"
	t.Setenv(envRelayAuthSecret, secret)
	t.Setenv(envStoreEncryptionKey, key)

	buf := captureLogOutput(t)
	cfg := DefaultConfig()
	applyServerSecretEnv(cfg)

	out := buf.String()
	assert.Contains(t, out, envRelayAuthSecret, "info log should name the relay auth env var")
	assert.Contains(t, out, envStoreEncryptionKey, "info log should name the store encryption env var")
	assert.NotContains(t, out, secret, "info log must not include the relay auth secret")
	assert.NotContains(t, out, key, "info log must not include the store encryption key")
	assert.Equal(t, secret, cfg.Server.AuthSecret, "auth secret should be taken from the environment")
	assert.Equal(t, key, cfg.Server.Store.EncryptionKey, "encryption key should be taken from the environment")
}

func TestLogEnvVarsMasksRelayAndStoreSecrets(t *testing.T) {
	unsetSecretEnvs(t)
	secret := "relay-secret-must-not-appear"
	key := "store-key-must-not-appear"
	t.Setenv(envRelayAuthSecret, secret)
	t.Setenv(envStoreEncryptionKey, key)

	buf := captureLogOutput(t)
	logEnvVars()

	out := buf.String()
	assert.Contains(t, out, envRelayAuthSecret+"=", "logEnvVars should list the relay auth env var")
	assert.Contains(t, out, envStoreEncryptionKey+"=", "logEnvVars should list the store encryption env var")
	assert.NotContains(t, out, secret, "logEnvVars must not include the relay auth secret")
	assert.NotContains(t, out, key, "logEnvVars must not include the store encryption key")
	assert.Contains(t, out, maskSecret(secret), "logEnvVars should mask the relay auth secret")
	assert.Contains(t, out, maskSecret(key), "logEnvVars should mask the store encryption key")
}

func captureLogOutput(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	logger := log.StandardLogger()
	origOut := logger.Out
	origLevel := logger.GetLevel()
	logger.SetOutput(&buf)
	logger.SetLevel(log.DebugLevel)
	t.Cleanup(func() {
		logger.SetOutput(origOut)
		logger.SetLevel(origLevel)
	})
	return &buf
}
