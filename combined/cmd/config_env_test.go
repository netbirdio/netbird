package cmd

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	nbconfig "github.com/netbirdio/netbird/management/internals/server/config"
	"github.com/netbirdio/netbird/shared/peerauth"
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

func TestLoadConfigNoPathSecretEnv(t *testing.T) {
	unsetSecretEnvs(t)
	t.Setenv(envRelayAuthSecret, "env-relay-auth-secret")
	t.Setenv(envStoreEncryptionKey, "env-store-encryption-key")

	cfg, err := LoadConfig("")
	require.NoError(t, err)
	assert.Equal(t, "env-relay-auth-secret", cfg.Server.AuthSecret, "server.authSecret")
	assert.Equal(t, "env-store-encryption-key", cfg.Server.Store.EncryptionKey, "server.store.encryptionKey")
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

func TestToManagementConfigPeerAuth(t *testing.T) {
	unsetSecretEnvs(t)
	mgmtPub, mgmtPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalPKCS8PrivateKey(mgmtPriv)
	require.NoError(t, err)
	keyFile := filepath.Join(t.TempDir(), "peer_auth.pem")
	require.NoError(t, os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600))

	path := writeCombinedConfig(t, "relay-secret", "")
	content, err := os.ReadFile(path)
	require.NoError(t, err)
	content = append(content, []byte("  peerAuth:\n    signingKeyFile: "+keyFile+"\n")...)
	require.NoError(t, os.WriteFile(path, content, 0o600))

	cfg, err := LoadConfig(path)
	require.NoError(t, err)
	require.NoError(t, cfg.Validate())
	mgmt, err := cfg.ToManagementConfig()
	require.NoError(t, err)

	assert.Equal(t, nbconfig.PeerAuth{SigningKeyFile: keyFile}, mgmt.PeerAuth, "server.peerAuth must reach the Management config")

	keys, err := localPeerAuthKeys(cfg)
	require.NoError(t, err)
	assert.Equal(t, map[peerauth.KeyID]ed25519.PublicKey{peerauth.Ed25519KeyID(mgmtPub): mgmtPub}, keys.Ed25519,
		"the local Relay and Signal must verify with the public key of the key Management signs with")
}

func TestLocalPeerAuthKeys_NoSigningKey(t *testing.T) {
	keys, err := localPeerAuthKeys(&CombinedConfig{})
	require.NoError(t, err)
	assert.Empty(t, keys.Ed25519, "without a signing key no bound token is issued, so none is verified")
}

func TestEnsurePeerAuthSigningKey(t *testing.T) {
	cfgWith := func(path string) *CombinedConfig {
		cfg := &CombinedConfig{}
		cfg.Server.PeerAuth.SigningKeyFile = path
		return cfg
	}

	t.Run("missing file is generated", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "peer_auth.pem")
		require.NoError(t, EnsurePeerAuthSigningKey(context.Background(), cfgWith(path)))

		entries, err := os.ReadDir(dir)
		require.NoError(t, err)
		require.Len(t, entries, 1, "the temporary file must be removed")
		assert.Equal(t, "peer_auth.pem", entries[0].Name())

		info, err := os.Stat(path)
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0o600), info.Mode().Perm(), "the private key must be readable by the owner only")

		key, err := peerauth.LoadSigningKeyFile(path)
		require.NoError(t, err, "the generated key must load as Management loads it")
		keys, err := localPeerAuthKeys(cfgWith(path))
		require.NoError(t, err)
		assert.Equal(t, []peerauth.KeyID{peerauth.Ed25519KeyID(key.Public().(ed25519.PublicKey))}, keys.KeyIDs(),
			"the local Relay and Signal must verify with the generated key")
	})

	t.Run("existing file is kept", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "peer_auth.pem")
		require.NoError(t, EnsurePeerAuthSigningKey(context.Background(), cfgWith(path)))
		before, err := os.ReadFile(path)
		require.NoError(t, err)

		require.NoError(t, EnsurePeerAuthSigningKey(context.Background(), cfgWith(path)))
		after, err := os.ReadFile(path)
		require.NoError(t, err)
		assert.Equal(t, before, after, "an existing key must never be replaced, or every issued token stops verifying")
	})

	t.Run("parent is not a directory", func(t *testing.T) {
		notADir := filepath.Join(t.TempDir(), "file")
		require.NoError(t, os.WriteFile(notADir, nil, 0o600))
		path := filepath.Join(notADir, "peer_auth.pem")
		assert.Error(t, EnsurePeerAuthSigningKey(context.Background(), cfgWith(path)), "a key that cannot be created must fail startup")
	})
}

func TestPeerAuthHostnamesConfig(t *testing.T) {
	unsetSecretEnvs(t)
	path := writeCombinedConfig(t, "relay-secret", "")
	content, err := os.ReadFile(path)
	require.NoError(t, err)
	content = append(content, []byte("  peerAuth:\n    hostnames: [netbird.example.com, relay.example.com]\n")...)
	require.NoError(t, os.WriteFile(path, content, 0o600))

	cfg, err := LoadConfig(path)
	require.NoError(t, err)
	assert.Equal(t, []string{"netbird.example.com", "relay.example.com"}, cfg.Server.PeerAuth.Hostnames,
		"server.peerAuth.hostnames must reach the local Relay and Signal")
}
