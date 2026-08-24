package cmd

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadManagementConfigSources(t *testing.T) {
	t.Setenv("MANAGEMENT_DATA_DIR", "/template-data")
	t.Setenv("MANAGEMENT_ENCRYPTION_KEY", "template-key")
	t.Setenv("NB_DATADIR", "/environment-data")
	t.Setenv("NB_HTTPCONFIG_AUTHAUDIENCE", "environment-audience")
	configPath := filepath.Join(t.TempDir(), "management.json")
	require.NoError(t, os.WriteFile(configPath, []byte(`{
  "Datadir": "{{ .MANAGEMENT_DATA_DIR }}",
  "DataStoreEncryptionKey": "{{ .MANAGEMENT_ENCRYPTION_KEY }}",
  "HttpConfig": {
    "AuthAudience": "file-audience"
  },
  "TURNConfig": {
    "CredentialsTTL": "1h"
  }
}`), 0o600))

	cfg, err := loadManagementConfig(configPath)
	require.NoError(t, err)
	assert.Equal(t, "/environment-data", cfg.Datadir, "Bound environment values should override template values")
	assert.Equal(t, "template-key", cfg.DataStoreEncryptionKey, "Template environment values should be expanded")
	require.NotNil(t, cfg.HttpConfig, "Nested configuration should be decoded")
	assert.Equal(t, "environment-audience", cfg.HttpConfig.AuthAudience, "Bound environment values should override the file")
	require.NotNil(t, cfg.TURNConfig, "TURN configuration should be decoded")
	assert.Equal(t, time.Hour, cfg.TURNConfig.CredentialsTTL.Duration, "JSON duration types should be decoded")

	datadirFlag := mgmtCmd.Flags().Lookup("datadir")
	oldDatadir := datadirFlag.Value.String()
	oldChanged := datadirFlag.Changed
	t.Cleanup(func() {
		require.NoError(t, datadirFlag.Value.Set(oldDatadir))
		datadirFlag.Changed = oldChanged
	})
	require.NoError(t, datadirFlag.Value.Set("/flag-data"))
	datadirFlag.Changed = true
	ApplyCommandLineOverrides(cfg, mgmtCmd.Flags())
	assert.Equal(t, "/flag-data", cfg.Datadir, "Flags should override environment values")
}
