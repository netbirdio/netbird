package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestInitializeConfig_ActivityStorePostgresDSNFromEnv reproduces netbirdio/netbird#5976:
// when server.activityStore.engine is "postgres" but server.activityStore.dsn is not set
// in config.yaml, initializeConfig() must still succeed if the DSN is supplied via the
// NB_ACTIVITY_EVENT_POSTGRES_DSN environment variable instead - the store layer
// (management/server/activity/store/sql_store.go) already reads that env var as a fallback,
// but the eager validation in initializeConfig() currently rejects the config before it
// gets a chance to.
func TestInitializeConfig_ActivityStorePostgresDSNFromEnv(t *testing.T) {
	dir := t.TempDir()
	cfgFile := filepath.Join(dir, "config.yaml")

	yamlContent := `
server:
  exposedAddress: "https://netbird.example.com:443"
  dataDir: "` + dir + `"
  authSecret: "test-secret"
  activityStore:
    engine: postgres
`
	require.NoError(t, os.WriteFile(cfgFile, []byte(yamlContent), 0o600))

	t.Setenv("NB_ACTIVITY_EVENT_POSTGRES_DSN", "postgres://user:pass@localhost:5432/activity")

	oldConfigPath := configPath
	oldConfig := config
	t.Cleanup(func() {
		configPath = oldConfigPath
		config = oldConfig
	})
	configPath = cfgFile

	err := initializeConfig()
	require.NoError(t, err, "initializeConfig should accept activityStore DSN supplied via NB_ACTIVITY_EVENT_POSTGRES_DSN env var")
}

// TestInitializeConfig_ActivityStorePostgresMissingDSN is the companion regression test:
// with activityStore.engine=postgres and no DSN in config.yaml, initializeConfig() must
// still reject the config when NB_ACTIVITY_EVENT_POSTGRES_DSN is either unset or set to
// an empty string - an empty env var must not be treated as "provided".
func TestInitializeConfig_ActivityStorePostgresMissingDSN(t *testing.T) {
	dir := t.TempDir()
	cfgFile := filepath.Join(dir, "config.yaml")

	yamlContent := `
server:
  exposedAddress: "https://netbird.example.com:443"
  dataDir: "` + dir + `"
  authSecret: "test-secret"
  activityStore:
    engine: postgres
`
	require.NoError(t, os.WriteFile(cfgFile, []byte(yamlContent), 0o600))

	oldConfigPath := configPath
	oldConfig := config
	t.Cleanup(func() {
		configPath = oldConfigPath
		config = oldConfig
	})
	configPath = cfgFile

	t.Run("env var unset", func(t *testing.T) {
		if orig, wasSet := os.LookupEnv("NB_ACTIVITY_EVENT_POSTGRES_DSN"); wasSet {
			t.Cleanup(func() { os.Setenv("NB_ACTIVITY_EVENT_POSTGRES_DSN", orig) })
		}
		os.Unsetenv("NB_ACTIVITY_EVENT_POSTGRES_DSN")
		err := initializeConfig()
		require.Error(t, err, "initializeConfig should reject missing activityStore DSN when no env var is set")
	})

	t.Run("env var empty string", func(t *testing.T) {
		t.Setenv("NB_ACTIVITY_EVENT_POSTGRES_DSN", "")
		err := initializeConfig()
		require.Error(t, err, "initializeConfig should reject an empty activityStore DSN env var, not treat it as provided")
	})
}
