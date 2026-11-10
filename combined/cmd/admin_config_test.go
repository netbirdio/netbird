package cmd

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"

	migratecmd "github.com/netbirdio/netbird/management/cmd/migrate"
	accesslogsmanager "github.com/netbirdio/netbird/management/internals/modules/reverseproxy/accesslogs/manager"
	nbconfig "github.com/netbirdio/netbird/management/internals/server/config"
)

func TestApplyAdminDefaultsCopiesServerStoreWithoutExposedAddress(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Server.ExposedAddress = ""
	cfg.Server.DataDir = "/srv/netbird"
	cfg.Server.Store = StoreConfig{
		Engine: "postgres",
		DSN:    "postgres://user:pass@example.com/netbird",
	}

	cfg.ApplyAdminDefaults()

	require.Equal(t, "/srv/netbird", cfg.Management.DataDir)
	require.Equal(t, "postgres", cfg.Management.Store.Engine)
	require.Equal(t, cfg.Server.Store.DSN, cfg.Management.Store.DSN)
}

func TestOpenAdminEventStoreMissingEncryptionKeyReturnsNilInterface(t *testing.T) {
	eventStore, err := openAdminEventStore(context.Background(), &CombinedConfig{}, &nbconfig.Config{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "encryption key")
	require.Nil(t, eventStore)
}

func TestApplyServerStoreEnv(t *testing.T) {
	t.Setenv("NB_STORE_ENGINE_POSTGRES_DSN", "")
	t.Setenv("NB_STORE_ENGINE_SQLITE_FILE", "")

	applyServerStoreEnv(StoreConfig{Engine: "postgres", DSN: "postgres-dsn", File: "store.db"})
	require.Equal(t, "postgres-dsn", os.Getenv("NB_STORE_ENGINE_POSTGRES_DSN"))
	require.Equal(t, "store.db", os.Getenv("NB_STORE_ENGINE_SQLITE_FILE"))
}

func TestApplyAccessLogStoreEnv(t *testing.T) {
	keys := []string{accesslogsmanager.StoreEngineEnv, accesslogsmanager.PostgresDSNEnv, accesslogsmanager.SqliteFileEnv}
	for _, key := range keys {
		t.Setenv(key, "")
		require.NoError(t, os.Unsetenv(key))
	}

	applyAccessLogStoreEnv(StoreConfig{})
	for _, key := range keys {
		_, ok := os.LookupEnv(key)
		require.False(t, ok, "%s should stay unset for an empty accessLogStore block", key)
	}

	applyAccessLogStoreEnv(StoreConfig{Engine: "Postgres", DSN: "postgres-dsn", File: "access_logs.db"})
	require.Equal(t, "postgres", os.Getenv(accesslogsmanager.StoreEngineEnv))
	require.Equal(t, "postgres-dsn", os.Getenv(accesslogsmanager.PostgresDSNEnv))
	require.Equal(t, "access_logs.db", os.Getenv(accesslogsmanager.SqliteFileEnv))
}

func TestMigrationTargetsUseConfiguredAccessLogFile(t *testing.T) {
	for _, key := range []string{accesslogsmanager.StoreEngineEnv, accesslogsmanager.PostgresDSNEnv, accesslogsmanager.SqliteFileEnv} {
		t.Setenv(key, "")
		require.NoError(t, os.Unsetenv(key))
	}

	dataDir := t.TempDir()
	accessLogFile := filepath.Join(t.TempDir(), "custom_access_logs.db")
	configFile := filepath.Join(t.TempDir(), "config.yaml")
	yaml := "server:\n  authSecret: secret\n  dataDir: " + dataDir + "\n  store:\n    encryptionKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n  accessLogStore:\n    file: " + accessLogFile + "\n"
	require.NoError(t, os.WriteFile(configFile, []byte(yaml), 0o600))

	oldConfigPath := configPath
	configPath = configFile
	t.Cleanup(func() { configPath = oldConfigPath })

	cmd := &cobra.Command{}
	cmd.SetContext(context.Background())
	err := withMigrationTargets(cmd, func(_ context.Context, targets []migratecmd.Target) error {
		require.NotEmpty(t, targets)
		return nil
	})
	require.NoError(t, err)

	require.Equal(t, accessLogFile, os.Getenv(accesslogsmanager.SqliteFileEnv))
	require.FileExists(t, accessLogFile)
	require.NoFileExists(t, filepath.Join(dataDir, "access_logs.db"))
}
