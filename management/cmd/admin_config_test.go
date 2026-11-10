package cmd

import (
	"context"
	"path"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	nbconfig "github.com/netbirdio/netbird/management/internals/server/config"
	"github.com/netbirdio/netbird/management/server/idp"
)

func TestApplyAdminDatadirOverrideRelocatesDefaultIDPStorage(t *testing.T) {
	oldDatadir := filepath.Join(t.TempDir(), "old")
	newDatadir := filepath.Join(t.TempDir(), "new")

	for _, defaultFile := range []string{
		"",
		filepath.Join(oldDatadir, "idp.db"),
		path.Join(oldDatadir, "idp.db"),
	} {
		t.Run(defaultFile, func(t *testing.T) {
			cfg := &nbconfig.Config{
				EmbeddedIdP: &idp.EmbeddedIdPConfig{
					Enabled: true,
					Storage: idp.EmbeddedStorageConfig{
						Type: "sqlite3",
						Config: idp.EmbeddedStorageTypeConfig{
							File: defaultFile,
						},
					},
				},
			}
			datadir := oldDatadir
			oldAdminDatadir := adminDatadir
			adminDatadir = newDatadir
			t.Cleanup(func() { adminDatadir = oldAdminDatadir })

			applyAdminDatadirOverride(cfg, &datadir)

			require.Equal(t, newDatadir, datadir)
			require.Equal(t, filepath.Join(newDatadir, "idp.db"), cfg.EmbeddedIdP.Storage.Config.File)
		})
	}
}

func TestOpenAdminEventStoreMissingEncryptionKeyReturnsNilInterface(t *testing.T) {
	eventStore, err := openAdminEventStore(context.Background(), &nbconfig.Config{}, t.TempDir())
	require.Error(t, err)
	require.Contains(t, err.Error(), "encryption key")
	require.Nil(t, eventStore)
}

func TestApplyAdminDatadirOverrideKeepsExplicitIDPStorage(t *testing.T) {
	oldDatadir := filepath.Join(t.TempDir(), "old")
	newDatadir := filepath.Join(t.TempDir(), "new")
	explicitFile := filepath.Join(t.TempDir(), "custom-idp.db")
	cfg := &nbconfig.Config{
		EmbeddedIdP: &idp.EmbeddedIdPConfig{
			Enabled: true,
			Storage: idp.EmbeddedStorageConfig{
				Type: "sqlite3",
				Config: idp.EmbeddedStorageTypeConfig{
					File: explicitFile,
				},
			},
		},
	}
	datadir := oldDatadir
	oldAdminDatadir := adminDatadir
	adminDatadir = newDatadir
	t.Cleanup(func() { adminDatadir = oldAdminDatadir })

	applyAdminDatadirOverride(cfg, &datadir)

	require.Equal(t, newDatadir, datadir)
	require.Equal(t, explicitFile, cfg.EmbeddedIdP.Storage.Config.File)
}

func TestResolveMigrateDatadirMatchesServer(t *testing.T) {
	oldMgmtDataDir := mgmtDataDir
	t.Cleanup(func() { mgmtDataDir = oldMgmtDataDir })

	for _, tc := range []struct {
		name       string
		configDir  string
		flag       string
		serverFlag string
	}{
		{name: "empty config datadir", configDir: "", flag: "", serverFlag: defaultMgmtDataDir},
		{name: "non-empty config datadir", configDir: "/srv/from-config", flag: "", serverFlag: defaultMgmtDataDir},
		{name: "explicit flag", configDir: "/srv/from-config", flag: "/srv/flag", serverFlag: "/srv/flag"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mgmtDataDir = tc.serverFlag
			serverConfig := &nbconfig.Config{Datadir: tc.configDir}
			ApplyCommandLineOverrides(serverConfig)

			require.Equal(t, serverConfig.Datadir, resolveMigrateDatadir(tc.flag))
		})
	}
}
