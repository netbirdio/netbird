package internal

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/util"
)

func TestGetConfig(t *testing.T) {
	// case 1: new default config has to be generated
	config, err := UpdateOrCreateConfig(ConfigInput{
		ConfigPath: filepath.Join(t.TempDir(), "config.json"),
	})
	if err != nil {
		return
	}

	assert.Equal(t, config.ManagementURL.String(), DefaultManagementURL)
	assert.Equal(t, config.AdminURL.String(), DefaultAdminURL)

	managementURL := "https://test.management.url:33071"
	adminURL := "https://app.admin.url:443"
	path := filepath.Join(t.TempDir(), "config.json")
	preSharedKey := "preSharedKey"

	// case 2: new config has to be generated
	config, err = UpdateOrCreateConfig(ConfigInput{
		ManagementURL: managementURL,
		AdminURL:      adminURL,
		ConfigPath:    path,
		PreSharedKey:  &preSharedKey,
	})
	if err != nil {
		return
	}

	assert.Equal(t, config.ManagementURL.String(), managementURL)
	assert.Equal(t, config.PreSharedKey, preSharedKey)

	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		t.Errorf("config file was expected to be created under path %s", path)
	}

	// case 3: existing config -> fetch it
	config, err = UpdateOrCreateConfig(ConfigInput{
		ManagementURL: managementURL,
		AdminURL:      adminURL,
		ConfigPath:    path,
		PreSharedKey:  &preSharedKey,
	})
	if err != nil {
		return
	}

	assert.Equal(t, config.ManagementURL.String(), managementURL)
	assert.Equal(t, config.PreSharedKey, preSharedKey)

	// case 4: existing config, but new managementURL has been provided -> update config
	newManagementURL := "https://test.newManagement.url:33071"
	config, err = UpdateOrCreateConfig(ConfigInput{
		ManagementURL: newManagementURL,
		AdminURL:      adminURL,
		ConfigPath:    path,
		PreSharedKey:  &preSharedKey,
	})
	if err != nil {
		return
	}

	assert.Equal(t, config.ManagementURL.String(), newManagementURL)
	assert.Equal(t, config.PreSharedKey, preSharedKey)

	// read once more to make sure that config file has been updated with the new management URL
	readConf, err := util.ReadJson(path, config)
	if err != nil {
		return
	}
	assert.Equal(t, readConf.(*Config).ManagementURL.String(), newManagementURL)
}

func TestExtraIFaceBlackList(t *testing.T) {
	extraIFaceBlackList := []string{"eth1"}
	path := filepath.Join(t.TempDir(), "config.json")
	config, err := UpdateOrCreateConfig(ConfigInput{
		ConfigPath:          path,
		ExtraIFaceBlackList: extraIFaceBlackList,
	})
	if err != nil {
		return
	}

	assert.Contains(t, config.IFaceBlackList, "eth1")
	readConf, err := util.ReadJson(path, config)
	if err != nil {
		return
	}

	assert.Contains(t, readConf.(*Config).IFaceBlackList, "eth1")
}

func TestHiddenPreSharedKey(t *testing.T) {
	hidden := "**********"
	samplePreSharedKey := "mysecretpresharedkey"
	tests := []struct {
		name         string
		preSharedKey *string
		want         string
	}{
		{"nil", nil, ""},
		{"hidden", &hidden, ""},
		{"filled", &samplePreSharedKey, samplePreSharedKey},
	}

	// generate default cfg
	cfgFile := filepath.Join(t.TempDir(), "config.json")
	_, _ = UpdateOrCreateConfig(ConfigInput{
		ConfigPath: cfgFile,
	})

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := UpdateOrCreateConfig(ConfigInput{
				ConfigPath:   cfgFile,
				PreSharedKey: tt.preSharedKey,
			})
			if err != nil {
				t.Fatalf("failed to get cfg: %s", err)
			}

			if cfg.PreSharedKey != tt.want {
				t.Fatalf("invalid preshared key: '%s', expected: '%s' ", cfg.PreSharedKey, tt.want)
			}
		})
	}
}

func TestUpdateOldManagementURL(t *testing.T) {
	tests := []struct {
		name                  string
		previousManagementURL string
		expectedManagementURL string
		fileShouldNotChange   bool
	}{
		{
			name:                  "Update old management URL with legacy port",
			previousManagementURL: "https://api.wiretrustee.com:33073",
			expectedManagementURL: DefaultManagementURL,
		},
		{
			name:                  "Update old management URL",
			previousManagementURL: oldDefaultManagementURL,
			expectedManagementURL: DefaultManagementURL,
		},
		{
			name:                  "No update needed when management URL is up to date",
			previousManagementURL: DefaultManagementURL,
			expectedManagementURL: DefaultManagementURL,
			fileShouldNotChange:   true,
		},
		{
			name:                  "No update needed when not using cloud management",
			previousManagementURL: "https://netbird.example.com:33073",
			expectedManagementURL: "https://netbird.example.com:33073",
			fileShouldNotChange:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tempDir := t.TempDir()
			configPath := filepath.Join(tempDir, "config.json")
			config, err := UpdateOrCreateConfig(ConfigInput{
				ManagementURL: tt.previousManagementURL,
				ConfigPath:    configPath,
			})
			require.NoError(t, err, "failed to create testing config")
			previousStats, err := os.Stat(configPath)
			require.NoError(t, err, "failed to create testing config stats")
			resultConfig, err := UpdateOldManagementURL(context.TODO(), config, configPath)
			require.NoError(t, err, "got error when updating old management url")
			require.Equal(t, tt.expectedManagementURL, resultConfig.ManagementURL.String())
			newStats, err := os.Stat(configPath)
			require.NoError(t, err, "failed to create testing config stats")
			switch tt.fileShouldNotChange {
			case true:
				require.Equal(t, previousStats.ModTime(), newStats.ModTime(), "file should not change")
			case false:
				require.NotEqual(t, previousStats.ModTime(), newStats.ModTime(), "file should have changed")
			}
		})
	}
}
