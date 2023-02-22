package internal

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/netbirdio/netbird/util"
	"github.com/stretchr/testify/assert"
)

func TestGetConfig(t *testing.T) {
	// case 1: new default config has to be generated
	config, err := GetConfig(ConfigInput{
		ConfigPath: filepath.Join(t.TempDir(), "config.json"),
	})

	if err != nil {
		return
	}

	assert.Equal(t, config.ManagementURL.String(), DefaultManagementURL)
	assert.Equal(t, config.AdminURL.String(), DefaultAdminURL)

	if err != nil {
		return
	}
	managementURL := "https://test.management.url:33071"
	adminURL := "https://app.admin.url:443"
	path := filepath.Join(t.TempDir(), "config.json")
	preSharedKey := "preSharedKey"

	// case 2: new config has to be generated
	config, err = GetConfig(ConfigInput{
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
	config, err = GetConfig(ConfigInput{
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
	config, err = GetConfig(ConfigInput{
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
	_, _ = GetConfig(ConfigInput{
		ConfigPath: cfgFile,
	})

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := GetConfig(ConfigInput{
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
