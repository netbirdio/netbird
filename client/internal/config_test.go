package internal

import (
	"errors"
	"github.com/stretchr/testify/assert"
	"github.com/wiretrustee/wiretrustee/util"
	"os"
	"path/filepath"
	"testing"
)

func TestReadConfig(t *testing.T) {

}
func TestGetConfig(t *testing.T) {

	managementURL := "https://test.management.url:33071"
	path := filepath.Join(t.TempDir(), "config.json")
	preSharedKey := "preSharedKey"

	// case 1: new config has to be generated
	config, err := GetConfig(managementURL, path, preSharedKey)
	if err != nil {
		return
	}

	assert.Equal(t, config.ManagementURL.String(), managementURL)
	assert.Equal(t, config.PreSharedKey, preSharedKey)

	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		t.Errorf("config file was expected to be created under path %s", path)
	}

	// case 2: existing config -> fetch it
	config, err = GetConfig(managementURL, path, preSharedKey)
	if err != nil {
		return
	}

	assert.Equal(t, config.ManagementURL.String(), managementURL)
	assert.Equal(t, config.PreSharedKey, preSharedKey)

	// case 3: existing config, but new managementURL has been provided -> update config
	newManagementURL := "https://test.newManagement.url:33071"
	config, err = GetConfig(newManagementURL, path, preSharedKey)
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
