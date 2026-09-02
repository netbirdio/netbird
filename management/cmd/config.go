package cmd

import (
	nbconfig "github.com/netbirdio/netbird/management/internals/server/config"
	configloader "github.com/netbirdio/netbird/util/config"
	"github.com/netbirdio/netbird/util/envtemplate"
)

func loadManagementConfig(configPath string) (*nbconfig.Config, error) {
	cfg, err := decodeManagementConfig(configPath, &nbconfig.Config{Datadir: defaultMgmtDataDir})
	if err != nil {
		return nil, err
	}
	if cfg.Datadir == "" {
		cfg.Datadir = defaultMgmtDataDir
	}
	return cfg, nil
}

func decodeManagementConfig(configPath string, defaults *nbconfig.Config) (*nbconfig.Config, error) {
	return configloader.Load(configPath, defaults, configloader.Options{
		TagName:   "json",
		Transform: envtemplate.Expand,
	})
}
