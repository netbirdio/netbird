package cmd

import (
	nbconfig "github.com/netbirdio/netbird/management/internals/server/config"
	configloader "github.com/netbirdio/netbird/util/config"
)

func loadManagementConfig(configPath string) (*nbconfig.Config, error) {
	return configloader.Load(configPath, &nbconfig.Config{Datadir: defaultMgmtDataDir}, configloader.Options{
		TagName:   "json",
		Transform: configloader.ExpandEnvTemplate,
	})
}
