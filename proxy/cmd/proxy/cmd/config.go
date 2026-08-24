package cmd

import (
	"github.com/spf13/cobra"
	"golang.org/x/crypto/acme"

	"github.com/netbirdio/netbird/proxy"
	configloader "github.com/netbirdio/netbird/util/config"
)

type commandConfig struct {
	proxy.Config `yaml:",squash"`

	LogLevel            string  `yaml:"logLevel" env:"NB_PROXY_LOG_LEVEL" flag:"log-level"`
	PreallocatedBuffers *uint32 `yaml:"preallocatedBuffers" env:"NB_PROXY_PREALLOCATED_BUFFERS"`
	MaxBatchSize        *uint32 `yaml:"maxBatchSize" env:"NB_PROXY_MAX_BATCH_SIZE"`
}

func defaultConfig() *commandConfig {
	return &commandConfig{
		Config: proxy.Config{
			ListenAddr:           ":443",
			ManagementAddress:    DefaultManagementURL,
			CertificateDirectory: "./certs",
			CertificateFile:      "tls.crt",
			CertificateKeyFile:   "tls.key",
			ACMEChallengeAddress: ":80",
			ACMEDirectory:        acme.LetsEncryptURL,
			ACMEChallengeType:    "tls-alpn-01",
			CertLockMethod:       "auto",
			HealthAddr:           "localhost:8080",
			ForwardedProto:       "auto",
			SupportsCustomPorts:  true,
			GeoDataDir:           "/var/lib/netbird/geolocation",
		},
		LogLevel: "info",
	}
}

func loadConfig(cmd *cobra.Command, configPath string) (*commandConfig, error) {
	return configloader.Load(configPath, defaultConfig(), configloader.Options{
		TagName:      "yaml",
		AllowMissing: configPath == "",
		FlagSet:      cmd.Flags(),
		Strict:       true,
	})
}
