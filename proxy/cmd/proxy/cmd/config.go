package cmd

import (
	"fmt"
	"os"
	"strconv"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/acme"

	"github.com/netbirdio/netbird/proxy"
	"github.com/netbirdio/netbird/trustedproxy"
	configloader "github.com/netbirdio/netbird/util/config"
)

type commandConfig struct {
	proxy.Config `yaml:",inline"`

	LogLevel            string  `yaml:"logLevel" env:"NB_PROXY_LOG_LEVEL" flag:"log-level"`
	PreallocatedBuffers *uint32 `yaml:"preallocatedBuffers" env:"-"`
	MaxBatchSize        *uint32 `yaml:"maxBatchSize" env:"-"`
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
			DebugEndpointAddress: "localhost:8444",
			HealthAddr:           "localhost:8080",
			TrustedProxies:       trustedproxy.FromPrefixes(nil),
			ForwardedProto:       "auto",
			SupportsCustomPorts:  true,
			GeoDataDir:           "/var/lib/netbird/geolocation",
		},
		LogLevel: "info",
	}
}

func loadConfig(cmd *cobra.Command, configPath string) (*commandConfig, error) {
	cfg, err := configloader.Load(configPath, defaultConfig(), configloader.Options{
		TagName:            "yaml",
		AllowMissing:       configPath == "",
		FlagSet:            cmd.Flags(),
		Strict:             true,
		InvalidEnvironment: configloader.InvalidEnvironmentIgnore,
	})
	if err != nil {
		return nil, err
	}
	if err := applyPerformanceEnvironment(cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

func applyPerformanceEnvironment(cfg *commandConfig) error {
	for _, setting := range []struct {
		name   string
		target **uint32
	}{
		{name: envPreallocatedBuffers, target: &cfg.PreallocatedBuffers},
		{name: envMaxBatchSize, target: &cfg.MaxBatchSize},
	} {
		raw := os.Getenv(setting.name)
		if raw == "" {
			continue
		}
		parsed, err := strconv.ParseUint(raw, 10, 32)
		if err != nil {
			return fmt.Errorf("invalid %s %q: %w", setting.name, raw, err)
		}
		value := uint32(parsed)
		*setting.target = &value
	}
	return nil
}
