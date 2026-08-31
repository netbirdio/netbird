package cmd

import (
	"os"
	"runtime"

	"github.com/spf13/cobra"

	configloader "github.com/netbirdio/netbird/util/config"
)

// Config contains Signal service startup configuration.
type Config struct {
	Port               int    `yaml:"port" env:"NB_PORT" flag:"port"`
	MetricsPort        int    `yaml:"metricsPort" env:"NB_METRICS_PORT" flag:"metrics-port"`
	LetsencryptDomain  string `yaml:"letsencryptDomain" env:"NB_LETSENCRYPT_DOMAIN" flag:"letsencrypt-domain"`
	LetsencryptEmail   string `yaml:"letsencryptEmail" env:"NB_LETSENCRYPT_EMAIL" flag:"letsencrypt-email"`
	LetsencryptDataDir string `yaml:"letsencryptDataDir" env:"NB_LETSENCRYPT_DATA_DIR,NB_SSL_DIR" flag:"letsencrypt-data-dir,ssl-dir"`
	CertFile           string `yaml:"certFile" env:"NB_CERT_FILE" flag:"cert-file"`
	CertKey            string `yaml:"certKey" env:"NB_CERT_KEY" flag:"cert-key"`
	LogLevel           string `yaml:"logLevel" env:"NB_LOG_LEVEL" flag:"log-level"`
	LogFile            string `yaml:"logFile" env:"NB_LOG_FILE" flag:"log-file"`
	PprofAddress       string `yaml:"pprofAddress" env:"NB_PPROF_ADDR"`
}

func defaultConfig() *Config {
	logFile := "/var/log/netbird/signal.log"
	if runtime.GOOS == "windows" {
		logFile = os.Getenv("PROGRAMDATA") + "\\Netbird\\signal.log"
	}
	return &Config{
		MetricsPort: 9090,
		LogLevel:    "info",
		LogFile:     logFile,
	}
}

func loadConfig(cmd *cobra.Command, configPath string) (*Config, error) {
	return configloader.Load(configPath, defaultConfig(), configloader.Options{
		TagName:      "yaml",
		AllowMissing: configPath == "",
		FlagSet:      cmd.Flags(),
		Strict:       true,
	})
}
