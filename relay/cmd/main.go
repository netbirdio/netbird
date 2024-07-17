package main

import (
	"crypto/tls"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/netbirdio/netbird/encryption"
	auth "github.com/netbirdio/netbird/relay/auth/hmac"
	"github.com/netbirdio/netbird/relay/server"
	"github.com/netbirdio/netbird/util"
)

type Config struct {
	ListenAddress string
	// in HA every peer connect to a common domain, the instance domain has been distributed during the p2p connection
	// it is a domain:port or ip:port
	ExposedAddress     string
	LetsencryptDataDir string
	LetsencryptDomains []string
	TlsCertFile        string
	TlsKeyFile         string
	AuthSecret         string
}

func (c Config) Validate() error {
	if c.ExposedAddress == "" {
		return fmt.Errorf("exposed address is required")
	}
	if c.AuthSecret == "" {
		return fmt.Errorf("auth secret is required")
	}
	return nil
}

func (c Config) HasCertConfig() bool {
	return c.TlsCertFile != "" && c.TlsKeyFile != ""
}

func (c Config) HasLetsEncrypt() bool {
	return c.LetsencryptDataDir != "" && c.LetsencryptDomains != nil && len(c.LetsencryptDomains) > 0
}

var (
	cobraConfig *Config
	cfgFile     string
	rootCmd     = &cobra.Command{
		Use:   "relay",
		Short: "Relay service",
		Long:  "Relay service for Netbird agents",
		Run:   execute,
	}
)

func init() {
	_ = util.InitLog("trace", "console")
	cobraConfig = &Config{}
	rootCmd.PersistentFlags().StringVarP(&cfgFile, "config-file", "f", "/etc/netbird/relay.json", "Relay server config file location")
	rootCmd.PersistentFlags().StringVarP(&cobraConfig.ListenAddress, "listen-address", "l", ":443", "listen address")
	rootCmd.PersistentFlags().StringVarP(&cobraConfig.ExposedAddress, "exposed-address", "e", "", "instance domain address (or ip) and port, it will be distributes between peers")
	rootCmd.PersistentFlags().StringVarP(&cobraConfig.LetsencryptDataDir, "letsencrypt-data-dir", "d", "", "a directory to store Let's Encrypt data. Required if Let's Encrypt is enabled.")
	rootCmd.PersistentFlags().StringArrayVarP(&cobraConfig.LetsencryptDomains, "letsencrypt-domains", "a", nil, "list of domains to issue Let's Encrypt certificate for. Enables TLS using Let's Encrypt. Will fetch and renew certificate, and run the server with TLS")
	rootCmd.PersistentFlags().StringVarP(&cobraConfig.TlsCertFile, "tls-cert-file", "c", "", "")
	rootCmd.PersistentFlags().StringVarP(&cobraConfig.TlsKeyFile, "tls-key-file", "k", "", "")
	rootCmd.PersistentFlags().StringVarP(&cobraConfig.AuthSecret, "auth-secret", "s", "", "log level")
}

func waitForExitSignal() {
	osSigs := make(chan os.Signal, 1)
	signal.Notify(osSigs, syscall.SIGINT, syscall.SIGTERM)
	<-osSigs
}

func loadConfig(configFile string) (*Config, error) {
	log.Infof("loading config from: %s", configFile)
	loadedConfig := &Config{}
	_, err := util.ReadJson(configFile, loadedConfig)
	if err != nil {
		return nil, err
	}
	if cobraConfig.ListenAddress != "" {
		loadedConfig.ListenAddress = cobraConfig.ListenAddress
	}

	if cobraConfig.ExposedAddress != "" {
		loadedConfig.ExposedAddress = cobraConfig.ExposedAddress
	}
	if cobraConfig.LetsencryptDataDir != "" {
		loadedConfig.LetsencryptDataDir = cobraConfig.LetsencryptDataDir
	}
	if len(cobraConfig.LetsencryptDomains) > 0 {
		loadedConfig.LetsencryptDomains = cobraConfig.LetsencryptDomains
	}
	if cobraConfig.TlsCertFile != "" {
		loadedConfig.TlsCertFile = cobraConfig.TlsCertFile
	}
	if cobraConfig.TlsKeyFile != "" {
		loadedConfig.TlsKeyFile = cobraConfig.TlsKeyFile
	}
	if cobraConfig.AuthSecret != "" {
		loadedConfig.AuthSecret = cobraConfig.AuthSecret
	}

	return loadedConfig, err
}

func execute(cmd *cobra.Command, args []string) {
	cfg, err := loadConfig(cfgFile)
	if err != nil {
		log.Errorf("failed to load config: %s", err)
		os.Exit(1)
	}

	err = cfg.Validate()
	if err != nil {
		log.Errorf("invalid config: %s", err)
		os.Exit(1)
	}

	srvListenerCfg := server.ListenerConfig{
		Address: cfg.ListenAddress,
	}
	if cfg.HasLetsEncrypt() {
		tlsCfg, err := setupTLSCertManager(cfg.LetsencryptDataDir, cfg.LetsencryptDomains...)
		if err != nil {
			log.Errorf("%s", err)
			os.Exit(1)
		}
		srvListenerCfg.TLSConfig = tlsCfg
	} else if cfg.HasCertConfig() {
		tlsCfg, err := encryption.LoadTLSConfig(cfg.TlsCertFile, cfg.TlsKeyFile)
		if err != nil {
			log.Errorf("%s", err)
			os.Exit(1)
		}
		srvListenerCfg.TLSConfig = tlsCfg
	}

	tlsSupport := srvListenerCfg.TLSConfig != nil

	authenticator := auth.NewTimedHMACValidator(cfg.AuthSecret, 24*time.Hour)
	srv := server.NewServer(cfg.ExposedAddress, tlsSupport, authenticator)
	log.Infof("server will be available on: %s", srv.InstanceURL())
	err = srv.Listen(srvListenerCfg)
	if err != nil {
		log.Errorf("failed to bind server: %s", err)
		os.Exit(1)
	}

	waitForExitSignal()

	err = srv.Close()
	if err != nil {
		log.Errorf("failed to close server: %s", err)
		os.Exit(1)
	}
}

func setupTLSCertManager(letsencryptDataDir string, letsencryptDomains ...string) (*tls.Config, error) {
	certManager, err := encryption.CreateCertManager(letsencryptDataDir, letsencryptDomains...)
	if err != nil {
		return nil, fmt.Errorf("failed creating LetsEncrypt cert manager: %v", err)
	}
	return certManager.TLSConfig(), nil
}

func main() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}
