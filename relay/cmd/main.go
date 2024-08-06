package main

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/netbirdio/netbird/encryption"
	auth "github.com/netbirdio/netbird/relay/auth/hmac"
	"github.com/netbirdio/netbird/relay/server"
	"github.com/netbirdio/netbird/signal/metrics"
	"github.com/netbirdio/netbird/util"
)

const (
	metricsPort    = 9090
	defaultLogPath = "console"
)

type Config struct {
	ListenAddress string
	// in HA every peer connect to a common domain, the instance domain has been distributed during the p2p connection
	// it is a domain:port or ip:port
	ExposedAddress                string
	LetsencryptEmail              string
	LetsencryptDataDir            string
	LetsencryptDomains            []string
	LetsencryptAWSAccessKeyID     string
	LetsencryptAWSSecretAccessKey string
	TlsCertFile                   string
	TlsKeyFile                    string
	AuthSecret                    string
	LogLevel                      string
	LogFile                       string
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

func (c Config) HasRoute54Credentials() bool {
	if c.LetsencryptDataDir == "" {
		return false
	}

	if c.LetsencryptEmail == "" {
		return false
	}

	if c.LetsencryptDomains == nil || len(c.LetsencryptDomains) == 0 {
		return false
	}

	return true
}

var (
	cobraConfig *Config
	cfgFile     string
	rootCmd     = &cobra.Command{
		Use:   "relay",
		Short: "Relay service",
		Long:  "Relay service for Netbird agents",
		RunE:  execute,
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
	rootCmd.PersistentFlags().StringVar(&cobraConfig.LetsencryptEmail, "letsencrypt-email", "", "email address to use for Let's Encrypt certificate registration")
	rootCmd.PersistentFlags().StringVar(&cobraConfig.LetsencryptAWSAccessKeyID, "letsencrypt-aws-accesskeyid", "", "AWS Access Key ID for Route 53 DNS provider")
	rootCmd.PersistentFlags().StringVar(&cobraConfig.LetsencryptAWSSecretAccessKey, "letsencypt-aws-secretaccesskey", "", "AWS Secret Access Key for Route 53 DNS provider")
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
	if cobraConfig.LetsencryptEmail != "" {
		loadedConfig.LetsencryptEmail = cobraConfig.LetsencryptEmail
	}
	if cobraConfig.LetsencryptAWSAccessKeyID != "" {
		loadedConfig.LetsencryptAWSAccessKeyID = cobraConfig.LetsencryptAWSAccessKeyID
	}
	if cobraConfig.LetsencryptAWSSecretAccessKey != "" {
		loadedConfig.LetsencryptAWSSecretAccessKey = cobraConfig.LetsencryptAWSSecretAccessKey
	}

	if loadedConfig.LogFile == "" {
		loadedConfig.LogFile = defaultLogPath
	}

	return loadedConfig, err
}

func execute(cmd *cobra.Command, args []string) error {
	cfg, err := loadConfig(cfgFile)
	if err != nil {
		return fmt.Errorf("failed to load config: %s", err)
	}

	err = cfg.Validate()
	if err != nil {
		return fmt.Errorf("invalid config: %s", err)
	}

	err = util.InitLog(cfg.LogLevel, cfg.LogFile)
	if err != nil {
		return fmt.Errorf("failed to initialize log: %s", err)
	}

	metricsServer, err := metrics.NewServer(metricsPort, "")
	if err != nil {
		return fmt.Errorf("setup metrics: %v", err)
	}

	go func() {
		log.Infof("running metrics server: %s%s", metricsServer.Addr, metricsServer.Endpoint)
		if err := metricsServer.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("Failed to start metrics server: %v", err)
		}
	}()

	srvListenerCfg := server.ListenerConfig{
		Address: cfg.ListenAddress,
	}
	if cfg.HasRoute54Credentials() {
		log.Debugf("using Let's Encrypt DNS resolver with Route 53 support")
		r53 := encryption.Route53TLS{
			DataDir:            cfg.LetsencryptDataDir,
			Email:              cfg.LetsencryptEmail,
			AwsAccessKeyID:     cfg.LetsencryptAWSAccessKeyID,
			AwsSecretAccessKey: cfg.LetsencryptAWSSecretAccessKey,
			Domains:            cfg.LetsencryptDomains,
		}
		tlsCfg, err := r53.GetCertificate()
		if err != nil {
			return fmt.Errorf("%s", err)
		}
		srvListenerCfg.TLSConfig = tlsCfg
	} else if cfg.HasLetsEncrypt() {
		log.Infof("setting up TLS with Let's Encrypt.")
		tlsCfg, err := setupTLSCertManager(cfg.LetsencryptDataDir, cfg.LetsencryptDomains...)
		if err != nil {
			return fmt.Errorf("%s", err)
		}
		srvListenerCfg.TLSConfig = tlsCfg
	} else if cfg.HasCertConfig() {
		log.Debugf("using file based TLS config")
		tlsCfg, err := encryption.LoadTLSConfig(cfg.TlsCertFile, cfg.TlsKeyFile)
		if err != nil {
			return fmt.Errorf("%s", err)
		}
		srvListenerCfg.TLSConfig = tlsCfg
	}

	tlsSupport := srvListenerCfg.TLSConfig != nil

	authenticator := auth.NewTimedHMACValidator(cfg.AuthSecret, 24*time.Hour)
	srv, err := server.NewServer(metricsServer.Meter, cfg.ExposedAddress, tlsSupport, authenticator)
	if err != nil {
		return fmt.Errorf("failed to create relay server: %v", err)
	}
	log.Infof("server will be available on: %s", srv.InstanceURL())
	err = srv.Listen(srvListenerCfg)
	if err != nil {
		return fmt.Errorf("failed to bind server: %s", err)
	}

	waitForExitSignal()

	err = srv.Close()
	if err != nil {
		return fmt.Errorf("failed to close server: %s", err)
	}
	return nil
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
