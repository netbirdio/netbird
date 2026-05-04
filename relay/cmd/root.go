package cmd

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/hashicorp/go-multierror"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/netbirdio/netbird/encryption"
	"github.com/netbirdio/netbird/relay/healthcheck"
	"github.com/netbirdio/netbird/relay/server"
	"github.com/netbirdio/netbird/shared/metrics"
	"github.com/netbirdio/netbird/shared/relay/auth"
	"github.com/netbirdio/netbird/stun"
	"github.com/netbirdio/netbird/util"
)

type Config struct {
	ListenAddress string
	// in HA every peer connect to a common domain, the instance domain has been distributed during the p2p connection
	// it is a domain:port or ip:port
	ExposedAddress     string
	MetricsPort        int
	LetsencryptEmail   string
	LetsencryptDataDir string
	LetsencryptDomains []string
	// in case of using Route 53 for DNS challenge the credentials should be provided in the environment variables or
	// in the AWS credentials file
	LetsencryptAWSRoute53    bool
	TlsCertFile              string
	TlsKeyFile               string
	AuthSecret               string
	LogLevel                 string
	LogFile                  string
	HealthcheckListenAddress string
	// STUN server configuration
	EnableSTUN   bool
	STUNPorts    []int
	STUNLogLevel string
}

func (c Config) Validate() error {
	if c.ExposedAddress == "" {
		return fmt.Errorf("exposed address is required")
	}
	if c.AuthSecret == "" {
		return fmt.Errorf("auth secret is required")
	}

	// Validate STUN configuration
	if c.EnableSTUN {
		if len(c.STUNPorts) == 0 {
			return fmt.Errorf("--stun-ports is required when --enable-stun is set")
		}

		seen := make(map[int]bool)
		for _, port := range c.STUNPorts {
			if port <= 0 || port > 65535 {
				return fmt.Errorf("invalid STUN port %d: must be between 1 and 65535", port)
			}
			if seen[port] {
				return fmt.Errorf("duplicate STUN port %d", port)
			}
			seen[port] = true
		}
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
	rootCmd     = &cobra.Command{
		Use:           "relay",
		Short:         "Relay service",
		Long:          "Relay service for Netbird agents",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE:          execute,
	}
)

func init() {
	_ = util.InitLog("trace", util.LogConsole)
	cobraConfig = &Config{}
	rootCmd.PersistentFlags().StringVarP(&cobraConfig.ListenAddress, "listen-address", "l", ":443", "listen address")
	rootCmd.PersistentFlags().StringVarP(&cobraConfig.ExposedAddress, "exposed-address", "e", "", "instance domain address (or ip) and port, it will be distributes between peers")
	rootCmd.PersistentFlags().IntVar(&cobraConfig.MetricsPort, "metrics-port", 9090, "metrics endpoint http port. Metrics are accessible under host:metrics-port/metrics")
	rootCmd.PersistentFlags().StringVarP(&cobraConfig.LetsencryptDataDir, "letsencrypt-data-dir", "d", "", "a directory to store Let's Encrypt data. Required if Let's Encrypt is enabled.")
	rootCmd.PersistentFlags().StringSliceVarP(&cobraConfig.LetsencryptDomains, "letsencrypt-domains", "a", nil, "list of domains to issue Let's Encrypt certificate for. Enables TLS using Let's Encrypt. Will fetch and renew certificate, and run the server with TLS")
	rootCmd.PersistentFlags().StringVar(&cobraConfig.LetsencryptEmail, "letsencrypt-email", "", "email address to use for Let's Encrypt certificate registration")
	rootCmd.PersistentFlags().BoolVar(&cobraConfig.LetsencryptAWSRoute53, "letsencrypt-aws-route53", false, "use AWS Route 53 for Let's Encrypt DNS challenge")
	rootCmd.PersistentFlags().StringVarP(&cobraConfig.TlsCertFile, "tls-cert-file", "c", "", "")
	rootCmd.PersistentFlags().StringVarP(&cobraConfig.TlsKeyFile, "tls-key-file", "k", "", "")
	rootCmd.PersistentFlags().StringVarP(&cobraConfig.AuthSecret, "auth-secret", "s", "", "auth secret")
	rootCmd.PersistentFlags().StringVar(&cobraConfig.LogLevel, "log-level", "info", "log level")
	rootCmd.PersistentFlags().StringVar(&cobraConfig.LogFile, "log-file", "console", "log file")
	rootCmd.PersistentFlags().StringVarP(&cobraConfig.HealthcheckListenAddress, "health-listen-address", "H", ":9000", "listen address of healthcheck server")
	rootCmd.PersistentFlags().BoolVar(&cobraConfig.EnableSTUN, "enable-stun", false, "enable embedded STUN server")
	rootCmd.PersistentFlags().IntSliceVar(&cobraConfig.STUNPorts, "stun-ports", []int{3478}, "ports for the embedded STUN server (can be specified multiple times or comma-separated)")
	rootCmd.PersistentFlags().StringVar(&cobraConfig.STUNLogLevel, "stun-log-level", "info", "log level for STUN server (panic, fatal, error, warn, info, debug, trace)")

	setFlagsFromEnvVars(rootCmd)
}

func Execute() error {
	return rootCmd.Execute()
}

func waitForExitSignal() {
	osSigs := make(chan os.Signal, 1)
	signal.Notify(osSigs, syscall.SIGINT, syscall.SIGTERM)
	<-osSigs
}

func execute(cmd *cobra.Command, args []string) error {
	wg := sync.WaitGroup{}
	err := cobraConfig.Validate()
	if err != nil {
		log.Debugf("invalid config: %s", err)
		return fmt.Errorf("invalid config: %s", err)
	}

	err = util.InitLog(cobraConfig.LogLevel, cobraConfig.LogFile)
	if err != nil {
		log.Debugf("failed to initialize log: %s", err)
		return fmt.Errorf("failed to initialize log: %s", err)
	}

	// Resource creation phase (fail fast before starting any goroutines)

	metricsServer, err := metrics.NewServer(cobraConfig.MetricsPort, "")
	if err != nil {
		log.Debugf("setup metrics: %v", err)
		return fmt.Errorf("setup metrics: %v", err)
	}

	srvListenerCfg := server.ListenerConfig{
		Address: cobraConfig.ListenAddress,
	}

	tlsConfig, tlsSupport, err := handleTLSConfig(cobraConfig)
	if err != nil {
		log.Debugf("failed to setup TLS config: %s", err)
		return fmt.Errorf("failed to setup TLS config: %s", err)
	}
	srvListenerCfg.TLSConfig = tlsConfig

	// Create STUN listeners early to fail fast
	stunListeners, err := createSTUNListeners()
	if err != nil {
		return err
	}

	hashedSecret := sha256.Sum256([]byte(cobraConfig.AuthSecret))
	authenticator := auth.NewTimedHMACValidator(hashedSecret[:], 24*time.Hour)

	cfg := server.Config{
		Meter:          metricsServer.Meter,
		ExposedAddress: cobraConfig.ExposedAddress,
		AuthValidator:  authenticator,
		TLSSupport:     tlsSupport,
	}

	srv, err := createRelayServer(cfg)
	if err != nil {
		cleanupSTUNListeners(stunListeners)
		return err
	}

	hCfg := healthcheck.Config{
		ListenAddress:  cobraConfig.HealthcheckListenAddress,
		ServiceChecker: srv,
	}
	httpHealthcheck, err := createHealthCheck(hCfg)
	if err != nil {
		cleanupSTUNListeners(stunListeners)
		return err
	}

	var stunServer *stun.Server
	if len(stunListeners) > 0 {
		stunServer = stun.NewServer(stunListeners, cobraConfig.STUNLogLevel)
	}

	// Start all servers (only after all resources are successfully created)
	startServers(&wg, metricsServer, srv, srvListenerCfg, httpHealthcheck, stunServer)

	waitForExitSignal()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	err = shutdownServers(ctx, metricsServer, srv, httpHealthcheck, stunServer)
	wg.Wait()
	return err
}

func startServers(wg *sync.WaitGroup, metricsServer *metrics.Metrics, srv *server.Server, srvListenerCfg server.ListenerConfig, httpHealthcheck *healthcheck.Server, stunServer *stun.Server) {
	wg.Add(1)
	go func() {
		defer wg.Done()
		log.Infof("running metrics server: %s%s", metricsServer.Addr, metricsServer.Endpoint)
		if err := metricsServer.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("failed to start metrics server: %v", err)
		}
	}()

	instanceURL := srv.InstanceURL()
	log.Infof("server will be available on: %s", instanceURL.String())
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := srv.Listen(srvListenerCfg); err != nil {
			log.Fatalf("failed to bind relay server: %s", err)
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := httpHealthcheck.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("failed to start healthcheck server: %v", err)
		}
	}()

	if stunServer != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := stunServer.Listen(); err != nil {
				if errors.Is(err, stun.ErrServerClosed) {
					return
				}
				log.Errorf("STUN server error: %v", err)
			}
		}()
	}
}

func shutdownServers(ctx context.Context, metricsServer *metrics.Metrics, srv *server.Server, httpHealthcheck *healthcheck.Server, stunServer *stun.Server) error {
	var errs error

	if err := httpHealthcheck.Shutdown(ctx); err != nil {
		errs = multierror.Append(errs, fmt.Errorf("failed to close healthcheck server: %w", err))
	}

	if stunServer != nil {
		if err := stunServer.Shutdown(); err != nil {
			errs = multierror.Append(errs, fmt.Errorf("failed to close STUN server: %w", err))
		}
	}

	if err := srv.Shutdown(ctx); err != nil {
		errs = multierror.Append(errs, fmt.Errorf("failed to close relay server: %w", err))
	}

	log.Infof("shutting down metrics server")
	if err := metricsServer.Shutdown(ctx); err != nil {
		errs = multierror.Append(errs, fmt.Errorf("failed to close metrics server: %w", err))
	}

	return errs
}

func createHealthCheck(hCfg healthcheck.Config) (*healthcheck.Server, error) {
	httpHealthcheck, err := healthcheck.NewServer(hCfg)
	if err != nil {
		log.Debugf("failed to create healthcheck server: %v", err)
		return nil, fmt.Errorf("failed to create healthcheck server: %v", err)
	}
	return httpHealthcheck, nil
}

func createRelayServer(cfg server.Config) (*server.Server, error) {
	srv, err := server.NewServer(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create relay server: %v", err)
	}
	return srv, nil
}

func cleanupSTUNListeners(stunListeners []*net.UDPConn) {
	for _, l := range stunListeners {
		_ = l.Close()
	}
}

func createSTUNListeners() ([]*net.UDPConn, error) {
	var stunListeners []*net.UDPConn
	if cobraConfig.EnableSTUN {
		for _, port := range cobraConfig.STUNPorts {
			listener, err := net.ListenUDP("udp", &net.UDPAddr{Port: port})
			if err != nil {
				// Close already opened listeners on failure
				cleanupSTUNListeners(stunListeners)
				log.Debugf("failed to create STUN listener on port %d: %v", port, err)
				return nil, fmt.Errorf("failed to create STUN listener on port %d: %v", port, err)
			}
			stunListeners = append(stunListeners, listener)
		}
	}
	return stunListeners, nil
}

func handleTLSConfig(cfg *Config) (*tls.Config, bool, error) {
	if cfg.LetsencryptAWSRoute53 {
		log.Debugf("using Let's Encrypt DNS resolver with Route 53 support")
		r53 := encryption.Route53TLS{
			DataDir: cfg.LetsencryptDataDir,
			Email:   cfg.LetsencryptEmail,
			Domains: cfg.LetsencryptDomains,
		}
		tlsCfg, err := r53.GetCertificate()
		if err != nil {
			return nil, false, fmt.Errorf("%s", err)
		}
		return tlsCfg, true, nil
	}

	if cfg.HasLetsEncrypt() {
		log.Infof("setting up TLS with Let's Encrypt.")
		tlsCfg, err := setupTLSCertManager(cfg.LetsencryptDataDir, cfg.LetsencryptDomains...)
		if err != nil {
			return nil, false, fmt.Errorf("%s", err)
		}
		return tlsCfg, true, nil
	}

	if cfg.HasCertConfig() {
		log.Debugf("using file based TLS config")
		tlsCfg, err := encryption.LoadTLSConfig(cfg.TlsCertFile, cfg.TlsKeyFile)
		if err != nil {
			return nil, false, fmt.Errorf("%s", err)
		}
		return tlsCfg, true, nil
	}
	return nil, false, nil
}

func setupTLSCertManager(letsencryptDataDir string, letsencryptDomains ...string) (*tls.Config, error) {
	certManager, err := encryption.CreateCertManager(letsencryptDataDir, letsencryptDomains...)
	if err != nil {
		return nil, fmt.Errorf("failed creating LetsEncrypt cert manager: %v", err)
	}
	return certManager.TLSConfig(), nil
}
