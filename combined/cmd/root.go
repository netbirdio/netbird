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
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/coder/websocket"
	"github.com/hashicorp/go-multierror"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"go.opentelemetry.io/otel/metric"
	"google.golang.org/grpc"

	"github.com/netbirdio/netbird/encryption"
	mgmtServer "github.com/netbirdio/netbird/management/internals/server"
	nbconfig "github.com/netbirdio/netbird/management/internals/server/config"
	"github.com/netbirdio/netbird/relay/healthcheck"
	relayServer "github.com/netbirdio/netbird/relay/server"
	"github.com/netbirdio/netbird/relay/server/listener/ws"
	"github.com/netbirdio/netbird/shared/relay/auth"
	"github.com/netbirdio/netbird/shared/signal/proto"
	"github.com/netbirdio/netbird/signal/metrics"
	signalServer "github.com/netbirdio/netbird/signal/server"
	"github.com/netbirdio/netbird/stun"
	"github.com/netbirdio/netbird/util"
	"github.com/netbirdio/netbird/util/wsproxy"
	wsproxyserver "github.com/netbirdio/netbird/util/wsproxy/server"
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
	// Signal server configuration (always enabled)
	SignalPort int
	// Management server configuration (always enabled, shares port with Signal)
	MgmtDataDir              string
	MgmtConfig               string
	MgmtDnsDomain            string
	MgmtSingleAccModeDomain  string
	DisableSingleAccMode     bool
	DisableMetrics           bool
	DisableGeoliteUpdate     bool
	IdpSignKeyRefreshEnabled bool
	UserDeleteFromIDPEnabled bool
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
		Use:           "combined",
		Short:         "Combined Netbird server (Management + Signal + Relay + STUN)",
		Long:          "Combined Netbird server for self-hosted deployments. Management, Signal, and Relay WebSocket services are multiplexed on the same port (--signal-port). Optional STUN server runs on separate UDP ports. WebSocket is used by default for all gRPC connections.",
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
	rootCmd.PersistentFlags().IntVar(&cobraConfig.SignalPort, "signal-port", 10000, "Signal and Management server gRPC/HTTP port (multiplexed)")

	// Management server flags
	rootCmd.PersistentFlags().StringVar(&cobraConfig.MgmtDataDir, "mgmt-datadir", "/var/lib/netbird/", "Management service data directory")
	rootCmd.PersistentFlags().StringVar(&cobraConfig.MgmtConfig, "mgmt-config", "/etc/netbird/management.json", "Management service config file location")
	rootCmd.PersistentFlags().StringVar(&cobraConfig.MgmtDnsDomain, "mgmt-dns-domain", "", "DNS domain for the management server")
	rootCmd.PersistentFlags().StringVar(&cobraConfig.MgmtSingleAccModeDomain, "mgmt-single-account-mode-domain", "", "Single account mode domain")
	rootCmd.PersistentFlags().BoolVar(&cobraConfig.DisableSingleAccMode, "disable-single-account-mode", false, "Disable single account mode")
	rootCmd.PersistentFlags().BoolVar(&cobraConfig.DisableMetrics, "disable-anonymous-metrics", false, "Disable anonymous metrics")
	rootCmd.PersistentFlags().BoolVar(&cobraConfig.DisableGeoliteUpdate, "disable-geolite-update", false, "Disable GeoLite database updates")
	rootCmd.PersistentFlags().BoolVar(&cobraConfig.IdpSignKeyRefreshEnabled, "idp-sign-key-refresh-enabled", false, "Enable IDP sign key refresh")
	rootCmd.PersistentFlags().BoolVar(&cobraConfig.UserDeleteFromIDPEnabled, "user-delete-from-idp-enabled", false, "Enable user deletion from IDP")

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

	srvListenerCfg := relayServer.ListenerConfig{
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

	relayCfg := relayServer.Config{
		Meter:          metricsServer.Meter,
		ExposedAddress: cobraConfig.ExposedAddress,
		AuthValidator:  authenticator,
		TLSSupport:     tlsSupport,
	}

	srv, err := createRelayServer(relayCfg, stunListeners)
	if err != nil {
		return err
	}

	// Load management config and create management server
	mgmtConfig, err := loadManagementConfig()
	if err != nil {
		cleanupSTUNListeners(stunListeners)
		return fmt.Errorf("failed to load management config: %v", err)
	}

	mgmtSrv, err := createManagementServer(mgmtConfig)
	if err != nil {
		cleanupSTUNListeners(stunListeners)
		return fmt.Errorf("failed to create management server: %v", err)
	}

	// Create Signal server that will share the same gRPC server as Management
	signalSrv, err := signalServer.NewServer(cmd.Context(), metricsServer.Meter)
	if err != nil {
		cleanupSTUNListeners(stunListeners)
		return fmt.Errorf("failed to create signal server: %v", err)
	}

	// Register Signal service with management's gRPC server using AfterInit hook
	// This ensures both Management and Signal services are registered on the same gRPC server
	// Also add Relay WebSocket handler to the same port
	mgmtSrv.AfterInit(func(s *mgmtServer.BaseServer) {
		grpcSrv := s.GRPCServer()
		proto.RegisterSignalExchangeServer(grpcSrv, signalSrv)
		log.Infof("Signal server registered with Management gRPC server on port %d", cobraConfig.SignalPort)

		// Override the handler to also support Relay WebSocket on the same port
		s.SetHandlerFunc(createCombinedHandler(grpcSrv, s.HTTPHandler(), srv, metricsServer.Meter))
		log.Infof("Relay WebSocket handler added to port %d (path: /relay)", cobraConfig.SignalPort)
	})

	hCfg := healthcheck.Config{
		ListenAddress:  cobraConfig.HealthcheckListenAddress,
		ServiceChecker: srv,
	}
	httpHealthcheck, err := createHealthCheck(hCfg, stunListeners)
	if err != nil {
		return err
	}

	var stunServer *stun.Server
	if len(stunListeners) > 0 {
		stunServer = stun.NewServer(stunListeners, cobraConfig.STUNLogLevel)
	}

	// Start management server (this also starts the signal/management multiplexed server)
	err = mgmtSrv.Start(cmd.Context())
	if err != nil {
		cleanupSTUNListeners(stunListeners)
		return fmt.Errorf("failed to start management server: %v", err)
	}

	// Start all other servers (only after all resources are successfully created)
	startServers(&wg, metricsServer, srv, srvListenerCfg, httpHealthcheck, stunServer)

	waitForExitSignal()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	err = shutdownServers(ctx, metricsServer, srv, httpHealthcheck, stunServer, mgmtSrv)
	wg.Wait()
	return err
}

func startServers(wg *sync.WaitGroup, metricsServer *metrics.Metrics, srv *relayServer.Server, srvListenerCfg relayServer.ListenerConfig, httpHealthcheck *healthcheck.Server, stunServer *stun.Server) {
	wg.Add(1)
	go func() {
		defer wg.Done()
		log.Infof("running metrics server: %s%s", metricsServer.Addr, metricsServer.Endpoint)
		if err := metricsServer.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("failed to start metrics server: %v", err)
		}
	}()

	instanceURL := srv.InstanceURL()
	log.Infof("Relay server instance URL: %s", instanceURL.String())
	log.Infof("Relay WebSocket multiplexed on management port (no separate relay listener)")
	// Note: Relay WebSocket is now handled by the management server's multiplexed handler
	// No separate relay listener is started - all relay traffic goes through /relay on the management port

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

func shutdownServers(ctx context.Context, metricsServer *metrics.Metrics, srv *relayServer.Server, httpHealthcheck *healthcheck.Server, stunServer *stun.Server, mgmtSrv *mgmtServer.BaseServer) error {
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

	// Stop management server (also stops signal server as they share the same gRPC server)
	log.Infof("shutting down management and signal servers")
	if err := mgmtSrv.Stop(); err != nil {
		errs = multierror.Append(errs, fmt.Errorf("failed to close management server: %w", err))
	}

	log.Infof("shutting down metrics server")
	if err := metricsServer.Shutdown(ctx); err != nil {
		errs = multierror.Append(errs, fmt.Errorf("failed to close metrics server: %w", err))
	}

	return errs
}

func createHealthCheck(hCfg healthcheck.Config, stunListeners []*net.UDPConn) (*healthcheck.Server, error) {
	httpHealthcheck, err := healthcheck.NewServer(hCfg)
	if err != nil {
		cleanupSTUNListeners(stunListeners)
		log.Debugf("failed to create healthcheck server: %v", err)
		return nil, fmt.Errorf("failed to create healthcheck server: %v", err)
	}
	return httpHealthcheck, nil
}

func createRelayServer(cfg relayServer.Config, stunListeners []*net.UDPConn) (*relayServer.Server, error) {
	srv, err := relayServer.NewServer(cfg)
	if err != nil {
		cleanupSTUNListeners(stunListeners)
		log.Debugf("failed to create relay server: %v", err)
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

func loadManagementConfig() (*nbconfig.Config, error) {
	mgmtConfig := &nbconfig.Config{}
	if _, err := util.ReadJsonWithEnvSub(cobraConfig.MgmtConfig, mgmtConfig); err != nil {
		log.Infof("unable to read config file %s, using defaults: %v", cobraConfig.MgmtConfig, err)
		mgmtConfig = &nbconfig.Config{}
	}

	// Override config with CLI flags
	if cobraConfig.MgmtDataDir != "" {
		mgmtConfig.Datadir = cobraConfig.MgmtDataDir
	}

	// Apply default single account mode domain if not disabled
	singleAccModeDomain := cobraConfig.MgmtSingleAccModeDomain
	if !cobraConfig.DisableSingleAccMode && singleAccModeDomain == "" && cobraConfig.MgmtDnsDomain != "" {
		singleAccModeDomain = cobraConfig.MgmtDnsDomain
	}

	if singleAccModeDomain != "" {
		log.Infof("single account mode domain: %s", singleAccModeDomain)
	}

	return mgmtConfig, nil
}

func createManagementServer(config *nbconfig.Config) (*mgmtServer.BaseServer, error) {
	dnsDomain := cobraConfig.MgmtDnsDomain
	singleAccModeDomain := cobraConfig.MgmtSingleAccModeDomain
	if !cobraConfig.DisableSingleAccMode && singleAccModeDomain == "" && dnsDomain != "" {
		singleAccModeDomain = dnsDomain
	}

	mgmtPort := cobraConfig.SignalPort
	mgmtMetricsPort := cobraConfig.MetricsPort

	mgmtSrv := mgmtServer.NewServer(
		config,
		dnsDomain,
		singleAccModeDomain,
		mgmtPort,
		mgmtMetricsPort,
		cobraConfig.DisableMetrics,
		cobraConfig.DisableGeoliteUpdate,
		cobraConfig.UserDeleteFromIDPEnabled,
	)

	return mgmtSrv, nil
}

// createCombinedHandler creates an HTTP handler that multiplexes Management, Signal (via wsproxy), and Relay WebSocket traffic
func createCombinedHandler(grpcServer *grpc.Server, httpHandler http.Handler, relaySrv *relayServer.Server, meter metric.Meter) http.Handler {
	// Create WebSocket proxy for gRPC (handles both Management and Signal)
	wsProxy := wsproxyserver.New(grpcServer, wsproxyserver.WithOTelMeter(meter))

	// Get relay accept function
	relayAcceptFn := relaySrv.RelayAccept()

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		// Native gRPC traffic (HTTP/2 with gRPC content-type)
		case r.ProtoMajor == 2 && (strings.HasPrefix(r.Header.Get("Content-Type"), "application/grpc") ||
			strings.HasPrefix(r.Header.Get("Content-Type"), "application/grpc+proto")):
			grpcServer.ServeHTTP(w, r)

		// WebSocket proxy for Management gRPC
		case r.URL.Path == wsproxy.ProxyPath+wsproxy.ManagementComponent:
			wsProxy.Handler().ServeHTTP(w, r)

		// WebSocket proxy for Signal gRPC
		case r.URL.Path == wsproxy.ProxyPath+wsproxy.SignalComponent:
			wsProxy.Handler().ServeHTTP(w, r)

		// Relay WebSocket
		case r.URL.Path == "/relay":
			handleRelayWebSocket(w, r, relayAcceptFn)

		// Management HTTP API (default)
		default:
			httpHandler.ServeHTTP(w, r)
		}
	})
}

// handleRelayWebSocket handles incoming WebSocket connections for the relay service
func handleRelayWebSocket(w http.ResponseWriter, r *http.Request, acceptFn func(conn net.Conn)) {
	// Import the websocket library used by the relay
	acceptOptions := &websocket.AcceptOptions{
		OriginPatterns: []string{"*"},
	}

	wsConn, err := websocket.Accept(w, r, acceptOptions)
	if err != nil {
		log.Errorf("failed to accept relay ws connection: %s", err)
		return
	}

	// Get remote address
	connRemoteAddr := r.RemoteAddr
	if r.Header.Get("X-Real-Ip") != "" && r.Header.Get("X-Real-Port") != "" {
		connRemoteAddr = net.JoinHostPort(r.Header.Get("X-Real-Ip"), r.Header.Get("X-Real-Port"))
	}

	rAddr, err := net.ResolveTCPAddr("tcp", connRemoteAddr)
	if err != nil {
		_ = wsConn.Close(websocket.StatusInternalError, "internal error")
		return
	}

	// Use the signal port as the local address since relay is multiplexed on that port
	lAddr, err := net.ResolveTCPAddr("tcp", fmt.Sprintf(":%d", cobraConfig.SignalPort))
	if err != nil {
		_ = wsConn.Close(websocket.StatusInternalError, "internal error")
		return
	}

	log.Infof("Relay WS client connected from: %s", rAddr)

	// Convert WebSocket to net.Conn using the relay's ws.Conn wrapper
	conn := ws.NewConn(wsConn, lAddr, rAddr)
	acceptFn(conn)
}
