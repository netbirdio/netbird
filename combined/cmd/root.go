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
	"strconv"
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
	"github.com/netbirdio/netbird/management/server/telemetry"
	"github.com/netbirdio/netbird/relay/healthcheck"
	relayServer "github.com/netbirdio/netbird/relay/server"
	"github.com/netbirdio/netbird/relay/server/listener/ws"
	sharedMetrics "github.com/netbirdio/netbird/shared/metrics"
	"github.com/netbirdio/netbird/shared/relay/auth"
	"github.com/netbirdio/netbird/shared/signal/proto"
	signalServer "github.com/netbirdio/netbird/signal/server"
	"github.com/netbirdio/netbird/stun"
	"github.com/netbirdio/netbird/util"
	"github.com/netbirdio/netbird/util/wsproxy"
	wsproxyserver "github.com/netbirdio/netbird/util/wsproxy/server"
)

var (
	configPath string
	config     *CombinedConfig

	rootCmd = &cobra.Command{
		Use:   "combined",
		Short: "Combined Netbird server (Management + Signal + Relay + STUN)",
		Long: `Combined Netbird server for self-hosted deployments.

All services (Management, Signal, Relay) are multiplexed on a single port.
Optional STUN server runs on separate UDP ports.

Configuration is loaded from a YAML file specified with --config.`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE:          execute,
	}
)

func init() {
	rootCmd.PersistentFlags().StringVarP(&configPath, "config", "c", "", "path to YAML configuration file (required)")
	_ = rootCmd.MarkPersistentFlagRequired("config")

	rootCmd.AddCommand(newTokenCommands())
}

func Execute() error {
	return rootCmd.Execute()
}

func waitForExitSignal() {
	osSigs := make(chan os.Signal, 1)
	signal.Notify(osSigs, syscall.SIGINT, syscall.SIGTERM)
	<-osSigs
}

func execute(cmd *cobra.Command, _ []string) error {
	if err := initializeConfig(); err != nil {
		return err
	}

	// Management is required as the base server when signal or relay are enabled
	if (config.Signal.Enabled || config.Relay.Enabled) && !config.Management.Enabled {
		return fmt.Errorf("management must be enabled when signal or relay are enabled (provides the base HTTP server)")
	}

	servers, err := createAllServers(cmd.Context(), config)
	if err != nil {
		return err
	}

	// Register services with management's gRPC server using AfterInit hook
	setupServerHooks(servers, config)

	// Start management server (this also starts the HTTP listener)
	if servers.mgmtSrv != nil {
		if err := servers.mgmtSrv.Start(cmd.Context()); err != nil {
			cleanupSTUNListeners(servers.stunListeners)
			return fmt.Errorf("failed to start management server: %w", err)
		}
	}

	// Start all other servers
	wg := sync.WaitGroup{}
	startServers(&wg, servers.relaySrv, servers.healthcheck, servers.stunServer, servers.metricsServer)

	waitForExitSignal()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	err = shutdownServers(ctx, servers.relaySrv, servers.healthcheck, servers.stunServer, servers.mgmtSrv, servers.metricsServer)
	wg.Wait()
	return err
}

// initializeConfig loads and validates the configuration, then initializes logging.
func initializeConfig() error {
	var err error
	config, err = LoadConfig(configPath)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	if err := config.Validate(); err != nil {
		return fmt.Errorf("invalid config: %w", err)
	}

	if err := util.InitLog(config.Server.LogLevel, config.Server.LogFile); err != nil {
		return fmt.Errorf("failed to initialize log: %w", err)
	}

	if dsn := config.Server.Store.DSN; dsn != "" {
		switch strings.ToLower(config.Server.Store.Engine) {
		case "postgres":
			os.Setenv("NB_STORE_ENGINE_POSTGRES_DSN", dsn)
		case "mysql":
			os.Setenv("NB_STORE_ENGINE_MYSQL_DSN", dsn)
		}
	}

	log.Infof("Starting combined NetBird server")
	logConfig(config)
	logEnvVars()
	return nil
}

// serverInstances holds all server instances created during startup.
type serverInstances struct {
	relaySrv      *relayServer.Server
	mgmtSrv       *mgmtServer.BaseServer
	signalSrv     *signalServer.Server
	healthcheck   *healthcheck.Server
	stunServer    *stun.Server
	stunListeners []*net.UDPConn
	metricsServer *sharedMetrics.Metrics
}

// createAllServers creates all server instances based on configuration.
func createAllServers(ctx context.Context, cfg *CombinedConfig) (*serverInstances, error) {
	metricsServer, err := sharedMetrics.NewServer(cfg.Server.MetricsPort, "")
	if err != nil {
		return nil, fmt.Errorf("failed to create metrics server: %w", err)
	}
	servers := &serverInstances{
		metricsServer: metricsServer,
	}

	_, tlsSupport, err := handleTLSConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to setup TLS config: %w", err)
	}

	if err := servers.createRelayServer(cfg, tlsSupport); err != nil {
		return nil, err
	}

	if err := servers.createManagementServer(ctx, cfg); err != nil {
		return nil, err
	}

	if err := servers.createSignalServer(ctx, cfg); err != nil {
		return nil, err
	}

	if err := servers.createHealthcheckServer(cfg); err != nil {
		return nil, err
	}

	return servers, nil
}

func (s *serverInstances) createRelayServer(cfg *CombinedConfig, tlsSupport bool) error {
	if !cfg.Relay.Enabled {
		return nil
	}

	var err error
	s.stunListeners, err = createSTUNListeners(cfg)
	if err != nil {
		return err
	}

	hashedSecret := sha256.Sum256([]byte(cfg.Relay.AuthSecret))
	authenticator := auth.NewTimedHMACValidator(hashedSecret[:], 24*time.Hour)

	relayCfg := relayServer.Config{
		Meter:          s.metricsServer.Meter,
		ExposedAddress: cfg.Relay.ExposedAddress,
		AuthValidator:  authenticator,
		TLSSupport:     tlsSupport,
	}

	s.relaySrv, err = createRelayServer(relayCfg, s.stunListeners)
	if err != nil {
		return err
	}

	log.Infof("Relay server created")

	if len(s.stunListeners) > 0 {
		s.stunServer = stun.NewServer(s.stunListeners, cfg.Relay.Stun.LogLevel)
	}

	return nil
}

func (s *serverInstances) createManagementServer(ctx context.Context, cfg *CombinedConfig) error {
	if !cfg.Management.Enabled {
		return nil
	}

	mgmtConfig, err := cfg.ToManagementConfig()
	if err != nil {
		return fmt.Errorf("failed to create management config: %w", err)
	}

	_, portStr, portErr := net.SplitHostPort(cfg.Server.ListenAddress)
	if portErr != nil {
		portStr = "443"
	}
	mgmtPort, _ := strconv.Atoi(portStr)

	if err := ApplyEmbeddedIdPConfig(ctx, mgmtConfig, mgmtPort, false); err != nil {
		cleanupSTUNListeners(s.stunListeners)
		return fmt.Errorf("failed to apply embedded IdP config: %w", err)
	}

	if err := EnsureEncryptionKey(ctx, mgmtConfig); err != nil {
		cleanupSTUNListeners(s.stunListeners)
		return fmt.Errorf("failed to ensure encryption key: %w", err)
	}

	LogConfigInfo(mgmtConfig)

	s.mgmtSrv, err = createManagementServer(cfg, mgmtConfig)
	if err != nil {
		cleanupSTUNListeners(s.stunListeners)
		return fmt.Errorf("failed to create management server: %w", err)
	}

	// Inject externally-managed AppMetrics so management uses the shared metrics server
	appMetrics, err := telemetry.NewAppMetricsWithMeter(ctx, s.metricsServer.Meter)
	if err != nil {
		cleanupSTUNListeners(s.stunListeners)
		return fmt.Errorf("failed to create management app metrics: %w", err)
	}
	mgmtServer.Inject[telemetry.AppMetrics](s.mgmtSrv, appMetrics)

	log.Infof("Management server created")
	return nil
}

func (s *serverInstances) createSignalServer(ctx context.Context, cfg *CombinedConfig) error {
	if !cfg.Signal.Enabled {
		return nil
	}

	var err error
	s.signalSrv, err = signalServer.NewServer(ctx, s.metricsServer.Meter, "signal_")
	if err != nil {
		cleanupSTUNListeners(s.stunListeners)
		return fmt.Errorf("failed to create signal server: %w", err)
	}

	log.Infof("Signal server created")
	return nil
}

func (s *serverInstances) createHealthcheckServer(cfg *CombinedConfig) error {
	hCfg := healthcheck.Config{
		ListenAddress:  cfg.Server.HealthcheckAddress,
		ServiceChecker: s.relaySrv,
	}

	var err error
	s.healthcheck, err = createHealthCheck(hCfg, s.stunListeners)
	return err
}

// setupServerHooks registers services with management's gRPC server.
func setupServerHooks(servers *serverInstances, cfg *CombinedConfig) {
	if servers.mgmtSrv == nil {
		return
	}

	servers.mgmtSrv.AfterInit(func(s *mgmtServer.BaseServer) {
		grpcSrv := s.GRPCServer()

		if servers.signalSrv != nil {
			proto.RegisterSignalExchangeServer(grpcSrv, servers.signalSrv)
			log.Infof("Signal server registered on port %s", cfg.Server.ListenAddress)
		}

		s.SetHandlerFunc(createCombinedHandler(grpcSrv, s.APIHandler(), servers.relaySrv, servers.metricsServer.Meter, cfg))
		if servers.relaySrv != nil {
			log.Infof("Relay WebSocket handler added (path: /relay)")
		}
	})
}

func startServers(wg *sync.WaitGroup, srv *relayServer.Server, httpHealthcheck *healthcheck.Server, stunServer *stun.Server, metricsServer *sharedMetrics.Metrics) {
	if srv != nil {
		instanceURL := srv.InstanceURL()
		log.Infof("Relay server instance URL: %s", instanceURL.String())
		log.Infof("Relay WebSocket multiplexed on management port (no separate relay listener)")
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		log.Infof("running metrics server: %s%s", metricsServer.Addr, metricsServer.Endpoint)
		if err := metricsServer.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("failed to start metrics server: %v", err)
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

func shutdownServers(ctx context.Context, srv *relayServer.Server, httpHealthcheck *healthcheck.Server, stunServer *stun.Server, mgmtSrv *mgmtServer.BaseServer, metricsServer *sharedMetrics.Metrics) error {
	var errs error

	if err := httpHealthcheck.Shutdown(ctx); err != nil {
		errs = multierror.Append(errs, fmt.Errorf("failed to close healthcheck server: %w", err))
	}

	if stunServer != nil {
		if err := stunServer.Shutdown(); err != nil {
			errs = multierror.Append(errs, fmt.Errorf("failed to close STUN server: %w", err))
		}
	}

	if srv != nil {
		if err := srv.Shutdown(ctx); err != nil {
			errs = multierror.Append(errs, fmt.Errorf("failed to close relay server: %w", err))
		}
	}

	if mgmtSrv != nil {
		log.Infof("shutting down management and signal servers")
		if err := mgmtSrv.Stop(); err != nil {
			errs = multierror.Append(errs, fmt.Errorf("failed to close management server: %w", err))
		}
	}

	if metricsServer != nil {
		log.Infof("shutting down metrics server")
		if err := metricsServer.Shutdown(ctx); err != nil {
			errs = multierror.Append(errs, fmt.Errorf("failed to close metrics server: %w", err))
		}
	}

	return errs
}

func createHealthCheck(hCfg healthcheck.Config, stunListeners []*net.UDPConn) (*healthcheck.Server, error) {
	httpHealthcheck, err := healthcheck.NewServer(hCfg)
	if err != nil {
		cleanupSTUNListeners(stunListeners)
		return nil, fmt.Errorf("failed to create healthcheck server: %w", err)
	}
	return httpHealthcheck, nil
}

func createRelayServer(cfg relayServer.Config, stunListeners []*net.UDPConn) (*relayServer.Server, error) {
	srv, err := relayServer.NewServer(cfg)
	if err != nil {
		cleanupSTUNListeners(stunListeners)
		return nil, fmt.Errorf("failed to create relay server: %w", err)
	}
	return srv, nil
}

func cleanupSTUNListeners(stunListeners []*net.UDPConn) {
	for _, l := range stunListeners {
		_ = l.Close()
	}
}

func createSTUNListeners(cfg *CombinedConfig) ([]*net.UDPConn, error) {
	var stunListeners []*net.UDPConn
	if cfg.Relay.Stun.Enabled {
		for _, port := range cfg.Relay.Stun.Ports {
			listener, err := net.ListenUDP("udp", &net.UDPAddr{Port: port})
			if err != nil {
				cleanupSTUNListeners(stunListeners)
				return nil, fmt.Errorf("failed to create STUN listener on port %d: %w", port, err)
			}
			stunListeners = append(stunListeners, listener)
			log.Infof("STUN server listening on UDP port %d", port)
		}
	}
	return stunListeners, nil
}

func handleTLSConfig(cfg *CombinedConfig) (*tls.Config, bool, error) {
	tlsCfg := cfg.Server.TLS

	if tlsCfg.LetsEncrypt.AWSRoute53 {
		log.Debugf("using Let's Encrypt DNS resolver with Route 53 support")
		r53 := encryption.Route53TLS{
			DataDir: tlsCfg.LetsEncrypt.DataDir,
			Email:   tlsCfg.LetsEncrypt.Email,
			Domains: tlsCfg.LetsEncrypt.Domains,
		}
		tc, err := r53.GetCertificate()
		if err != nil {
			return nil, false, err
		}
		return tc, true, nil
	}

	if cfg.HasLetsEncrypt() {
		log.Infof("setting up TLS with Let's Encrypt")
		certManager, err := encryption.CreateCertManager(tlsCfg.LetsEncrypt.DataDir, tlsCfg.LetsEncrypt.Domains...)
		if err != nil {
			return nil, false, fmt.Errorf("failed creating LetsEncrypt cert manager: %w", err)
		}
		return certManager.TLSConfig(), true, nil
	}

	if cfg.HasTLSCert() {
		log.Debugf("using file based TLS config")
		tc, err := encryption.LoadTLSConfig(tlsCfg.CertFile, tlsCfg.KeyFile)
		if err != nil {
			return nil, false, err
		}
		return tc, true, nil
	}

	return nil, false, nil
}

func createManagementServer(cfg *CombinedConfig, mgmtConfig *nbconfig.Config) (*mgmtServer.BaseServer, error) {
	mgmt := cfg.Management

	dnsDomain := mgmt.DnsDomain
	singleAccModeDomain := dnsDomain

	// Extract port from listen address
	_, portStr, err := net.SplitHostPort(cfg.Server.ListenAddress)
	if err != nil {
		// If no port specified, assume default
		portStr = "443"
	}
	mgmtPort, _ := strconv.Atoi(portStr)

	mgmtSrv := mgmtServer.NewServer(
		mgmtConfig,
		dnsDomain,
		singleAccModeDomain,
		mgmtPort,
		cfg.Server.MetricsPort,
		mgmt.DisableAnonymousMetrics,
		mgmt.DisableGeoliteUpdate,
		// Always enable user deletion from IDP in combined server (embedded IdP is always enabled)
		true,
	)

	return mgmtSrv, nil
}

// createCombinedHandler creates an HTTP handler that multiplexes Management, Signal (via wsproxy), and Relay WebSocket traffic
func createCombinedHandler(grpcServer *grpc.Server, httpHandler http.Handler, relaySrv *relayServer.Server, meter metric.Meter, cfg *CombinedConfig) http.Handler {
	wsProxy := wsproxyserver.New(grpcServer, wsproxyserver.WithOTelMeter(meter))

	var relayAcceptFn func(conn net.Conn)
	if relaySrv != nil {
		relayAcceptFn = relaySrv.RelayAccept()
	}

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
			if cfg.Signal.Enabled {
				wsProxy.Handler().ServeHTTP(w, r)
			} else {
				http.Error(w, "Signal service not enabled", http.StatusNotFound)
			}

		// Relay WebSocket
		case r.URL.Path == "/relay":
			if relayAcceptFn != nil {
				handleRelayWebSocket(w, r, relayAcceptFn, cfg)
			} else {
				http.Error(w, "Relay service not enabled", http.StatusNotFound)
			}

		// Management HTTP API (default)
		default:
			httpHandler.ServeHTTP(w, r)
		}
	})
}

// handleRelayWebSocket handles incoming WebSocket connections for the relay service
func handleRelayWebSocket(w http.ResponseWriter, r *http.Request, acceptFn func(conn net.Conn), cfg *CombinedConfig) {
	acceptOptions := &websocket.AcceptOptions{
		OriginPatterns: []string{"*"},
	}

	wsConn, err := websocket.Accept(w, r, acceptOptions)
	if err != nil {
		log.Errorf("failed to accept relay ws connection: %s", err)
		return
	}

	connRemoteAddr := r.RemoteAddr
	if r.Header.Get("X-Real-Ip") != "" && r.Header.Get("X-Real-Port") != "" {
		connRemoteAddr = net.JoinHostPort(r.Header.Get("X-Real-Ip"), r.Header.Get("X-Real-Port"))
	}

	rAddr, err := net.ResolveTCPAddr("tcp", connRemoteAddr)
	if err != nil {
		_ = wsConn.Close(websocket.StatusInternalError, "internal error")
		return
	}

	lAddr, err := net.ResolveTCPAddr("tcp", cfg.Server.ListenAddress)
	if err != nil {
		_ = wsConn.Close(websocket.StatusInternalError, "internal error")
		return
	}

	log.Debugf("Relay WS client connected from: %s", rAddr)

	conn := ws.NewConn(wsConn, lAddr, rAddr)
	acceptFn(conn)
}

// logConfig prints all configuration parameters for debugging
func logConfig(cfg *CombinedConfig) {
	log.Info("=== Configuration ===")
	logServerConfig(cfg)
	logComponentsConfig(cfg)
	logRelayConfig(cfg)
	logManagementConfig(cfg)
	log.Info("=== End Configuration ===")
}

func logServerConfig(cfg *CombinedConfig) {
	log.Info("--- Server ---")
	log.Infof("  Listen address: %s", cfg.Server.ListenAddress)
	log.Infof("  Exposed address: %s", cfg.Server.ExposedAddress)
	log.Infof("  Healthcheck address: %s", cfg.Server.HealthcheckAddress)
	log.Infof("  Metrics port: %d", cfg.Server.MetricsPort)
	log.Infof("  Log level: %s", cfg.Server.LogLevel)
	log.Infof("  Data dir: %s", cfg.Server.DataDir)

	switch {
	case cfg.HasTLSCert():
		log.Infof("  TLS: cert=%s, key=%s", cfg.Server.TLS.CertFile, cfg.Server.TLS.KeyFile)
	case cfg.HasLetsEncrypt():
		log.Infof("  TLS: Let's Encrypt (domains=%v)", cfg.Server.TLS.LetsEncrypt.Domains)
	default:
		log.Info("  TLS: disabled (using reverse proxy)")
	}
}

func logComponentsConfig(cfg *CombinedConfig) {
	log.Info("--- Components ---")
	log.Infof("  Management: %v (log level: %s)", cfg.Management.Enabled, cfg.Management.LogLevel)
	log.Infof("  Signal: %v (log level: %s)", cfg.Signal.Enabled, cfg.Signal.LogLevel)
	log.Infof("  Relay: %v (log level: %s)", cfg.Relay.Enabled, cfg.Relay.LogLevel)
}

func logRelayConfig(cfg *CombinedConfig) {
	if !cfg.Relay.Enabled {
		return
	}
	log.Info("--- Relay ---")
	log.Infof("  Exposed address: %s", cfg.Relay.ExposedAddress)
	log.Infof("  Auth secret: %s...", maskSecret(cfg.Relay.AuthSecret))
	if cfg.Relay.Stun.Enabled {
		log.Infof("  STUN ports: %v (log level: %s)", cfg.Relay.Stun.Ports, cfg.Relay.Stun.LogLevel)
	} else {
		log.Info("  STUN: disabled")
	}
}

func logManagementConfig(cfg *CombinedConfig) {
	if !cfg.Management.Enabled {
		return
	}
	log.Info("--- Management ---")
	log.Infof("  Data dir: %s", cfg.Management.DataDir)
	log.Infof("  DNS domain: %s", cfg.Management.DnsDomain)
	log.Infof("  Store engine: %s", cfg.Management.Store.Engine)
	if cfg.Server.Store.DSN != "" {
		log.Infof("  Store DSN: %s", maskDSNPassword(cfg.Server.Store.DSN))
	}

	log.Info("  Auth (embedded IdP):")
	log.Infof("    Issuer: %s", cfg.Management.Auth.Issuer)
	log.Infof("    Dashboard redirect URIs: %v", cfg.Management.Auth.DashboardRedirectURIs)
	log.Infof("    CLI redirect URIs: %v", cfg.Management.Auth.CLIRedirectURIs)

	log.Info("  Client settings:")
	log.Infof("    Signal URI: %s", cfg.Management.SignalURI)
	for _, s := range cfg.Management.Stuns {
		log.Infof("    STUN: %s", s.URI)
	}
	if len(cfg.Management.Relays.Addresses) > 0 {
		log.Infof("    Relay addresses: %v", cfg.Management.Relays.Addresses)
		log.Infof("    Relay credentials TTL: %s", cfg.Management.Relays.CredentialsTTL)
	}
}

// logEnvVars logs all NB_ environment variables that are currently set
func logEnvVars() {
	log.Info("=== Environment Variables ===")
	found := false
	for _, env := range os.Environ() {
		if strings.HasPrefix(env, "NB_") {
			key, _, _ := strings.Cut(env, "=")
			value := os.Getenv(key)
			if strings.Contains(strings.ToLower(key), "secret") || strings.Contains(strings.ToLower(key), "key") || strings.Contains(strings.ToLower(key), "password") {
				value = maskSecret(value)
			}
			log.Infof("  %s=%s", key, value)
			found = true
		}
	}
	if !found {
		log.Info("  (none set)")
	}
	log.Info("=== End Environment Variables ===")
}

// maskDSNPassword masks the password in a DSN string.
// Handles both key=value format ("password=secret") and URI format ("user:secret@host").
func maskDSNPassword(dsn string) string {
	// Key=value format: "host=localhost user=nb password=secret dbname=nb"
	if strings.Contains(dsn, "password=") {
		parts := strings.Fields(dsn)
		for i, p := range parts {
			if strings.HasPrefix(p, "password=") {
				parts[i] = "password=****"
			}
		}
		return strings.Join(parts, " ")
	}

	// URI format: "user:password@host..."
	if atIdx := strings.Index(dsn, "@"); atIdx != -1 {
		prefix := dsn[:atIdx]
		if colonIdx := strings.Index(prefix, ":"); colonIdx != -1 {
			return prefix[:colonIdx+1] + "****" + dsn[atIdx:]
		}
	}

	return dsn
}

// maskSecret returns first 4 chars of secret followed by "..."
func maskSecret(secret string) string {
	if len(secret) <= 4 {
		return "****"
	}
	return secret[:4] + "..."
}
