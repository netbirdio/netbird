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
	"go.opentelemetry.io/otel/metric/noop"
	"google.golang.org/grpc"

	"github.com/netbirdio/netbird/encryption"
	mgmtServer "github.com/netbirdio/netbird/management/internals/server"
	nbconfig "github.com/netbirdio/netbird/management/internals/server/config"
	"github.com/netbirdio/netbird/relay/healthcheck"
	relayServer "github.com/netbirdio/netbird/relay/server"
	"github.com/netbirdio/netbird/relay/server/listener/ws"
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
	// Load configuration from YAML file
	var err error
	config, err = LoadConfig(configPath)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	if err := config.Validate(); err != nil {
		return fmt.Errorf("invalid config: %w", err)
	}

	// Initialize logging
	if err := util.InitLog(config.Server.LogLevel, config.Server.LogFile); err != nil {
		return fmt.Errorf("failed to initialize log: %w", err)
	}

	log.Infof("Starting combined NetBird server")
	logConfig(config)

	// Management is required as the base server when signal or relay are enabled
	if (config.Signal.Enabled || config.Relay.Enabled) && !config.Management.Enabled {
		return fmt.Errorf("management must be enabled when signal or relay are enabled (provides the base HTTP server)")
	}

	wg := sync.WaitGroup{}

	// TODO: Implement combined metrics server for all components
	// For now, metrics are disabled to avoid port conflicts between components

	_, tlsSupport, err := handleTLSConfig(config)
	if err != nil {
		return fmt.Errorf("failed to setup TLS config: %w", err)
	}

	// Create STUN listeners early to fail fast (only if relay with STUN is enabled)
	var stunListeners []*net.UDPConn
	if config.Relay.Enabled {
		stunListeners, err = createSTUNListeners(config)
		if err != nil {
			return err
		}
	}

	// Create relay server if enabled
	var srv *relayServer.Server
	if config.Relay.Enabled {
		hashedSecret := sha256.Sum256([]byte(config.Relay.AuthSecret))
		authenticator := auth.NewTimedHMACValidator(hashedSecret[:], 24*time.Hour)

		relayCfg := relayServer.Config{
			ExposedAddress: config.Relay.ExposedAddress,
			AuthValidator:  authenticator,
			TLSSupport:     tlsSupport,
		}

		srv, err = createRelayServer(relayCfg, stunListeners)
		if err != nil {
			return err
		}

		log.Infof("Relay server created")
	}

	// Create management server if enabled
	var mgmtSrv *mgmtServer.BaseServer
	var mgmtConfig *nbconfig.Config
	if config.Management.Enabled {
		mgmtConfig = config.ToManagementConfig()

		// Extract port from listen address for embedded IdP config
		_, portStr, portErr := net.SplitHostPort(config.Server.ListenAddress)
		if portErr != nil {
			portStr = "443"
		}
		var mgmtPort int
		fmt.Sscanf(portStr, "%d", &mgmtPort)

		// Apply embedded IdP configuration (mirrors management/cmd/management.go)
		if err := ApplyEmbeddedIdPConfig(cmd.Context(), mgmtConfig, mgmtPort, config.Management.DisableSingleAccountMode); err != nil {
			cleanupSTUNListeners(stunListeners)
			return fmt.Errorf("failed to apply embedded IdP config: %w", err)
		}

		// Ensure encryption key exists
		if err := EnsureEncryptionKey(cmd.Context(), mgmtConfig); err != nil {
			cleanupSTUNListeners(stunListeners)
			return fmt.Errorf("failed to ensure encryption key: %w", err)
		}

		// Log config info
		LogConfigInfo(mgmtConfig)

		mgmtSrv, err = createManagementServer(config, mgmtConfig)
		if err != nil {
			cleanupSTUNListeners(stunListeners)
			return fmt.Errorf("failed to create management server: %w", err)
		}
		log.Infof("Management server created")
	}

	// Create Signal server if enabled
	// Use no-op meter since metrics are disabled for now
	noopMeter := noop.NewMeterProvider().Meter("noop")
	var signalSrv *signalServer.Server
	if config.Signal.Enabled {
		signalSrv, err = signalServer.NewServer(cmd.Context(), noopMeter)
		if err != nil {
			cleanupSTUNListeners(stunListeners)
			return fmt.Errorf("failed to create signal server: %w", err)
		}
		log.Infof("Signal server created")
	}

	// Register services with management's gRPC server using AfterInit hook
	if mgmtSrv != nil {
		mgmtSrv.AfterInit(func(s *mgmtServer.BaseServer) {
			grpcSrv := s.GRPCServer()

			// Register Signal service if enabled
			if signalSrv != nil {
				proto.RegisterSignalExchangeServer(grpcSrv, signalSrv)
				log.Infof("Signal server registered on port %s", config.Server.ListenAddress)
			}

			// Create combined handler with enabled components
			s.SetHandlerFunc(createCombinedHandler(grpcSrv, s.APIHandler(), srv, noopMeter, config))
			if srv != nil {
				log.Infof("Relay WebSocket handler added (path: /relay)")
			}
		})
	}

	// Create healthcheck server
	var httpHealthcheck *healthcheck.Server
	hCfg := healthcheck.Config{
		ListenAddress:  config.Server.HealthcheckAddress,
		ServiceChecker: srv, // Can be nil if relay is disabled
	}
	httpHealthcheck, err = createHealthCheck(hCfg, stunListeners)
	if err != nil {
		return err
	}

	// Create STUN server if listeners exist
	var stunServer *stun.Server
	if len(stunListeners) > 0 {
		stunServer = stun.NewServer(stunListeners, config.Relay.Stun.LogLevel)
	}

	// Start management server (this also starts the HTTP listener)
	if mgmtSrv != nil {
		if err := mgmtSrv.Start(cmd.Context()); err != nil {
			cleanupSTUNListeners(stunListeners)
			return fmt.Errorf("failed to start management server: %w", err)
		}
	}

	// Start all other servers
	startServers(&wg, srv, httpHealthcheck, stunServer)

	waitForExitSignal()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	err = shutdownServers(ctx, srv, httpHealthcheck, stunServer, mgmtSrv)
	wg.Wait()
	return err
}

func startServers(wg *sync.WaitGroup, srv *relayServer.Server, httpHealthcheck *healthcheck.Server, stunServer *stun.Server) {
	if srv != nil {
		instanceURL := srv.InstanceURL()
		log.Infof("Relay server instance URL: %s", instanceURL.String())
		log.Infof("Relay WebSocket multiplexed on management port (no separate relay listener)")
	}

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

func shutdownServers(ctx context.Context, srv *relayServer.Server, httpHealthcheck *healthcheck.Server, stunServer *stun.Server, mgmtSrv *mgmtServer.BaseServer) error {
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
	singleAccModeDomain := mgmt.SingleAccountModeDomain
	if !mgmt.DisableSingleAccountMode && singleAccModeDomain == "" && dnsDomain != "" {
		singleAccModeDomain = dnsDomain
	}

	// Extract port from listen address
	_, portStr, err := net.SplitHostPort(cfg.Server.ListenAddress)
	if err != nil {
		// If no port specified, assume default
		portStr = "443"
	}
	var mgmtPort int
	fmt.Sscanf(portStr, "%d", &mgmtPort)

	// Enable user deletion from IDP by default if EmbeddedIdP is enabled
	userDeleteFromIDPEnabled := mgmt.UserDeleteFromIDPEnabled
	if mgmt.Auth.Enabled {
		userDeleteFromIDPEnabled = true
	}

	mgmtSrv := mgmtServer.NewServer(
		mgmtConfig,
		dnsDomain,
		singleAccModeDomain,
		mgmtPort,
		cfg.Server.MetricsPort,
		mgmt.DisableAnonymousMetrics,
		mgmt.DisableGeoliteUpdate,
		userDeleteFromIDPEnabled,
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

	// Server settings
	log.Info("--- Server ---")
	log.Infof("  Listen address: %s", cfg.Server.ListenAddress)
	log.Infof("  Exposed address: %s", cfg.Server.ExposedAddress)
	log.Infof("  Healthcheck address: %s", cfg.Server.HealthcheckAddress)
	log.Infof("  Metrics port: %d", cfg.Server.MetricsPort)
	log.Infof("  Log level: %s", cfg.Server.LogLevel)
	log.Infof("  Data dir: %s", cfg.Server.DataDir)

	// TLS
	if cfg.HasTLSCert() {
		log.Infof("  TLS: cert=%s, key=%s", cfg.Server.TLS.CertFile, cfg.Server.TLS.KeyFile)
	} else if cfg.HasLetsEncrypt() {
		log.Infof("  TLS: Let's Encrypt (domains=%v)", cfg.Server.TLS.LetsEncrypt.Domains)
	} else {
		log.Info("  TLS: disabled (using reverse proxy)")
	}

	// Components enabled
	log.Info("--- Components ---")
	log.Infof("  Management: %v (log level: %s)", cfg.Management.Enabled, cfg.Management.LogLevel)
	log.Infof("  Signal: %v (log level: %s)", cfg.Signal.Enabled, cfg.Signal.LogLevel)
	log.Infof("  Relay: %v (log level: %s)", cfg.Relay.Enabled, cfg.Relay.LogLevel)

	// Relay config
	if cfg.Relay.Enabled {
		log.Info("--- Relay ---")
		log.Infof("  Exposed address: %s", cfg.Relay.ExposedAddress)
		log.Infof("  Auth secret: %s...", maskSecret(cfg.Relay.AuthSecret))
		if cfg.Relay.Stun.Enabled {
			log.Infof("  STUN ports: %v (log level: %s)", cfg.Relay.Stun.Ports, cfg.Relay.Stun.LogLevel)
		} else {
			log.Info("  STUN: disabled")
		}
	}

	// Management config
	if cfg.Management.Enabled {
		log.Info("--- Management ---")
		log.Infof("  Data dir: %s", cfg.Management.DataDir)
		log.Infof("  DNS domain: %s", cfg.Management.DnsDomain)
		log.Infof("  Single account mode domain: %s", cfg.Management.SingleAccountModeDomain)
		log.Infof("  Disable single account mode: %v", cfg.Management.DisableSingleAccountMode)
		log.Infof("  Store engine: %s", cfg.Management.Store.Engine)

		// Auth/IdP
		if cfg.Management.Auth.Enabled {
			log.Info("  Auth (embedded IdP):")
			log.Infof("    Issuer: %s", cfg.Management.Auth.Issuer)
			log.Infof("    Dashboard redirect URIs: %v", cfg.Management.Auth.DashboardRedirectURIs)
			log.Infof("    CLI redirect URIs: %v", cfg.Management.Auth.CLIRedirectURIs)
		} else {
			log.Info("  Auth: disabled (using external IdP)")
		}

		// Client settings (what clients will receive)
		log.Info("  Client settings:")
		log.Infof("    Signal URI: %s", cfg.Management.SignalURI)
		if len(cfg.Management.Stuns) > 0 {
			for _, s := range cfg.Management.Stuns {
				log.Infof("    STUN: %s", s.URI)
			}
		}
		if len(cfg.Management.Relays.Addresses) > 0 {
			log.Infof("    Relay addresses: %v", cfg.Management.Relays.Addresses)
			log.Infof("    Relay credentials TTL: %s", cfg.Management.Relays.CredentialsTTL)
		}
	}

	log.Info("=== End Configuration ===")
}

// maskSecret returns first 4 chars of secret followed by "..."
func maskSecret(secret string) string {
	if len(secret) <= 4 {
		return "****"
	}
	return secret[:4] + "..."
}
