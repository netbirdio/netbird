// Package proxy runs a NetBird proxy server.
// It attempts to do everything it needs to do within the context
// of a single request to the server to try to reduce the amount
// of concurrency coordination that is required. However, it does
// run two additional routines in an error group for handling
// updates from the management server and running a separate
// HTTP server to handle ACME HTTP-01 challenges (if configured).
package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"path/filepath"
	"reflect"
	"sync"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/pires/go-proxyproto"
	prometheus2 "github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel/exporters/prometheus"
	"go.opentelemetry.io/otel/sdk/metric"
	"golang.org/x/exp/maps"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/netbirdio/netbird/proxy/internal/accesslog"
	"github.com/netbirdio/netbird/proxy/internal/acme"
	"github.com/netbirdio/netbird/proxy/internal/auth"
	"github.com/netbirdio/netbird/proxy/internal/certwatch"
	"github.com/netbirdio/netbird/proxy/internal/conntrack"
	"github.com/netbirdio/netbird/proxy/internal/crowdsec"
	"github.com/netbirdio/netbird/proxy/internal/debug"
	"github.com/netbirdio/netbird/proxy/internal/geolocation"
	proxygrpc "github.com/netbirdio/netbird/proxy/internal/grpc"
	"github.com/netbirdio/netbird/proxy/internal/health"
	"github.com/netbirdio/netbird/proxy/internal/k8s"
	proxymetrics "github.com/netbirdio/netbird/proxy/internal/metrics"
	"github.com/netbirdio/netbird/proxy/internal/netutil"
	"github.com/netbirdio/netbird/proxy/internal/proxy"
	"github.com/netbirdio/netbird/proxy/internal/restrict"
	"github.com/netbirdio/netbird/proxy/internal/roundtrip"
	nbtcp "github.com/netbirdio/netbird/proxy/internal/tcp"
	"github.com/netbirdio/netbird/proxy/internal/types"
	udprelay "github.com/netbirdio/netbird/proxy/internal/udp"
	"github.com/netbirdio/netbird/proxy/web"
	"github.com/netbirdio/netbird/shared/management/domain"
	"github.com/netbirdio/netbird/shared/management/proto"
	"github.com/netbirdio/netbird/util/embeddedroots"
)

// portRouter bundles a per-port Router with its listener and cancel func.
type portRouter struct {
	router   *nbtcp.Router
	listener net.Listener
	cancel   context.CancelFunc
}

type Server struct {
	mgmtClient    proto.ProxyServiceClient
	proxy         *proxy.ReverseProxy
	netbird       *roundtrip.NetBird
	acme          *acme.Manager
	auth          *auth.Middleware
	http          *http.Server
	https         *http.Server
	debug         *http.Server
	healthServer  *health.Server
	healthChecker *health.Checker
	meter         *proxymetrics.Metrics
	accessLog     *accesslog.Logger
	mainRouter    *nbtcp.Router
	mainPort      uint16
	udpMu         sync.Mutex
	udpRelays     map[types.ServiceID]*udprelay.Relay
	udpRelayWg    sync.WaitGroup
	portMu        sync.RWMutex
	portRouters   map[uint16]*portRouter
	svcPorts      map[types.ServiceID][]uint16
	lastMappings  map[types.ServiceID]*proto.ProxyMapping
	portRouterWg  sync.WaitGroup

	// hijackTracker tracks hijacked connections (e.g. WebSocket upgrades)
	// so they can be closed during graceful shutdown, since http.Server.Shutdown
	// does not handle them.
	hijackTracker conntrack.HijackTracker
	// geo resolves IP addresses to country/city for access restrictions and access logs.
	geo    restrict.GeoResolver
	geoRaw *geolocation.Lookup

	// crowdsecRegistry manages the shared CrowdSec bouncer lifecycle.
	crowdsecRegistry *crowdsec.Registry
	// crowdsecServices tracks which services have CrowdSec enabled for
	// proper acquire/release lifecycle management.
	crowdsecMu       sync.Mutex
	crowdsecServices map[types.ServiceID]bool

	// routerReady is closed once mainRouter is fully initialized.
	// The mapping worker waits on this before processing updates.
	routerReady chan struct{}

	// Mostly used for debugging on management.
	startTime time.Time

	ID                       string
	Logger                   *log.Logger
	Version                  string
	ProxyURL                 string
	ManagementAddress        string
	CertificateDirectory     string
	CertificateFile          string
	CertificateKeyFile       string
	GenerateACMECertificates bool
	ACMEChallengeAddress     string
	ACMEDirectory            string
	// ACMEEABKID is the External Account Binding Key ID for CAs that require EAB (e.g., ZeroSSL).
	ACMEEABKID string
	// ACMEEABHMACKey is the External Account Binding HMAC key (base64 URL-encoded) for CAs that require EAB.
	ACMEEABHMACKey string
	// ACMEChallengeType specifies the ACME challenge type: "http-01" or "tls-alpn-01".
	// Defaults to "tls-alpn-01" if not specified.
	ACMEChallengeType string
	// CertLockMethod controls how ACME certificate locks are coordinated
	// across replicas. Default: CertLockAuto (detect environment).
	CertLockMethod acme.CertLockMethod
	// WildcardCertDir is an optional directory containing wildcard certificate
	// pairs (<name>.crt / <name>.key). Wildcard patterns are extracted from
	// the certificates' SAN lists. Matching domains use these static certs
	// instead of ACME.
	WildcardCertDir string

	// DebugEndpointEnabled enables the debug HTTP endpoint.
	DebugEndpointEnabled bool
	// DebugEndpointAddress is the address for the debug HTTP endpoint (default: ":8444").
	DebugEndpointAddress string
	// HealthAddress is the address for the health probe endpoint.
	HealthAddress string
	// ProxyToken is the access token for authenticating with the management server.
	ProxyToken string
	// ForwardedProto overrides the X-Forwarded-Proto value sent to backends.
	// Valid values: "auto" (detect from TLS), "http", "https".
	ForwardedProto string
	// TrustedProxies is a list of IP prefixes for trusted upstream proxies.
	// When set, forwarding headers from these sources are preserved and
	// appended to instead of being stripped.
	TrustedProxies []netip.Prefix
	// WireguardPort is the port for the NetBird tunnel interface. Use 0
	// for a random OS-assigned port. A fixed port only works with
	// single-account deployments; multiple accounts will fail to bind
	// the same port.
	WireguardPort uint16
	// ProxyProtocol enables PROXY protocol (v1/v2) on TCP listeners.
	// When enabled, the real client IP is extracted from the PROXY header
	// sent by upstream L4 proxies that support PROXY protocol.
	ProxyProtocol bool
	// PreSharedKey used for tunnel between proxy and peers (set globally not per account)
	PreSharedKey string
	// SupportsCustomPorts indicates whether the proxy can bind arbitrary
	// ports for TCP/UDP/TLS services.
	SupportsCustomPorts bool
	// RequireSubdomain indicates whether a subdomain label is required
	// in front of this proxy's cluster domain. When true, accounts cannot
	// create services on the bare cluster domain.
	RequireSubdomain bool
	// MaxDialTimeout caps the per-service backend dial timeout.
	// When the API sends a timeout, it is clamped to this value.
	// When the API sends no timeout, this value is used as the default.
	// Zero means no cap (the proxy honors whatever management sends).
	MaxDialTimeout time.Duration
	// GeoDataDir is the directory containing GeoLite2 MMDB files for
	// country-based access restrictions. Empty disables geo lookups.
	GeoDataDir string
	// CrowdSecAPIURL is the CrowdSec LAPI URL. Empty disables CrowdSec.
	CrowdSecAPIURL string
	// CrowdSecAPIKey is the CrowdSec bouncer API key. Empty disables CrowdSec.
	CrowdSecAPIKey string
	// MaxSessionIdleTimeout caps the per-service session idle timeout.
	// Zero means no cap (the proxy honors whatever management sends).
	// Set via NB_PROXY_MAX_SESSION_IDLE_TIMEOUT for shared deployments.
	MaxSessionIdleTimeout time.Duration
}

// clampIdleTimeout returns d capped to MaxSessionIdleTimeout when configured.
func (s *Server) clampIdleTimeout(d time.Duration) time.Duration {
	if s.MaxSessionIdleTimeout > 0 && d > s.MaxSessionIdleTimeout {
		return s.MaxSessionIdleTimeout
	}
	return d
}

// clampDialTimeout returns d capped to MaxDialTimeout when configured.
// If d is zero, MaxDialTimeout is used as the default.
func (s *Server) clampDialTimeout(d time.Duration) time.Duration {
	if s.MaxDialTimeout <= 0 {
		return d
	}
	if d <= 0 || d > s.MaxDialTimeout {
		return s.MaxDialTimeout
	}
	return d
}

// NotifyStatus sends a status update to management about tunnel connectivity.
func (s *Server) NotifyStatus(ctx context.Context, accountID types.AccountID, serviceID types.ServiceID, connected bool) error {
	status := proto.ProxyStatus_PROXY_STATUS_TUNNEL_NOT_CREATED
	if connected {
		status = proto.ProxyStatus_PROXY_STATUS_ACTIVE
	}

	_, err := s.mgmtClient.SendStatusUpdate(ctx, &proto.SendStatusUpdateRequest{
		ServiceId:         string(serviceID),
		AccountId:         string(accountID),
		Status:            status,
		CertificateIssued: false,
	})
	return err
}

// NotifyCertificateIssued sends a notification to management that a certificate was issued
func (s *Server) NotifyCertificateIssued(ctx context.Context, accountID types.AccountID, serviceID types.ServiceID, domain string) error {
	_, err := s.mgmtClient.SendStatusUpdate(ctx, &proto.SendStatusUpdateRequest{
		ServiceId:         string(serviceID),
		AccountId:         string(accountID),
		Status:            proto.ProxyStatus_PROXY_STATUS_ACTIVE,
		CertificateIssued: true,
	})
	return err
}

func (s *Server) ListenAndServe(ctx context.Context, addr string) (err error) {
	s.initDefaults()
	s.routerReady = make(chan struct{})
	s.udpRelays = make(map[types.ServiceID]*udprelay.Relay)
	s.portRouters = make(map[uint16]*portRouter)
	s.svcPorts = make(map[types.ServiceID][]uint16)
	s.lastMappings = make(map[types.ServiceID]*proto.ProxyMapping)

	exporter, err := prometheus.New()
	if err != nil {
		return fmt.Errorf("create prometheus exporter: %w", err)
	}

	provider := metric.NewMeterProvider(metric.WithReader(exporter))
	pkg := reflect.TypeOf(Server{}).PkgPath()
	meter := provider.Meter(pkg)

	s.meter, err = proxymetrics.New(ctx, meter)
	if err != nil {
		return fmt.Errorf("create metrics: %w", err)
	}

	mgmtConn, err := s.dialManagement()
	if err != nil {
		return err
	}
	defer func() {
		if err := mgmtConn.Close(); err != nil {
			s.Logger.Debugf("management connection close: %v", err)
		}
	}()
	s.mgmtClient = proto.NewProxyServiceClient(mgmtConn)
	runCtx, runCancel := context.WithCancel(ctx)
	defer runCancel()

	// Initialize the netbird client, this is required to build peer connections
	// to proxy over.
	s.netbird = roundtrip.NewNetBird(s.ID, s.ProxyURL, roundtrip.ClientConfig{
		MgmtAddr:     s.ManagementAddress,
		WGPort:       s.WireguardPort,
		PreSharedKey: s.PreSharedKey,
	}, s.Logger, s, s.mgmtClient)

	// Create health checker before the mapping worker so it can track
	// management connectivity from the first stream connection.
	s.healthChecker = health.NewChecker(s.Logger, s.netbird)

	s.crowdsecRegistry = crowdsec.NewRegistry(s.CrowdSecAPIURL, s.CrowdSecAPIKey, log.NewEntry(s.Logger))
	s.crowdsecServices = make(map[types.ServiceID]bool)

	go s.newManagementMappingWorker(runCtx, s.mgmtClient)

	tlsConfig, err := s.configureTLS(ctx)
	if err != nil {
		return err
	}

	// Configure the reverse proxy using NetBird's HTTP Client Transport for proxying.
	s.proxy = proxy.NewReverseProxy(s.meter.RoundTripper(s.netbird), s.ForwardedProto, s.TrustedProxies, s.Logger)

	geoLookup, err := geolocation.NewLookup(s.Logger, s.GeoDataDir)
	if err != nil {
		return fmt.Errorf("initialize geolocation: %w", err)
	}
	s.geoRaw = geoLookup
	if geoLookup != nil {
		s.geo = geoLookup
	}

	var startupOK bool
	defer func() {
		if startupOK {
			return
		}
		if s.geoRaw != nil {
			if err := s.geoRaw.Close(); err != nil {
				s.Logger.Debugf("close geolocation on startup failure: %v", err)
			}
		}
	}()

	// Configure the authentication middleware with session validator for OIDC group checks.
	s.auth = auth.NewMiddleware(s.Logger, s.mgmtClient, s.geo)

	// Configure Access logs to management server.
	s.accessLog = accesslog.NewLogger(s.mgmtClient, s.Logger, s.TrustedProxies)

	s.startDebugEndpoint()

	if err := s.startHealthServer(); err != nil {
		return err
	}

	// Build the handler chain from inside out.
	handler := http.Handler(s.proxy)
	handler = s.auth.Protect(handler)
	handler = web.AssetHandler(handler)
	handler = s.accessLog.Middleware(handler)
	handler = s.meter.Middleware(handler)
	handler = s.hijackTracker.Middleware(handler)

	// Start a raw TCP listener; the SNI router peeks at ClientHello
	// and routes to either the HTTP handler or a TCP relay.
	lc := net.ListenConfig{}
	ln, err := lc.Listen(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", addr, err)
	}
	if s.ProxyProtocol {
		ln = s.wrapProxyProtocol(ln)
	}
	s.mainPort = uint16(ln.Addr().(*net.TCPAddr).Port) //nolint:gosec // port from OS is always valid

	// Set up the SNI router for TCP/HTTP multiplexing on the main port.
	s.mainRouter = nbtcp.NewRouter(s.Logger, s.resolveDialFunc, ln.Addr())
	s.mainRouter.SetObserver(s.meter)
	s.mainRouter.SetAccessLogger(s.accessLog)
	close(s.routerReady)

	// The HTTP server uses the chanListener fed by the SNI router.
	s.https = &http.Server{
		Addr:              addr,
		Handler:           handler,
		TLSConfig:         tlsConfig,
		ReadHeaderTimeout: httpReadHeaderTimeout,
		IdleTimeout:       httpIdleTimeout,
		ErrorLog:          newHTTPServerLogger(s.Logger, logtagValueHTTPS),
	}

	startupOK = true

	httpsErr := make(chan error, 1)
	go func() {
		s.Logger.Debug("starting HTTPS server on SNI router HTTP channel")
		httpsErr <- s.https.ServeTLS(s.mainRouter.HTTPListener(), "", "")
	}()

	routerErr := make(chan error, 1)
	go func() {
		s.Logger.Debugf("starting SNI router on %s", addr)
		routerErr <- s.mainRouter.Serve(runCtx, ln)
	}()

	select {
	case err := <-httpsErr:
		s.shutdownServices()
		if !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("https server: %w", err)
		}
		return nil
	case err := <-routerErr:
		s.shutdownServices()
		if err != nil {
			return fmt.Errorf("SNI router: %w", err)
		}
		return nil
	case <-ctx.Done():
		s.gracefulShutdown()
		return nil
	}
}

// initDefaults sets fallback values for optional Server fields.
func (s *Server) initDefaults() {
	s.startTime = time.Now()

	// If no ID is set then one can be generated.
	if s.ID == "" {
		s.ID = "netbird-proxy-" + s.startTime.Format("20060102150405")
	}
	// Fallback version option in case it is not set.
	if s.Version == "" {
		s.Version = "dev"
	}

	// If no logger is specified fallback to the standard logger.
	if s.Logger == nil {
		s.Logger = log.StandardLogger()
	}
}

// startDebugEndpoint launches the debug HTTP server if enabled.
func (s *Server) startDebugEndpoint() {
	if !s.DebugEndpointEnabled {
		return
	}
	debugAddr := debugEndpointAddr(s.DebugEndpointAddress)
	debugHandler := debug.NewHandler(s.netbird, s.healthChecker, s.Logger)
	if s.acme != nil {
		debugHandler.SetCertStatus(s.acme)
	}
	s.debug = &http.Server{
		Addr:     debugAddr,
		Handler:  debugHandler,
		ErrorLog: newHTTPServerLogger(s.Logger, logtagValueDebug),
	}
	go func() {
		s.Logger.Infof("starting debug endpoint on %s", debugAddr)
		if err := s.debug.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.Logger.Errorf("debug endpoint error: %v", err)
		}
	}()
}

// startHealthServer launches the health probe and metrics server.
func (s *Server) startHealthServer() error {
	healthAddr := s.HealthAddress
	if healthAddr == "" {
		healthAddr = defaultHealthAddr
	}
	s.healthServer = health.NewServer(healthAddr, s.healthChecker, s.Logger, promhttp.HandlerFor(prometheus2.DefaultGatherer, promhttp.HandlerOpts{EnableOpenMetrics: true}))
	healthListener, err := net.Listen("tcp", healthAddr)
	if err != nil {
		return fmt.Errorf("health probe server listen on %s: %w", healthAddr, err)
	}
	go func() {
		if err := s.healthServer.Serve(healthListener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.Logger.Errorf("health probe server: %v", err)
		}
	}()
	return nil
}

// wrapProxyProtocol wraps a listener with PROXY protocol support.
// When TrustedProxies is configured, only those sources may send PROXY headers;
// connections from untrusted sources have any PROXY header ignored.
func (s *Server) wrapProxyProtocol(ln net.Listener) net.Listener {
	ppListener := &proxyproto.Listener{
		Listener:          ln,
		ReadHeaderTimeout: proxyProtoHeaderTimeout,
	}
	if len(s.TrustedProxies) > 0 {
		ppListener.ConnPolicy = s.proxyProtocolPolicy
	} else {
		s.Logger.Warn("PROXY protocol enabled without trusted proxies; any source may send PROXY headers")
	}
	s.Logger.Info("PROXY protocol enabled on listener")
	return ppListener
}

// proxyProtocolPolicy returns whether to require, skip, or reject the PROXY
// header based on whether the connection source is in TrustedProxies.
func (s *Server) proxyProtocolPolicy(opts proxyproto.ConnPolicyOptions) (proxyproto.Policy, error) {
	// No logging on reject to prevent abuse
	tcpAddr, ok := opts.Upstream.(*net.TCPAddr)
	if !ok {
		return proxyproto.REJECT, nil
	}
	addr, ok := netip.AddrFromSlice(tcpAddr.IP)
	if !ok {
		return proxyproto.REJECT, nil
	}
	addr = addr.Unmap()

	// called per accept
	for _, prefix := range s.TrustedProxies {
		if prefix.Contains(addr) {
			return proxyproto.REQUIRE, nil
		}
	}
	return proxyproto.IGNORE, nil
}

const (
	defaultHealthAddr = "localhost:8080"
	defaultDebugAddr  = "localhost:8444"

	// proxyProtoHeaderTimeout is the deadline for reading the PROXY protocol
	// header after accepting a connection.
	proxyProtoHeaderTimeout = 5 * time.Second

	// shutdownPreStopDelay is the time to wait after receiving a shutdown signal
	// before draining connections. This allows the load balancer to propagate
	// the endpoint removal.
	shutdownPreStopDelay = 5 * time.Second

	// shutdownDrainTimeout is the maximum time to wait for in-flight HTTP
	// requests to complete during graceful shutdown.
	shutdownDrainTimeout = 30 * time.Second

	// shutdownServiceTimeout is the maximum time to wait for auxiliary
	// services (health probe, debug endpoint, ACME) to shut down.
	shutdownServiceTimeout = 5 * time.Second

	// httpReadHeaderTimeout limits how long the server waits to read
	// request headers after accepting a connection. Prevents slowloris.
	httpReadHeaderTimeout = 10 * time.Second
	// httpIdleTimeout limits how long an idle keep-alive connection
	// stays open before the server closes it.
	httpIdleTimeout = 120 * time.Second
)

func (s *Server) dialManagement() (*grpc.ClientConn, error) {
	mgmtURL, err := url.Parse(s.ManagementAddress)
	if err != nil {
		return nil, fmt.Errorf("parse management address: %w", err)
	}
	creds := insecure.NewCredentials()
	// Assume management TLS is enabled for gRPC as well if using HTTPS for the API.
	if mgmtURL.Scheme == "https" {
		certPool, err := x509.SystemCertPool()
		if err != nil || certPool == nil {
			// Fall back to embedded CAs if no OS-provided ones are available.
			certPool = embeddedroots.Get()
		}
		creds = credentials.NewTLS(&tls.Config{
			RootCAs: certPool,
		})
	}
	s.Logger.WithFields(log.Fields{
		"gRPC_address": mgmtURL.Host,
		"TLS_enabled":  mgmtURL.Scheme == "https",
	}).Debug("starting management gRPC client")
	conn, err := grpc.NewClient(mgmtURL.Host,
		grpc.WithTransportCredentials(creds),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:                20 * time.Second,
			Timeout:             10 * time.Second,
			PermitWithoutStream: true,
		}),
		proxygrpc.WithProxyToken(s.ProxyToken),
	)
	if err != nil {
		return nil, fmt.Errorf("create management connection: %w", err)
	}
	return conn, nil
}

func (s *Server) configureTLS(ctx context.Context) (*tls.Config, error) {
	tlsConfig := &tls.Config{}
	if !s.GenerateACMECertificates {
		s.Logger.Debug("ACME certificates disabled, using static certificates with file watching")
		certPath := filepath.Join(s.CertificateDirectory, s.CertificateFile)
		keyPath := filepath.Join(s.CertificateDirectory, s.CertificateKeyFile)

		certWatcher, err := certwatch.NewWatcher(certPath, keyPath, s.Logger)
		if err != nil {
			return nil, fmt.Errorf("initialize certificate watcher: %w", err)
		}
		go certWatcher.Watch(ctx)
		tlsConfig.GetCertificate = certWatcher.GetCertificate
		return tlsConfig, nil
	}

	if s.ACMEChallengeType == "" {
		s.ACMEChallengeType = "tls-alpn-01"
	}
	s.Logger.WithFields(log.Fields{
		"acme_server":    s.ACMEDirectory,
		"challenge_type": s.ACMEChallengeType,
	}).Debug("ACME certificates enabled, configuring certificate manager")
	var err error
	s.acme, err = acme.NewManager(acme.ManagerConfig{
		CertDir:     s.CertificateDirectory,
		ACMEURL:     s.ACMEDirectory,
		EABKID:      s.ACMEEABKID,
		EABHMACKey:  s.ACMEEABHMACKey,
		LockMethod:  s.CertLockMethod,
		WildcardDir: s.WildcardCertDir,
	}, s, s.Logger, s.meter)
	if err != nil {
		return nil, fmt.Errorf("create ACME manager: %w", err)
	}

	go s.acme.WatchWildcards(ctx)

	if s.ACMEChallengeType == "http-01" {
		s.http = &http.Server{
			Addr:     s.ACMEChallengeAddress,
			Handler:  s.acme.HTTPHandler(nil),
			ErrorLog: newHTTPServerLogger(s.Logger, logtagValueACME),
		}
		go func() {
			if err := s.http.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				s.Logger.WithError(err).Error("ACME HTTP-01 challenge server failed")
			}
		}()
	}
	tlsConfig = s.acme.TLSConfig()

	// autocert.Manager.TLSConfig() wires its own GetCertificate, which
	// bypasses our override that checks wildcards first.
	tlsConfig.GetCertificate = s.acme.GetCertificate

	// ServerName needs to be set to allow for ACME to work correctly
	// when using CNAME URLs to access the proxy.
	tlsConfig.ServerName = s.ProxyURL

	s.Logger.WithFields(log.Fields{
		"ServerName":     s.ProxyURL,
		"challenge_type": s.ACMEChallengeType,
	}).Debug("ACME certificate manager configured")
	return tlsConfig, nil
}

// gracefulShutdown performs a zero-downtime shutdown sequence. It marks the
// readiness probe as failing, waits for load balancer propagation, drains
// in-flight connections, and then stops all background services.
func (s *Server) gracefulShutdown() {
	s.Logger.Info("shutdown signal received, starting graceful shutdown")

	// Step 1: Fail readiness probe so load balancers stop routing new traffic.
	if s.healthChecker != nil {
		s.healthChecker.SetShuttingDown()
	}

	// Step 2: When running behind a load balancer, wait for endpoint removal
	// to propagate before draining connections.
	if k8s.InCluster() {
		s.Logger.Infof("waiting %s for load balancer propagation", shutdownPreStopDelay)
		time.Sleep(shutdownPreStopDelay)
	}

	// Step 3: Stop accepting new connections and drain in-flight requests.
	drainCtx, drainCancel := context.WithTimeout(context.Background(), shutdownDrainTimeout)
	defer drainCancel()

	s.Logger.Info("draining in-flight connections")
	if err := s.https.Shutdown(drainCtx); err != nil {
		s.Logger.Warnf("https server drain: %v", err)
	}

	// Step 4: Close hijacked connections (WebSocket) that Shutdown does not handle.
	if n := s.hijackTracker.CloseAll(); n > 0 {
		s.Logger.Infof("closed %d hijacked connection(s)", n)
	}

	// Drain all router relay connections (main + per-port) in parallel.
	s.drainAllRouters(shutdownDrainTimeout)

	// Step 5: Stop all remaining background services.
	s.shutdownServices()
	s.Logger.Info("graceful shutdown complete")
}

// shutdownServices stops all background services concurrently and waits for
// them to finish.
// drainAllRouters drains active relay connections on the main router and
// all per-port routers in parallel, up to the given timeout.
func (s *Server) drainAllRouters(timeout time.Duration) {
	var wg sync.WaitGroup

	drain := func(name string, router *nbtcp.Router) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if ok := router.Drain(timeout); !ok {
				s.Logger.Warnf("timed out draining %s relay connections", name)
			}
		}()
	}

	if s.mainRouter != nil {
		drain("main router", s.mainRouter)
	}

	s.portMu.RLock()
	for port, pr := range s.portRouters {
		drain(fmt.Sprintf("port %d", port), pr.router)
	}
	s.portMu.RUnlock()

	wg.Wait()
}

func (s *Server) shutdownServices() {
	var wg sync.WaitGroup

	shutdownHTTP := func(name string, shutdown func(context.Context) error) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), shutdownServiceTimeout)
			defer cancel()
			if err := shutdown(ctx); err != nil {
				s.Logger.Debugf("%s shutdown: %v", name, err)
			}
		}()
	}

	if s.healthServer != nil {
		shutdownHTTP("health probe", s.healthServer.Shutdown)
	}
	if s.debug != nil {
		shutdownHTTP("debug endpoint", s.debug.Shutdown)
	}
	if s.http != nil {
		shutdownHTTP("acme http", s.http.Shutdown)
	}

	if s.netbird != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), shutdownDrainTimeout)
			defer cancel()
			if err := s.netbird.StopAll(ctx); err != nil {
				s.Logger.Warnf("stop netbird clients: %v", err)
			}
		}()
	}

	// Close all UDP relays and wait for their goroutines to exit.
	s.udpMu.Lock()
	for id, relay := range s.udpRelays {
		relay.Close()
		delete(s.udpRelays, id)
	}
	s.udpMu.Unlock()
	s.udpRelayWg.Wait()

	// Close all per-port routers.
	s.portMu.Lock()
	for port, pr := range s.portRouters {
		pr.cancel()
		if err := pr.listener.Close(); err != nil {
			s.Logger.Debugf("close listener on port %d: %v", port, err)
		}
		delete(s.portRouters, port)
	}
	maps.Clear(s.svcPorts)
	maps.Clear(s.lastMappings)
	s.portMu.Unlock()

	// Wait for per-port router serve goroutines to exit.
	s.portRouterWg.Wait()

	wg.Wait()

	if s.accessLog != nil {
		s.accessLog.Close()
	}

	if s.geoRaw != nil {
		if err := s.geoRaw.Close(); err != nil {
			s.Logger.Debugf("close geolocation: %v", err)
		}
	}

	s.shutdownCrowdSec()
}

func (s *Server) shutdownCrowdSec() {
	if s.crowdsecRegistry == nil {
		return
	}
	s.crowdsecMu.Lock()
	services := maps.Clone(s.crowdsecServices)
	maps.Clear(s.crowdsecServices)
	s.crowdsecMu.Unlock()

	for svcID := range services {
		s.crowdsecRegistry.Release(svcID)
	}
}

// resolveDialFunc returns a DialContextFunc that dials through the
// NetBird tunnel for the given account.
func (s *Server) resolveDialFunc(accountID types.AccountID) (types.DialContextFunc, error) {
	client, ok := s.netbird.GetClient(accountID)
	if !ok {
		return nil, fmt.Errorf("no client for account %s", accountID)
	}
	return client.DialContext, nil
}

// notifyError reports a resource error back to management so it can be
// surfaced to the user (e.g. port bind failure, dialer resolution error).
func (s *Server) notifyError(ctx context.Context, mapping *proto.ProxyMapping, err error) {
	s.sendStatusUpdate(ctx, types.AccountID(mapping.GetAccountId()), types.ServiceID(mapping.GetId()), proto.ProxyStatus_PROXY_STATUS_ERROR, err)
}

// sendStatusUpdate sends a status update for a service to management.
func (s *Server) sendStatusUpdate(ctx context.Context, accountID types.AccountID, serviceID types.ServiceID, st proto.ProxyStatus, err error) {
	req := &proto.SendStatusUpdateRequest{
		ServiceId: string(serviceID),
		AccountId: string(accountID),
		Status:    st,
	}
	if err != nil {
		msg := err.Error()
		req.ErrorMessage = &msg
	}
	if _, sendErr := s.mgmtClient.SendStatusUpdate(ctx, req); sendErr != nil {
		s.Logger.Debugf("failed to send status update for %s: %v", serviceID, sendErr)
	}
}

// routerForPort returns the router that handles the given listen port. If port
// is 0 or matches the main listener port, the main router is returned.
// Otherwise a new per-port router is created and started.
func (s *Server) routerForPort(ctx context.Context, port uint16) (*nbtcp.Router, error) {
	if port == 0 || port == s.mainPort {
		return s.mainRouter, nil
	}
	return s.getOrCreatePortRouter(ctx, port)
}

// routerForPortExisting returns the router for the given port without creating
// one. Returns the main router for port 0 / mainPort, or nil if no per-port
// router exists.
func (s *Server) routerForPortExisting(port uint16) *nbtcp.Router {
	if port == 0 || port == s.mainPort {
		return s.mainRouter
	}
	s.portMu.RLock()
	pr := s.portRouters[port]
	s.portMu.RUnlock()
	if pr != nil {
		return pr.router
	}
	return nil
}

// getOrCreatePortRouter returns an existing per-port router or creates one
// with a new TCP listener and starts serving.
func (s *Server) getOrCreatePortRouter(ctx context.Context, port uint16) (*nbtcp.Router, error) {
	s.portMu.Lock()
	defer s.portMu.Unlock()

	if pr, ok := s.portRouters[port]; ok {
		return pr.router, nil
	}

	listenAddr := fmt.Sprintf(":%d", port)
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return nil, fmt.Errorf("listen TCP on %s: %w", listenAddr, err)
	}
	if s.ProxyProtocol {
		ln = s.wrapProxyProtocol(ln)
	}

	router := nbtcp.NewPortRouter(s.Logger, s.resolveDialFunc)
	router.SetObserver(s.meter)
	router.SetAccessLogger(s.accessLog)
	portCtx, cancel := context.WithCancel(ctx)

	s.portRouters[port] = &portRouter{
		router:   router,
		listener: ln,
		cancel:   cancel,
	}

	s.portRouterWg.Add(1)
	go func() {
		defer s.portRouterWg.Done()
		if err := router.Serve(portCtx, ln); err != nil {
			s.Logger.Debugf("port %d router stopped: %v", port, err)
		}
	}()

	s.Logger.Debugf("started per-port router on %s", listenAddr)
	return router, nil
}

// cleanupPortIfEmpty tears down a per-port router if it has no remaining
// routes or fallback. The main port is never cleaned up. Active relay
// connections are drained before the listener is closed.
func (s *Server) cleanupPortIfEmpty(port uint16) {
	if port == 0 || port == s.mainPort {
		return
	}

	s.portMu.Lock()
	pr, ok := s.portRouters[port]
	if !ok || !pr.router.IsEmpty() {
		s.portMu.Unlock()
		return
	}

	// Cancel and close the listener while holding the lock so that
	// getOrCreatePortRouter sees the entry is gone before we drain.
	pr.cancel()
	if err := pr.listener.Close(); err != nil {
		s.Logger.Debugf("close listener on port %d: %v", port, err)
	}
	delete(s.portRouters, port)
	s.portMu.Unlock()

	// Drain active relay connections outside the lock.
	if ok := pr.router.Drain(nbtcp.DefaultDrainTimeout); !ok {
		s.Logger.Warnf("timed out draining relay connections on port %d", port)
	}
	s.Logger.Debugf("cleaned up empty per-port router on port %d", port)
}

func (s *Server) newManagementMappingWorker(ctx context.Context, client proto.ProxyServiceClient) {
	bo := &backoff.ExponentialBackOff{
		InitialInterval:     800 * time.Millisecond,
		RandomizationFactor: 1,
		Multiplier:          1.7,
		MaxInterval:         10 * time.Second,
		MaxElapsedTime:      0, // retry indefinitely until context is canceled
		Stop:                backoff.Stop,
		Clock:               backoff.SystemClock,
	}

	initialSyncDone := false

	operation := func() error {
		s.Logger.Debug("connecting to management mapping stream")

		initialSyncDone = false

		if s.healthChecker != nil {
			s.healthChecker.SetManagementConnected(false)
		}

		supportsCrowdSec := s.crowdsecRegistry.Available()
		mappingClient, err := client.GetMappingUpdate(ctx, &proto.GetMappingUpdateRequest{
			ProxyId:   s.ID,
			Version:   s.Version,
			StartedAt: timestamppb.New(s.startTime),
			Address:   s.ProxyURL,
			Capabilities: &proto.ProxyCapabilities{
				SupportsCustomPorts: &s.SupportsCustomPorts,
				RequireSubdomain:    &s.RequireSubdomain,
				SupportsCrowdsec:    &supportsCrowdSec,
			},
		})
		if err != nil {
			return fmt.Errorf("create mapping stream: %w", err)
		}

		if s.healthChecker != nil {
			s.healthChecker.SetManagementConnected(true)
		}
		s.Logger.Debug("management mapping stream established")

		// Stream established — reset backoff so the next failure retries quickly.
		bo.Reset()

		streamErr := s.handleMappingStream(ctx, mappingClient, &initialSyncDone)

		if s.healthChecker != nil {
			s.healthChecker.SetManagementConnected(false)
		}

		if streamErr == nil {
			return fmt.Errorf("stream closed by server")
		}

		return fmt.Errorf("mapping stream: %w", streamErr)
	}

	notify := func(err error, next time.Duration) {
		s.Logger.Warnf("management connection failed, retrying in %s: %v", next.Truncate(time.Millisecond), err)
	}

	if err := backoff.RetryNotify(operation, backoff.WithContext(bo, ctx), notify); err != nil {
		s.Logger.WithError(err).Debug("management mapping worker exiting")
	}
}

func (s *Server) handleMappingStream(ctx context.Context, mappingClient proto.ProxyService_GetMappingUpdateClient, initialSyncDone *bool) error {
	select {
	case <-s.routerReady:
	case <-ctx.Done():
		return ctx.Err()
	}

	var snapshotIDs map[types.ServiceID]struct{}
	if !*initialSyncDone {
		snapshotIDs = make(map[types.ServiceID]struct{})
	}

	for {
		// Check for context completion to gracefully shutdown.
		select {
		case <-ctx.Done():
			// Shutting down.
			return ctx.Err()
		default:
			msg, err := mappingClient.Recv()
			switch {
			case errors.Is(err, io.EOF):
				// Mapping connection gracefully terminated by server.
				return nil
			case err != nil:
				// Something has gone horribly wrong, return and hope the parent retries the connection.
				return fmt.Errorf("receive msg: %w", err)
			}
			s.Logger.Debug("Received mapping update, starting processing")
			s.processMappings(ctx, msg.GetMapping())
			s.Logger.Debug("Processing mapping update completed")

			if !*initialSyncDone {
				for _, m := range msg.GetMapping() {
					snapshotIDs[types.ServiceID(m.GetId())] = struct{}{}
				}
				if msg.GetInitialSyncComplete() {
					s.reconcileSnapshot(ctx, snapshotIDs)
					snapshotIDs = nil
					if s.healthChecker != nil {
						s.healthChecker.SetInitialSyncComplete()
					}
					*initialSyncDone = true
					s.Logger.Info("Initial mapping sync complete")
				}
			}
		}
	}
}

// reconcileSnapshot removes local mappings that are absent from the snapshot.
// This ensures services deleted while the proxy was disconnected get cleaned up.
func (s *Server) reconcileSnapshot(ctx context.Context, snapshotIDs map[types.ServiceID]struct{}) {
	s.portMu.RLock()
	var stale []*proto.ProxyMapping
	for svcID, mapping := range s.lastMappings {
		if _, ok := snapshotIDs[svcID]; !ok {
			stale = append(stale, mapping)
		}
	}
	s.portMu.RUnlock()

	for _, mapping := range stale {
		s.Logger.WithFields(log.Fields{
			"service_id": mapping.GetId(),
			"domain":     mapping.GetDomain(),
		}).Info("Removing stale mapping absent from snapshot")
		s.removeMapping(ctx, mapping)
	}
}

func (s *Server) processMappings(ctx context.Context, mappings []*proto.ProxyMapping) {
	for _, mapping := range mappings {
		s.Logger.WithFields(log.Fields{
			"type":   mapping.GetType(),
			"domain": mapping.GetDomain(),
			"mode":   mapping.GetMode(),
			"port":   mapping.GetListenPort(),
			"id":     mapping.GetId(),
		}).Debug("Processing mapping update")
		switch mapping.GetType() {
		case proto.ProxyMappingUpdateType_UPDATE_TYPE_CREATED:
			if err := s.addMapping(ctx, mapping); err != nil {
				s.Logger.WithFields(log.Fields{
					"service_id": mapping.GetId(),
					"domain":     mapping.GetDomain(),
					"error":      err,
				}).Error("Error adding new mapping, ignoring this mapping and continuing processing")
				s.notifyError(ctx, mapping, err)
			}
		case proto.ProxyMappingUpdateType_UPDATE_TYPE_MODIFIED:
			if err := s.modifyMapping(ctx, mapping); err != nil {
				s.Logger.WithFields(log.Fields{
					"service_id": mapping.GetId(),
					"domain":     mapping.GetDomain(),
					"error":      err,
				}).Error("failed to modify mapping")
				s.notifyError(ctx, mapping, err)
			}
		case proto.ProxyMappingUpdateType_UPDATE_TYPE_REMOVED:
			s.removeMapping(ctx, mapping)
		}
	}
}

// addMapping registers a service mapping and starts the appropriate relay or routes.
func (s *Server) addMapping(ctx context.Context, mapping *proto.ProxyMapping) error {
	accountID := types.AccountID(mapping.GetAccountId())
	svcID := types.ServiceID(mapping.GetId())
	authToken := mapping.GetAuthToken()

	svcKey := s.serviceKeyForMapping(mapping)
	if err := s.netbird.AddPeer(ctx, accountID, svcKey, authToken, svcID); err != nil {
		return fmt.Errorf("create peer for service %s: %w", svcID, err)
	}

	if err := s.setupMappingRoutes(ctx, mapping); err != nil {
		s.cleanupMappingRoutes(mapping)
		if peerErr := s.netbird.RemovePeer(ctx, accountID, svcKey); peerErr != nil {
			s.Logger.WithError(peerErr).WithField("service_id", svcID).Warn("failed to remove peer after setup failure")
		}
		return err
	}
	s.storeMapping(mapping)
	return nil
}

// modifyMapping updates a service mapping in place without tearing down the
// NetBird peer. It cleans up old routes using the previously stored mapping
// state and re-applies them from the new mapping.
func (s *Server) modifyMapping(ctx context.Context, mapping *proto.ProxyMapping) error {
	if old := s.loadMapping(types.ServiceID(mapping.GetId())); old != nil {
		s.cleanupMappingRoutes(old)
		if mode := types.ServiceMode(old.GetMode()); mode.IsL4() {
			s.meter.L4ServiceRemoved(mode)
		}
	} else {
		s.cleanupMappingRoutes(mapping)
	}
	if err := s.setupMappingRoutes(ctx, mapping); err != nil {
		s.cleanupMappingRoutes(mapping)
		return err
	}
	s.storeMapping(mapping)
	return nil
}

// setupMappingRoutes configures the appropriate routes or relays for the given
// service mapping based on its mode. The NetBird peer must already exist.
func (s *Server) setupMappingRoutes(ctx context.Context, mapping *proto.ProxyMapping) error {
	switch types.ServiceMode(mapping.GetMode()) {
	case types.ServiceModeTCP:
		return s.setupTCPMapping(ctx, mapping)
	case types.ServiceModeUDP:
		return s.setupUDPMapping(ctx, mapping)
	case types.ServiceModeTLS:
		return s.setupTLSMapping(ctx, mapping)
	default:
		return s.setupHTTPMapping(ctx, mapping)
	}
}

// setupHTTPMapping configures HTTP reverse proxy, auth, and ACME routes.
func (s *Server) setupHTTPMapping(ctx context.Context, mapping *proto.ProxyMapping) error {
	d := domain.Domain(mapping.GetDomain())
	accountID := types.AccountID(mapping.GetAccountId())
	svcID := types.ServiceID(mapping.GetId())

	if len(mapping.GetPath()) == 0 {
		return nil
	}

	var wildcardHit bool
	if s.acme != nil {
		wildcardHit = s.acme.AddDomain(d, accountID, svcID)
	}
	s.mainRouter.AddRoute(nbtcp.SNIHost(mapping.GetDomain()), nbtcp.Route{
		Type:      nbtcp.RouteHTTP,
		AccountID: accountID,
		ServiceID: svcID,
		Domain:    mapping.GetDomain(),
	})
	if err := s.updateMapping(ctx, mapping); err != nil {
		return fmt.Errorf("update mapping for domain %q: %w", d, err)
	}

	if wildcardHit {
		if err := s.NotifyCertificateIssued(ctx, accountID, svcID, string(d)); err != nil {
			s.Logger.Warnf("notify certificate ready for domain %q: %v", d, err)
		}
	}

	return nil
}

// setupTCPMapping sets up a TCP port-forwarding fallback route on the listen port.
func (s *Server) setupTCPMapping(ctx context.Context, mapping *proto.ProxyMapping) error {
	svcID := types.ServiceID(mapping.GetId())
	accountID := types.AccountID(mapping.GetAccountId())

	port, err := netutil.ValidatePort(mapping.GetListenPort())
	if err != nil {
		return fmt.Errorf("TCP service %s: %w", svcID, err)
	}

	targetAddr := s.l4TargetAddress(mapping)
	if targetAddr == "" {
		return fmt.Errorf("empty target address for TCP service %s", svcID)
	}

	if s.WireguardPort != 0 && port == s.WireguardPort {
		return fmt.Errorf("port %d conflicts with tunnel port", port)
	}

	router, err := s.routerForPort(ctx, port)
	if err != nil {
		return fmt.Errorf("router for TCP port %d: %w", port, err)
	}

	s.warnIfGeoUnavailable(mapping.GetDomain(), mapping.GetAccessRestrictions())

	router.SetGeo(s.geo)
	router.SetFallback(nbtcp.Route{
		Type:               nbtcp.RouteTCP,
		AccountID:          accountID,
		ServiceID:          svcID,
		Domain:             mapping.GetDomain(),
		Protocol:           accesslog.ProtocolTCP,
		Target:             targetAddr,
		ProxyProtocol:      s.l4ProxyProtocol(mapping),
		DialTimeout:        s.l4DialTimeout(mapping),
		SessionIdleTimeout: s.clampIdleTimeout(l4SessionIdleTimeout(mapping)),
		Filter:             s.parseRestrictions(mapping),
	})

	s.portMu.Lock()
	s.svcPorts[svcID] = []uint16{port}
	s.portMu.Unlock()

	s.meter.L4ServiceAdded(types.ServiceModeTCP)
	s.sendStatusUpdate(ctx, accountID, svcID, proto.ProxyStatus_PROXY_STATUS_ACTIVE, nil)
	return nil
}

// setupUDPMapping starts a UDP relay on the listen port.
func (s *Server) setupUDPMapping(ctx context.Context, mapping *proto.ProxyMapping) error {
	svcID := types.ServiceID(mapping.GetId())
	accountID := types.AccountID(mapping.GetAccountId())

	port, err := netutil.ValidatePort(mapping.GetListenPort())
	if err != nil {
		return fmt.Errorf("UDP service %s: %w", svcID, err)
	}

	targetAddr := s.l4TargetAddress(mapping)
	if targetAddr == "" {
		return fmt.Errorf("empty target address for UDP service %s", svcID)
	}

	s.warnIfGeoUnavailable(mapping.GetDomain(), mapping.GetAccessRestrictions())

	if err := s.addUDPRelay(ctx, mapping, targetAddr, port); err != nil {
		return fmt.Errorf("UDP relay for service %s: %w", svcID, err)
	}

	s.meter.L4ServiceAdded(types.ServiceModeUDP)
	s.sendStatusUpdate(ctx, accountID, svcID, proto.ProxyStatus_PROXY_STATUS_ACTIVE, nil)
	return nil
}

// setupTLSMapping configures a TLS SNI-routed passthrough on the listen port.
func (s *Server) setupTLSMapping(ctx context.Context, mapping *proto.ProxyMapping) error {
	svcID := types.ServiceID(mapping.GetId())
	accountID := types.AccountID(mapping.GetAccountId())

	tlsPort, err := netutil.ValidatePort(mapping.GetListenPort())
	if err != nil {
		return fmt.Errorf("TLS service %s: %w", svcID, err)
	}

	targetAddr := s.l4TargetAddress(mapping)
	if targetAddr == "" {
		return fmt.Errorf("empty target address for TLS service %s", svcID)
	}

	if s.WireguardPort != 0 && tlsPort == s.WireguardPort {
		return fmt.Errorf("port %d conflicts with tunnel port", tlsPort)
	}

	router, err := s.routerForPort(ctx, tlsPort)
	if err != nil {
		return fmt.Errorf("router for TLS port %d: %w", tlsPort, err)
	}

	s.warnIfGeoUnavailable(mapping.GetDomain(), mapping.GetAccessRestrictions())

	router.SetGeo(s.geo)
	router.AddRoute(nbtcp.SNIHost(mapping.GetDomain()), nbtcp.Route{
		Type:               nbtcp.RouteTCP,
		AccountID:          accountID,
		ServiceID:          svcID,
		Domain:             mapping.GetDomain(),
		Protocol:           accesslog.ProtocolTLS,
		Target:             targetAddr,
		ProxyProtocol:      s.l4ProxyProtocol(mapping),
		DialTimeout:        s.l4DialTimeout(mapping),
		SessionIdleTimeout: s.clampIdleTimeout(l4SessionIdleTimeout(mapping)),
		Filter:             s.parseRestrictions(mapping),
	})

	if tlsPort != s.mainPort {
		s.portMu.Lock()
		s.svcPorts[svcID] = []uint16{tlsPort}
		s.portMu.Unlock()
	}

	s.Logger.WithFields(log.Fields{
		"domain":  mapping.GetDomain(),
		"target":  targetAddr,
		"port":    tlsPort,
		"service": svcID,
	}).Info("TLS passthrough mapping added")

	s.meter.L4ServiceAdded(types.ServiceModeTLS)
	s.sendStatusUpdate(ctx, accountID, svcID, proto.ProxyStatus_PROXY_STATUS_ACTIVE, nil)
	return nil
}

// serviceKeyForMapping returns the appropriate ServiceKey for a mapping.
// TCP/UDP use an ID-based key; HTTP/TLS use a domain-based key.
func (s *Server) serviceKeyForMapping(mapping *proto.ProxyMapping) roundtrip.ServiceKey {
	switch types.ServiceMode(mapping.GetMode()) {
	case types.ServiceModeTCP, types.ServiceModeUDP:
		return roundtrip.L4ServiceKey(types.ServiceID(mapping.GetId()))
	default:
		return roundtrip.DomainServiceKey(mapping.GetDomain())
	}
}

// parseRestrictions converts a proto mapping's access restrictions into
// a restrict.Filter. Returns nil if the mapping has no restrictions.
func (s *Server) parseRestrictions(mapping *proto.ProxyMapping) *restrict.Filter {
	r := mapping.GetAccessRestrictions()
	if r == nil {
		return nil
	}

	svcID := types.ServiceID(mapping.GetId())
	csMode := restrict.CrowdSecMode(r.GetCrowdsecMode())

	var checker restrict.CrowdSecChecker
	if csMode == restrict.CrowdSecEnforce || csMode == restrict.CrowdSecObserve {
		if b := s.crowdsecRegistry.Acquire(svcID); b != nil {
			checker = b
			s.crowdsecMu.Lock()
			s.crowdsecServices[svcID] = true
			s.crowdsecMu.Unlock()
		} else {
			s.Logger.Warnf("service %s requests CrowdSec mode %q but proxy has no CrowdSec configured", svcID, csMode)
			// Keep the mode: restrict.Filter will fail-closed for enforce (DenyCrowdSecUnavailable)
			// and allow for observe.
		}
	}

	return restrict.ParseFilter(restrict.FilterConfig{
		AllowedCIDRs:     r.GetAllowedCidrs(),
		BlockedCIDRs:     r.GetBlockedCidrs(),
		AllowedCountries: r.GetAllowedCountries(),
		BlockedCountries: r.GetBlockedCountries(),
		CrowdSec:         checker,
		CrowdSecMode:     csMode,
		Logger:           log.NewEntry(s.Logger),
	})
}

// releaseCrowdSec releases the CrowdSec bouncer reference for the given
// service if it had one.
func (s *Server) releaseCrowdSec(svcID types.ServiceID) {
	s.crowdsecMu.Lock()
	had := s.crowdsecServices[svcID]
	delete(s.crowdsecServices, svcID)
	s.crowdsecMu.Unlock()

	if had {
		s.crowdsecRegistry.Release(svcID)
	}
}

// warnIfGeoUnavailable logs a warning if the mapping has country restrictions
// but the proxy has no geolocation database loaded. All requests to this
// service will be denied at runtime (fail-close).
func (s *Server) warnIfGeoUnavailable(domain string, r *proto.AccessRestrictions) {
	if r == nil {
		return
	}
	if len(r.GetAllowedCountries()) == 0 && len(r.GetBlockedCountries()) == 0 {
		return
	}
	if s.geo != nil && s.geo.Available() {
		return
	}
	s.Logger.Warnf("service %s has country restrictions but no geolocation database is loaded: all requests will be denied", domain)
}

// l4TargetAddress extracts and validates the target address from a mapping's
// first path entry. Returns empty string if no paths exist or the address is
// not a valid host:port.
func (s *Server) l4TargetAddress(mapping *proto.ProxyMapping) string {
	paths := mapping.GetPath()
	if len(paths) == 0 {
		return ""
	}
	target := paths[0].GetTarget()
	if _, _, err := net.SplitHostPort(target); err != nil {
		s.Logger.WithFields(log.Fields{
			"service_id": mapping.GetId(),
			"target":     target,
		}).Warnf("invalid L4 target address: %v", err)
		return ""
	}
	return target
}

// l4ProxyProtocol returns whether the first target has PROXY protocol enabled.
func (s *Server) l4ProxyProtocol(mapping *proto.ProxyMapping) bool {
	paths := mapping.GetPath()
	if len(paths) == 0 {
		return false
	}
	return paths[0].GetOptions().GetProxyProtocol()
}

// l4DialTimeout returns the dial timeout from the first target's options,
// clamped to MaxDialTimeout.
func (s *Server) l4DialTimeout(mapping *proto.ProxyMapping) time.Duration {
	paths := mapping.GetPath()
	if len(paths) > 0 {
		if d := paths[0].GetOptions().GetRequestTimeout(); d != nil {
			return s.clampDialTimeout(d.AsDuration())
		}
	}
	return s.clampDialTimeout(0)
}

// l4SessionIdleTimeout returns the configured session idle timeout from the
// mapping options, or 0 to use the relay's default.
func l4SessionIdleTimeout(mapping *proto.ProxyMapping) time.Duration {
	paths := mapping.GetPath()
	if len(paths) > 0 {
		if d := paths[0].GetOptions().GetSessionIdleTimeout(); d != nil {
			return d.AsDuration()
		}
	}
	return 0
}

// addUDPRelay starts a UDP relay on the specified listen port.
func (s *Server) addUDPRelay(ctx context.Context, mapping *proto.ProxyMapping, targetAddress string, listenPort uint16) error {
	svcID := types.ServiceID(mapping.GetId())
	accountID := types.AccountID(mapping.GetAccountId())

	if s.WireguardPort != 0 && listenPort == s.WireguardPort {
		return fmt.Errorf("UDP port %d conflicts with tunnel port", listenPort)
	}

	// Close existing relay if present (idempotent re-add).
	s.removeUDPRelay(svcID)

	listenAddr := fmt.Sprintf(":%d", listenPort)

	listener, err := net.ListenPacket("udp", listenAddr)
	if err != nil {
		return fmt.Errorf("listen UDP on %s: %w", listenAddr, err)
	}

	dialFn, err := s.resolveDialFunc(accountID)
	if err != nil {
		if err := listener.Close(); err != nil {
			s.Logger.Debugf("close UDP listener on %s: %v", listenAddr, err)
		}
		return fmt.Errorf("resolve dialer for UDP: %w", err)
	}

	entry := s.Logger.WithFields(log.Fields{
		"target":      targetAddress,
		"listen_port": listenPort,
		"service_id":  svcID,
	})

	relay := udprelay.New(ctx, udprelay.RelayConfig{
		Logger:      entry,
		Listener:    listener,
		Target:      targetAddress,
		Domain:      mapping.GetDomain(),
		AccountID:   accountID,
		ServiceID:   svcID,
		DialFunc:    dialFn,
		DialTimeout: s.l4DialTimeout(mapping),
		SessionTTL:  s.clampIdleTimeout(l4SessionIdleTimeout(mapping)),
		AccessLog:   s.accessLog,
		Filter:      s.parseRestrictions(mapping),
		Geo:         s.geo,
	})
	relay.SetObserver(s.meter)

	s.udpMu.Lock()
	s.udpRelays[svcID] = relay
	s.udpMu.Unlock()

	s.udpRelayWg.Go(relay.Serve)
	entry.Info("UDP relay added")
	return nil
}

func (s *Server) updateMapping(ctx context.Context, mapping *proto.ProxyMapping) error {
	// Very simple implementation here, we don't touch the existing peer
	// connection or any existing TLS configuration, we simply overwrite
	// the auth and proxy mappings.
	// Note: this does require the management server to always send a
	// full mapping rather than deltas during a modification.
	accountID := types.AccountID(mapping.GetAccountId())
	svcID := types.ServiceID(mapping.GetId())

	var schemes []auth.Scheme
	if mapping.GetAuth().GetPassword() {
		schemes = append(schemes, auth.NewPassword(s.mgmtClient, svcID, accountID))
	}
	if mapping.GetAuth().GetPin() {
		schemes = append(schemes, auth.NewPin(s.mgmtClient, svcID, accountID))
	}
	if mapping.GetAuth().GetOidc() {
		schemes = append(schemes, auth.NewOIDC(s.mgmtClient, svcID, accountID, s.ForwardedProto))
	}
	for _, ha := range mapping.GetAuth().GetHeaderAuths() {
		schemes = append(schemes, auth.NewHeader(s.mgmtClient, svcID, accountID, ha.GetHeader()))
	}

	ipRestrictions := s.parseRestrictions(mapping)
	s.warnIfGeoUnavailable(mapping.GetDomain(), mapping.GetAccessRestrictions())

	maxSessionAge := time.Duration(mapping.GetAuth().GetMaxSessionAgeSeconds()) * time.Second
	if err := s.auth.AddDomain(mapping.GetDomain(), schemes, mapping.GetAuth().GetSessionKey(), maxSessionAge, accountID, svcID, ipRestrictions); err != nil {
		return fmt.Errorf("auth setup for domain %s: %w", mapping.GetDomain(), err)
	}
	m := s.protoToMapping(ctx, mapping)
	s.proxy.AddMapping(m)
	s.meter.AddMapping(m)
	return nil
}

// removeMapping tears down routes/relays and the NetBird peer for a service.
// Uses the stored mapping state when available to ensure all previously
// configured routes are cleaned up.
func (s *Server) removeMapping(ctx context.Context, mapping *proto.ProxyMapping) {
	accountID := types.AccountID(mapping.GetAccountId())
	svcKey := s.serviceKeyForMapping(mapping)
	if err := s.netbird.RemovePeer(ctx, accountID, svcKey); err != nil {
		s.Logger.WithFields(log.Fields{
			"account_id": accountID,
			"service_id": mapping.GetId(),
			"error":      err,
		}).Error("failed to remove NetBird peer, continuing cleanup")
	}

	if old := s.deleteMapping(types.ServiceID(mapping.GetId())); old != nil {
		s.cleanupMappingRoutes(old)
		if mode := types.ServiceMode(old.GetMode()); mode.IsL4() {
			s.meter.L4ServiceRemoved(mode)
		}
	} else {
		s.cleanupMappingRoutes(mapping)
	}
}

// cleanupMappingRoutes removes HTTP/TLS/L4 routes and custom port state for a
// service without touching the NetBird peer. This is used for both full
// removal and in-place modification of mappings.
func (s *Server) cleanupMappingRoutes(mapping *proto.ProxyMapping) {
	svcID := types.ServiceID(mapping.GetId())
	host := mapping.GetDomain()

	// HTTP/TLS cleanup (only relevant when a domain is set).
	if host != "" {
		d := domain.Domain(host)
		if s.acme != nil {
			s.acme.RemoveDomain(d)
		}
		s.auth.RemoveDomain(host)
		if s.proxy.RemoveMapping(proxy.Mapping{Host: host}) {
			s.meter.RemoveMapping(proxy.Mapping{Host: host})
		}
		// Close hijacked connections (WebSocket) for this domain.
		if n := s.hijackTracker.CloseByHost(host); n > 0 {
			s.Logger.Debugf("closed %d hijacked connection(s) for %s", n, host)
		}
		// Remove SNI route from the main router (covers both HTTP and main-port TLS).
		s.mainRouter.RemoveRoute(nbtcp.SNIHost(host), svcID)
	}

	// Extract and delete tracked custom-port entries atomically.
	s.portMu.Lock()
	entries := s.svcPorts[svcID]
	delete(s.svcPorts, svcID)
	s.portMu.Unlock()

	for _, entry := range entries {
		if router := s.routerForPortExisting(entry); router != nil {
			if host != "" {
				router.RemoveRoute(nbtcp.SNIHost(host), svcID)
			} else {
				router.RemoveFallback(svcID)
			}
		}
		s.cleanupPortIfEmpty(entry)
	}

	// UDP relay cleanup (idempotent).
	s.removeUDPRelay(svcID)

	// Release CrowdSec after all routes are removed so the shared bouncer
	// isn't stopped while stale filters can still be reached by in-flight requests.
	s.releaseCrowdSec(svcID)
}

// removeUDPRelay stops and removes a UDP relay by service ID.
func (s *Server) removeUDPRelay(svcID types.ServiceID) {
	s.udpMu.Lock()
	relay, ok := s.udpRelays[svcID]
	if ok {
		delete(s.udpRelays, svcID)
	}
	s.udpMu.Unlock()

	if ok {
		relay.Close()
		s.Logger.WithField("service_id", svcID).Info("UDP relay removed")
	}
}

func (s *Server) storeMapping(mapping *proto.ProxyMapping) {
	s.portMu.Lock()
	s.lastMappings[types.ServiceID(mapping.GetId())] = mapping
	s.portMu.Unlock()
}

func (s *Server) loadMapping(svcID types.ServiceID) *proto.ProxyMapping {
	s.portMu.RLock()
	m := s.lastMappings[svcID]
	s.portMu.RUnlock()
	return m
}

func (s *Server) deleteMapping(svcID types.ServiceID) *proto.ProxyMapping {
	s.portMu.Lock()
	m := s.lastMappings[svcID]
	delete(s.lastMappings, svcID)
	s.portMu.Unlock()
	return m
}

func (s *Server) protoToMapping(ctx context.Context, mapping *proto.ProxyMapping) proxy.Mapping {
	paths := make(map[string]*proxy.PathTarget)
	for _, pathMapping := range mapping.GetPath() {
		targetURL, err := url.Parse(pathMapping.GetTarget())
		if err != nil {
			s.Logger.WithFields(log.Fields{
				"service_id": mapping.GetId(),
				"account_id": mapping.GetAccountId(),
				"domain":     mapping.GetDomain(),
				"path":       pathMapping.GetPath(),
				"target":     pathMapping.GetTarget(),
			}).WithError(err).Error("failed to parse target URL for path, skipping")
			s.notifyError(ctx, mapping, fmt.Errorf("invalid target URL %q for path %q: %w", pathMapping.GetTarget(), pathMapping.GetPath(), err))
			continue
		}

		pt := &proxy.PathTarget{URL: targetURL}
		if opts := pathMapping.GetOptions(); opts != nil {
			pt.SkipTLSVerify = opts.GetSkipTlsVerify()
			pt.PathRewrite = protoToPathRewrite(opts.GetPathRewrite())
			pt.CustomHeaders = opts.GetCustomHeaders()
			if d := opts.GetRequestTimeout(); d != nil {
				pt.RequestTimeout = d.AsDuration()
			}
		}
		pt.RequestTimeout = s.clampDialTimeout(pt.RequestTimeout)
		paths[pathMapping.GetPath()] = pt
	}
	m := proxy.Mapping{
		ID:               types.ServiceID(mapping.GetId()),
		AccountID:        types.AccountID(mapping.GetAccountId()),
		Host:             mapping.GetDomain(),
		Paths:            paths,
		PassHostHeader:   mapping.GetPassHostHeader(),
		RewriteRedirects: mapping.GetRewriteRedirects(),
	}
	for _, ha := range mapping.GetAuth().GetHeaderAuths() {
		m.StripAuthHeaders = append(m.StripAuthHeaders, ha.GetHeader())
	}
	return m
}

func protoToPathRewrite(mode proto.PathRewriteMode) proxy.PathRewriteMode {
	switch mode {
	case proto.PathRewriteMode_PATH_REWRITE_PRESERVE:
		return proxy.PathRewritePreserve
	default:
		return proxy.PathRewriteDefault
	}
}

// debugEndpointAddr returns the address for the debug endpoint.
// If addr is empty, it defaults to localhost:8444 for security.
func debugEndpointAddr(addr string) string {
	if addr == "" {
		return defaultDebugAddr
	}
	return addr
}
