package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
	"github.com/soheilhy/cmux"
	"go.opentelemetry.io/otel/metric"
	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c" //nolint:staticcheck
	"google.golang.org/grpc"

	"github.com/netbirdio/netbird/encryption"
	nbconfig "github.com/netbirdio/netbird/management/internals/server/config"
	"github.com/netbirdio/netbird/management/server/idp"
	"github.com/netbirdio/netbird/management/server/metrics"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/util/wsproxy"
	wsproxyserver "github.com/netbirdio/netbird/util/wsproxy/server"
	"github.com/netbirdio/netbird/version"
)

const (
	// ManagementLegacyPort is the port that was used before by the Management gRPC server.
	// It is used for backward compatibility now.
	ManagementLegacyPort = 33073
	// DefaultSelfHostedDomain is the default domain used for self-hosted fresh installs.
	DefaultSelfHostedDomain = "netbird.selfhosted"

	ContainerKeyBaseServer = "baseServer"

	// NativeGRPCEnvVar enables serving gRPC on the native gRPC transport,
	// multiplexed with HTTP on the shared listener, instead of through the
	// net/http ServeHTTP path which costs two extra goroutines per stream.
	NativeGRPCEnvVar = "NB_MGMT_NATIVE_GRPC"
)

func nativeGRPCEnabled() bool {
	enabled, _ := strconv.ParseBool(os.Getenv(NativeGRPCEnvVar))
	return enabled
}

type Server interface {
	Start(ctx context.Context) error
	Stop() error
	Errors() <-chan error
	GetContainer(key string) (any, bool)
	SetContainer(key string, container any)
}

// BaseServer holds the HTTP server instance.
// Add any additional fields you need, such as database connections, Config, etc.
type BaseServer struct {
	// Config holds the server configuration
	Config *nbconfig.Config
	// container of dependencies, each dependency is identified by a unique string.
	container map[string]any
	// AfterInit is a function that will be called after the server is initialized
	afterInit []func(s *BaseServer)

	disableMetrics              bool
	dnsDomain                   string
	disableGeoliteUpdate        bool
	userDeleteFromIDPEnabled    bool
	mgmtSingleAccModeDomain     string
	mgmtMetricsPort             int
	mgmtPort                    int
	disableLegacyManagementPort bool
	autoResolveDomains          bool

	proxyAuthClose func()

	listener    net.Listener
	certManager *autocert.Manager
	update      *version.Update

	errCh  chan error
	wg     sync.WaitGroup
	cancel context.CancelFunc
}

// Config holds the configuration parameters for creating a new server
type Config struct {
	NbConfig                    *nbconfig.Config
	DNSDomain                   string
	MgmtSingleAccModeDomain     string
	MgmtPort                    int
	MgmtMetricsPort             int
	DisableLegacyManagementPort bool
	DisableMetrics              bool
	DisableGeoliteUpdate        bool
	UserDeleteFromIDPEnabled    bool
	AutoResolveDomains          bool
}

// NewServer initializes and configures a new Server instance
func NewServer(cfg *Config) *BaseServer {
	s := &BaseServer{
		Config:                      cfg.NbConfig,
		container:                   make(map[string]any),
		dnsDomain:                   cfg.DNSDomain,
		mgmtSingleAccModeDomain:     cfg.MgmtSingleAccModeDomain,
		disableMetrics:              cfg.DisableMetrics,
		disableGeoliteUpdate:        cfg.DisableGeoliteUpdate,
		userDeleteFromIDPEnabled:    cfg.UserDeleteFromIDPEnabled,
		mgmtPort:                    cfg.MgmtPort,
		disableLegacyManagementPort: cfg.DisableLegacyManagementPort,
		mgmtMetricsPort:             cfg.MgmtMetricsPort,
		autoResolveDomains:          cfg.AutoResolveDomains,
	}
	s.container[ContainerKeyBaseServer] = s

	return s
}

func (s *BaseServer) AfterInit(fn func(s *BaseServer)) {
	s.afterInit = append(s.afterInit, fn)
}

// Start begins listening for HTTP requests on the configured address
func (s *BaseServer) Start(ctx context.Context) error {
	srvCtx, cancel := context.WithCancel(ctx)
	s.cancel = cancel
	s.errCh = make(chan error, 4)

	if s.autoResolveDomains {
		s.ResolveDomains(srvCtx)
	}

	s.PeersManager()
	s.GeoLocationManager()

	err := s.Metrics().Expose(srvCtx, s.mgmtMetricsPort, "/metrics")
	if err != nil {
		return fmt.Errorf("failed to expose metrics: %v", err)
	}
	s.EphemeralManager().LoadInitialPeers(srvCtx)

	var tlsConfig *tls.Config
	tlsEnabled := false
	if s.Config.HttpConfig.LetsEncryptDomain != "" {
		s.certManager, err = encryption.CreateCertManager(s.Config.Datadir, s.Config.HttpConfig.LetsEncryptDomain)
		if err != nil {
			return fmt.Errorf("failed creating LetsEncrypt cert manager: %v", err)
		}
		tlsEnabled = true
	} else if s.Config.HttpConfig.CertFile != "" && s.Config.HttpConfig.CertKey != "" {
		tlsConfig, err = loadTLSConfig(s.Config.HttpConfig.CertFile, s.Config.HttpConfig.CertKey)
		if err != nil {
			log.WithContext(srvCtx).Errorf("cannot load TLS credentials: %v", err)
			return err
		}
		tlsEnabled = true
	}

	installationID, err := getInstallationID(srvCtx, s.Store())
	if err != nil {
		log.WithContext(srvCtx).Errorf("cannot load TLS credentials: %v", err)
		return err
	}

	if !s.disableMetrics {
		idpManager := "disabled"
		if s.Config.IdpManagerConfig != nil && s.Config.IdpManagerConfig.ManagerType != "" {
			idpManager = s.Config.IdpManagerConfig.ManagerType
		}

		if s.Config.EmbeddedIdP != nil && s.Config.EmbeddedIdP.Enabled {
			idpManager = metrics.EmbeddedType
		}

		metricsWorker := metrics.NewWorker(srvCtx, installationID, s.Store(), s.PeersUpdateManager(), idpManager)
		go metricsWorker.Run(srvCtx)
	}

	// Eagerly create the gRPC server so that all AfterInit hooks are registered
	// before we iterate them. Lazy creation after the loop would miss hooks
	// registered during GRPCServer() construction (e.g., SetServiceManager).
	s.GRPCServer()

	for _, fn := range s.afterInit {
		if fn != nil {
			fn(s)
		}
	}

	// With the native transport enabled the gRPC server carries no transport
	// credentials, so TLS must be terminated at each of its listeners.
	var grpcTLSConfig *tls.Config
	if nativeGRPCEnabled() {
		if s.certManager != nil {
			grpcTLSConfig = s.certManager.TLSConfig()
		} else {
			grpcTLSConfig = tlsConfig
		}
	}

	var compatListener net.Listener
	if s.mgmtPort != ManagementLegacyPort && !s.disableLegacyManagementPort {
		// The Management gRPC server was running on port 33073 previously. Old agents that are already connected to it
		// are using port 33073. For compatibility purposes we keep running a 2nd gRPC server on port 33073.
		compatListener, err = s.serveGRPC(srvCtx, s.GRPCServer(), ManagementLegacyPort, grpcTLSConfig)
		if err != nil {
			return err
		}
		log.WithContext(srvCtx).Infof("running gRPC backward compatibility server: %s", compatListener.Addr().String())
	}

	rootHandler := s.handlerFunc(srvCtx, s.GRPCServer(), s.APIHandler(), s.IDPHandler(), s.Metrics().GetMeter())
	switch {
	case s.certManager != nil:
		if s.mgmtPort == 443 {
			// CertManager, HTTP and gRPC API all on the same port
			rootHandler = s.certManager.HTTPHandler(rootHandler)
			if nativeGRPCEnabled() {
				var tcpListener net.Listener
				tcpListener, err = net.Listen("tcp", fmt.Sprintf(":%d", s.mgmtPort))
				if err != nil {
					return fmt.Errorf("failed creating TCP listener on port %d: %v", s.mgmtPort, err)
				}
				s.listener = tls.NewListener(tcpListener, preferHTTP1ForDualProtoClients(s.certManager.TLSConfig()))
			} else {
				s.listener = s.certManager.Listener()
			}
		} else {
			mgmtTLSConfig := s.certManager.TLSConfig()
			if nativeGRPCEnabled() {
				mgmtTLSConfig = preferHTTP1ForDualProtoClients(mgmtTLSConfig)
			}
			s.listener, err = tls.Listen("tcp", fmt.Sprintf(":%d", s.mgmtPort), mgmtTLSConfig)
			if err != nil {
				return fmt.Errorf("failed creating TLS listener on port %d: %v", s.mgmtPort, err)
			}
			cml := s.certManager.Listener()
			log.WithContext(ctx).Infof("running HTTP server (LetsEncrypt challenge handler): %s", cml.Addr().String())
			s.serveHTTP(ctx, cml, s.certManager.HTTPHandler(nil))
		}
	case tlsConfig != nil:
		mgmtTLSConfig := tlsConfig
		if nativeGRPCEnabled() {
			mgmtTLSConfig = preferHTTP1ForDualProtoClients(mgmtTLSConfig)
		}
		s.listener, err = tls.Listen("tcp", fmt.Sprintf(":%d", s.mgmtPort), mgmtTLSConfig)
		if err != nil {
			return fmt.Errorf("failed creating TLS listener on port %d: %v", s.mgmtPort, err)
		}
	default:
		s.listener, err = net.Listen("tcp", fmt.Sprintf(":%d", s.mgmtPort))
		if err != nil {
			return fmt.Errorf("failed creating TCP listener on port %d: %v", s.mgmtPort, err)
		}
	}

	log.WithContext(ctx).Infof("management server version %s", version.NetbirdVersion())
	log.WithContext(ctx).Infof("running HTTP server and gRPC server on the same port: %s", s.listener.Addr().String())
	if nativeGRPCEnabled() {
		log.WithContext(ctx).Infof("serving gRPC on the native transport (multiplexed with HTTP)")
		s.serveMultiplexed(ctx, s.listener, s.GRPCServer(), rootHandler, tlsEnabled)
	} else {
		s.serveGRPCWithHTTP(ctx, s.listener, rootHandler, tlsEnabled)
	}

	s.update = version.NewUpdateAndStart("nb/management")
	s.update.SetDaemonVersion(version.NetbirdVersion())
	s.update.SetOnUpdateListener(func() {
		log.WithContext(ctx).Infof("your management version, \"%s\", is outdated, a new management version is available. Learn more here: https://github.com/netbirdio/netbird/releases", version.NetbirdVersion())
	})

	return nil
}

// Stop attempts a graceful shutdown, waiting up to 5 seconds for active connections to finish
func (s *BaseServer) Stop() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	s.IntegratedValidator().Stop(ctx)
	if s.GeoLocationManager() != nil {
		_ = s.GeoLocationManager().Stop()
	}
	s.EphemeralManager().Stop()
	_ = s.Metrics().Close()
	if s.listener != nil {
		_ = s.listener.Close()
	}
	if s.certManager != nil {
		_ = s.certManager.Listener().Close()
	}
	s.GRPCServer().Stop()
	if s.proxyAuthClose != nil {
		s.proxyAuthClose()
		s.proxyAuthClose = nil
	}
	_ = s.Store().Close(ctx)
	_ = s.EventStore().Close(ctx)
	if s.update != nil {
		s.update.StopWatch()
	}
	// Stop embedded IdP if configured
	if embeddedIdP, ok := s.IdpManager().(*idp.EmbeddedIdPManager); ok {
		_ = embeddedIdP.Stop(ctx)
	}

	select {
	case <-s.Errors():
		log.WithContext(ctx).Infof("stopped Management Service")
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Done returns a channel that is closed when the server stops
func (s *BaseServer) Errors() <-chan error {
	return s.errCh
}

// GetContainer retrieves a dependency from the BaseServer's container by its key
func (s *BaseServer) GetContainer(key string) (any, bool) {
	container, exists := s.container[key]
	return container, exists
}

// SetContainer stores a dependency in the BaseServer's container with the specified key
func (s *BaseServer) SetContainer(key string, container any) {
	if _, exists := s.container[key]; exists {
		log.Tracef("container with key %s already exists", key)
		return
	}
	s.container[key] = container
	log.Tracef("container with key %s set successfully", key)
}

// SetHandlerFunc allows overriding the default HTTP handler function.
// This is useful for multiplexing additional services on the same port.
func (s *BaseServer) SetHandlerFunc(handler http.Handler) {
	s.container["customHandler"] = handler
	log.Tracef("custom handler set successfully")
}

func (s *BaseServer) handlerFunc(_ context.Context, gRPCHandler *grpc.Server, httpHandler http.Handler, idpHandler http.Handler, meter metric.Meter) http.Handler {
	// Check if a custom handler was set (for multiplexing additional services)
	if customHandler, ok := s.GetContainer("customHandler"); ok {
		if handler, ok := customHandler.(http.Handler); ok {
			log.Tracef("using custom handler")
			return handler
		}
	}

	// Use default handler
	wsProxy := wsproxyserver.New(gRPCHandler, wsproxyserver.WithOTelMeter(meter))

	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch {
		case request.ProtoMajor == 2 && (strings.HasPrefix(request.Header.Get("Content-Type"), "application/grpc") ||
			strings.HasPrefix(request.Header.Get("Content-Type"), "application/grpc+proto")):
			gRPCHandler.ServeHTTP(writer, request)
		case request.URL.Path == wsproxy.ProxyPath+wsproxy.ManagementComponent:
			wsProxy.Handler().ServeHTTP(writer, request)
		case idpHandler != nil && strings.HasPrefix(request.URL.Path, "/oauth2"):
			idpHandler.ServeHTTP(writer, request)
		default:
			httpHandler.ServeHTTP(writer, request)
		}
	})
}

func (s *BaseServer) serveGRPC(ctx context.Context, grpcServer *grpc.Server, port int, tlsConf *tls.Config) (net.Listener, error) {
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return nil, err
	}
	if tlsConf != nil {
		listener = tls.NewListener(listener, tlsConf)
	}

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		err := grpcServer.Serve(listener)

		if ctx.Err() != nil {
			return
		}

		select {
		case s.errCh <- err:
		default:
		}
	}()

	return listener, nil
}

func (s *BaseServer) serveHTTP(ctx context.Context, httpListener net.Listener, handler http.Handler) {
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		err := http.Serve(httpListener, handler)
		if ctx.Err() != nil {
			return
		}

		select {
		case s.errCh <- err:
		default:
		}
	}()
}

func (s *BaseServer) serveGRPCWithHTTP(ctx context.Context, listener net.Listener, handler http.Handler, tlsEnabled bool) {
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		var err error
		if tlsEnabled {
			err = http.Serve(listener, handler)
		} else {
			// the following magic is needed to support HTTP2 without TLS
			// and still share a single port between gRPC and HTTP APIs
			h1s := &http.Server{
				//nolint:staticcheck // h2c also handles the HTTP/1 Upgrade mechanism, which http.Server's UnencryptedHTTP2 does not
				Handler: h2c.NewHandler(handler, &http2.Server{}),
			}
			err = h1s.Serve(listener)
		}

		if ctx.Err() != nil {
			return
		}

		select {
		case s.errCh <- err:
		default:
		}
	}()
}

// preferHTTP1ForDualProtoClients steers TLS clients that offer both "h2" and
// "http/1.1" in ALPN (browsers, REST clients) to HTTP/1.1. gRPC clients offer
// only "h2", so with this steering every HTTP/2 connection on the shared
// listener carries gRPC and can be routed to the native transport without
// inspecting frames. ACME "acme-tls/1" and single-protocol clients keep the
// base configuration.
func preferHTTP1ForDualProtoClients(base *tls.Config) *tls.Config {
	h1Config := base.Clone()
	h1Config.NextProtos = []string{"http/1.1"}
	steered := base.Clone()
	steered.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		if slices.Contains(hello.SupportedProtos, "http/1.1") && slices.Contains(hello.SupportedProtos, "h2") {
			return h1Config, nil
		}
		return nil, nil
	}
	return steered
}

// serveMultiplexed splits the shared listener by protocol: HTTP/2 connections
// go to the native gRPC transport (see preferHTTP1ForDualProtoClients for why
// they are all gRPC), everything else is served by net/http.
//
// Content-type based classification cannot be used here: cmux's SendSettings
// matchers greet non-matching HTTP/2 connections and corrupt them for any
// subsequent handler, while read-only matchers deadlock grpc-go clients,
// which do not send HEADERS until they receive the server SETTINGS frame.
func (s *BaseServer) serveMultiplexed(ctx context.Context, listener net.Listener, grpcServer *grpc.Server, handler http.Handler, tlsEnabled bool) {
	mux := cmux.New(listener)
	grpcListener := mux.Match(cmux.HTTP2())
	httpListener := mux.Match(cmux.Any())

	httpHandler := handler
	if !tlsEnabled {
		//nolint:staticcheck // h2c also handles the HTTP/1 Upgrade mechanism, which http.Server's UnencryptedHTTP2 does not
		httpHandler = h2c.NewHandler(handler, &http2.Server{})
	}

	s.wg.Add(3)
	go func() {
		defer s.wg.Done()
		s.reportServeError(ctx, grpcServer.Serve(grpcListener))
	}()
	go func() {
		defer s.wg.Done()
		s.reportServeError(ctx, http.Serve(httpListener, httpHandler))
	}()
	go func() {
		defer s.wg.Done()
		s.reportServeError(ctx, mux.Serve())
	}()
}

func (s *BaseServer) reportServeError(ctx context.Context, err error) {
	if ctx.Err() != nil || err == nil {
		return
	}
	select {
	case s.errCh <- err:
	default:
	}
}

// ResolveDomains determines dnsDomain and mgmtSingleAccModeDomain based on store state.
// Fresh installs use the default self-hosted domain, while existing installs reuse the
// persisted account domain to keep addressing stable across config changes.
func (s *BaseServer) ResolveDomains(ctx context.Context) {
	st := s.Store()

	setDefault := func(logMsg string, args ...any) {
		if logMsg != "" {
			log.WithContext(ctx).Warnf(logMsg, args...)
		}
		s.dnsDomain = DefaultSelfHostedDomain
		s.mgmtSingleAccModeDomain = DefaultSelfHostedDomain
	}

	accountsCount, err := st.GetAccountsCounter(ctx)
	if err != nil {
		setDefault("resolve domains: failed to read accounts counter: %v; using default domain %q", err, DefaultSelfHostedDomain)
		return
	}

	if accountsCount == 0 {
		s.dnsDomain = DefaultSelfHostedDomain
		s.mgmtSingleAccModeDomain = DefaultSelfHostedDomain
		log.WithContext(ctx).Infof("resolve domains: fresh install detected, using default domain %q", DefaultSelfHostedDomain)
		return
	}

	accountID, err := st.GetAnyAccountID(ctx)
	if err != nil {
		setDefault("resolve domains: failed to get existing account ID: %v; using default domain %q", err, DefaultSelfHostedDomain)
		return
	}

	if accountID == "" {
		setDefault("resolve domains: empty account ID returned for existing accounts; using default domain %q", DefaultSelfHostedDomain)
		return
	}

	domain, _, err := st.GetAccountDomainAndCategory(ctx, store.LockingStrengthNone, accountID)
	if err != nil {
		setDefault("resolve domains: failed to get account domain for account %q: %v; using default domain %q", accountID, err, DefaultSelfHostedDomain)
		return
	}

	if domain == "" {
		setDefault("resolve domains: account %q has empty domain; using default domain %q", accountID, DefaultSelfHostedDomain)
		return
	}

	s.dnsDomain = domain
	s.mgmtSingleAccModeDomain = domain
	log.WithContext(ctx).Infof("resolve domains: using persisted account domain %q", domain)
}

func getInstallationID(ctx context.Context, store store.Store) (string, error) {
	installationID := store.GetInstallationID()
	if installationID != "" {
		return installationID, nil
	}

	installationID = strings.ToUpper(uuid.New().String())
	err := store.SaveInstallationID(ctx, installationID)
	if err != nil {
		return "", err
	}
	return installationID, nil
}
