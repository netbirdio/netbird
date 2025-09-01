package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	"google.golang.org/grpc"

	"github.com/netbirdio/netbird/encryption"
	nbconfig "github.com/netbirdio/netbird/management/internals/server/config"
	"github.com/netbirdio/netbird/management/server/metrics"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/util"
	"github.com/netbirdio/netbird/version"
)

// ManagementLegacyPort is the port that was used before by the Management gRPC server.
// It is used for backward compatibility now.
const ManagementLegacyPort = 33073

type Server interface {
	Start(ctx context.Context) error
	Stop() error
	Errors() <-chan error
	GetContainer(key string) (any, bool)
	SetContainer(key string, container any)
}

// Server holds the HTTP BaseServer instance.
// Add any additional fields you need, such as database connections, config, etc.
type BaseServer struct {
	// config holds the server configuration
	config *nbconfig.Config
	// container of dependencies, each dependency is identified by a unique string.
	container map[string]any
	// AfterInit is a function that will be called after the server is initialized
	afterInit []func(s *BaseServer)

	disableMetrics           bool
	dnsDomain                string
	disableGeoliteUpdate     bool
	userDeleteFromIDPEnabled bool
	mgmtSingleAccModeDomain  string
	mgmtMetricsPort          int
	mgmtPort                 int

	listener    net.Listener
	certManager *autocert.Manager
	update      *version.Update

	errCh  chan error
	wg     sync.WaitGroup
	cancel context.CancelFunc
}

// NewServer initializes and configures a new Server instance
func NewServer(config *nbconfig.Config, dnsDomain, mgmtSingleAccModeDomain string, mgmtPort, mgmtMetricsPort int, disableMetrics, disableGeoliteUpdate, userDeleteFromIDPEnabled bool) *BaseServer {
	return &BaseServer{
		config:                   config,
		container:                make(map[string]any),
		dnsDomain:                dnsDomain,
		mgmtSingleAccModeDomain:  mgmtSingleAccModeDomain,
		disableMetrics:           disableMetrics,
		disableGeoliteUpdate:     disableGeoliteUpdate,
		userDeleteFromIDPEnabled: userDeleteFromIDPEnabled,
		mgmtPort:                 mgmtPort,
		mgmtMetricsPort:          mgmtMetricsPort,
	}
}

func (s *BaseServer) AfterInit(fn func(s *BaseServer)) {
	s.afterInit = append(s.afterInit, fn)
}

// Start begins listening for HTTP requests on the configured address
func (s *BaseServer) Start(ctx context.Context) error {
	srvCtx, cancel := context.WithCancel(ctx)
	s.cancel = cancel
	s.errCh = make(chan error, 4)

	s.PeersManager()
	s.GeoLocationManager()

	for _, fn := range s.afterInit {
		if fn != nil {
			fn(s)
		}
	}

	err := s.Metrics().Expose(srvCtx, s.mgmtMetricsPort, "/metrics")
	if err != nil {
		return fmt.Errorf("failed to expose metrics: %v", err)
	}
	s.EphemeralManager().LoadInitialPeers(srvCtx)

	var tlsConfig *tls.Config
	tlsEnabled := false
	if s.config.HttpConfig.LetsEncryptDomain != "" {
		s.certManager, err = encryption.CreateCertManager(s.config.Datadir, s.config.HttpConfig.LetsEncryptDomain)
		if err != nil {
			return fmt.Errorf("failed creating LetsEncrypt cert manager: %v", err)
		}
		tlsEnabled = true
	} else if s.config.HttpConfig.CertFile != "" && s.config.HttpConfig.CertKey != "" {
		tlsConfig, err = loadTLSConfig(s.config.HttpConfig.CertFile, s.config.HttpConfig.CertKey)
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
		if s.config.IdpManagerConfig != nil && s.config.IdpManagerConfig.ManagerType != "" {
			idpManager = s.config.IdpManagerConfig.ManagerType
		}
		metricsWorker := metrics.NewWorker(srvCtx, installationID, s.Store(), s.PeersUpdateManager(), idpManager)
		go metricsWorker.Run(srvCtx)
	}

	var compatListener net.Listener
	if s.mgmtPort != ManagementLegacyPort {
		// The Management gRPC server was running on port 33073 previously. Old agents that are already connected to it
		// are using port 33073. For compatibility purposes we keep running a 2nd gRPC server on port 33073.
		compatListener, err = s.serveGRPC(srvCtx, s.GRPCServer(), ManagementLegacyPort)
		if err != nil {
			return err
		}
		log.WithContext(srvCtx).Infof("running gRPC backward compatibility server: %s", compatListener.Addr().String())
	}

	rootHandler := handlerFunc(s.GRPCServer(), s.APIHandler())
	switch {
	case s.certManager != nil:
		// a call to certManager.Listener() always creates a new listener so we do it once
		cml := s.certManager.Listener()
		if s.mgmtPort == 443 {
			// CertManager, HTTP and gRPC API all on the same port
			rootHandler = s.certManager.HTTPHandler(rootHandler)
			s.listener = cml
		} else {
			s.listener, err = tls.Listen("tcp", fmt.Sprintf(":%d", s.mgmtPort), s.certManager.TLSConfig())
			if err != nil {
				return fmt.Errorf("failed creating TLS listener on port %d: %v", s.mgmtPort, err)
			}
			log.WithContext(ctx).Infof("running HTTP server (LetsEncrypt challenge handler): %s", cml.Addr().String())
			s.serveHTTP(ctx, cml, s.certManager.HTTPHandler(nil))
		}
	case tlsConfig != nil:
		s.listener, err = tls.Listen("tcp", fmt.Sprintf(":%d", s.mgmtPort), tlsConfig)
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
	s.serveGRPCWithHTTP(ctx, s.listener, rootHandler, tlsEnabled)

	s.update = version.NewUpdate("nb/management")
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
	_ = s.Store().Close(ctx)
	_ = s.EventStore().Close(ctx)
	if s.update != nil {
		s.update.StopWatch()
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

func updateMgmtConfig(ctx context.Context, path string, config *nbconfig.Config) error {
	return util.DirectWriteJson(ctx, path, config)
}

func handlerFunc(gRPCHandler *grpc.Server, httpHandler http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		grpcHeader := strings.HasPrefix(request.Header.Get("Content-Type"), "application/grpc") ||
			strings.HasPrefix(request.Header.Get("Content-Type"), "application/grpc+proto")
		if request.ProtoMajor == 2 && grpcHeader {
			gRPCHandler.ServeHTTP(writer, request)
		} else {
			httpHandler.ServeHTTP(writer, request)
		}
	})
}

func (s *BaseServer) serveGRPC(ctx context.Context, grpcServer *grpc.Server, port int) (net.Listener, error) {
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return nil, err
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
