package server

// @note this file includes all the lower level dependencies, db, http and grpc BaseServer, metrics, logger, etc.

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"time"

	grpcMiddleware "github.com/grpc-ecosystem/go-grpc-middleware/v2"
	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/realip"
	"github.com/rs/xid"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"

	"github.com/netbirdio/management-integrations/integrations"
	"github.com/netbirdio/netbird/encryption"
	"github.com/netbirdio/netbird/formatter/hook"
	nbgrpc "github.com/netbirdio/netbird/management/internals/shared/grpc"
	"github.com/netbirdio/netbird/management/server/activity"
	nbContext "github.com/netbirdio/netbird/management/server/context"
	nbhttp "github.com/netbirdio/netbird/management/server/http"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/telemetry"
	mgmtProto "github.com/netbirdio/netbird/shared/management/proto"
	"github.com/netbirdio/netbird/util/crypt"
)

var (
	kaep = keepalive.EnforcementPolicy{
		MinTime:             15 * time.Second,
		PermitWithoutStream: true,
	}

	kasp = keepalive.ServerParameters{
		MaxConnectionIdle:     15 * time.Second,
		MaxConnectionAgeGrace: 5 * time.Second,
		Time:                  5 * time.Second,
		Timeout:               2 * time.Second,
	}
)

func (s *BaseServer) Metrics() telemetry.AppMetrics {
	return Create(s, func() telemetry.AppMetrics {
		appMetrics, err := telemetry.NewDefaultAppMetrics(context.Background())
		if err != nil {
			log.Fatalf("error while creating app metrics: %s", err)
		}
		return appMetrics
	})
}

func (s *BaseServer) Store() store.Store {
	return Create(s, func() store.Store {
		store, err := store.NewStore(context.Background(), s.Config.StoreConfig.Engine, s.Config.Datadir, s.Metrics(), false)
		if err != nil {
			log.Fatalf("failed to create store: %v", err)
		}

		if s.Config.DataStoreEncryptionKey != "" {
			fieldEncrypt, err := crypt.NewFieldEncrypt(s.Config.DataStoreEncryptionKey)
			if err != nil {
				log.Fatalf("failed to create field encryptor: %v", err)
			}
			store.SetFieldEncrypt(fieldEncrypt)
		}

		return store
	})
}

func (s *BaseServer) EventStore() activity.Store {
	return Create(s, func() activity.Store {
		integrationMetrics, err := integrations.InitIntegrationMetrics(context.Background(), s.Metrics())
		if err != nil {
			log.Fatalf("failed to initialize integration metrics: %v", err)
		}

		eventStore, _, err := integrations.InitEventStore(context.Background(), s.Config.Datadir, s.Config.DataStoreEncryptionKey, integrationMetrics)
		if err != nil {
			log.Fatalf("failed to initialize event store: %v", err)
		}

		return eventStore
	})
}

func (s *BaseServer) APIHandler() http.Handler {
	return Create(s, func() http.Handler {
		httpAPIHandler, err := nbhttp.NewAPIHandler(context.Background(), s.AccountManager(), s.NetworksManager(), s.ResourcesManager(), s.RoutesManager(), s.GroupsManager(), s.GeoLocationManager(), s.AuthManager(), s.Metrics(), s.IntegratedValidator(), s.ProxyController(), s.PermissionsManager(), s.PeersManager(), s.SettingsManager(), s.ZonesManager(), s.RecordsManager(), s.NetworkMapController(), s.IdpManager())
		if err != nil {
			log.Fatalf("failed to create API handler: %v", err)
		}
		return httpAPIHandler
	})
}

func (s *BaseServer) GRPCServer() *grpc.Server {
	return Create(s, func() *grpc.Server {
		trustedPeers := s.Config.ReverseProxy.TrustedPeers
		defaultTrustedPeers := []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")}
		if len(trustedPeers) == 0 || slices.Equal[[]netip.Prefix](trustedPeers, defaultTrustedPeers) {
			log.WithContext(context.Background()).Warn("TrustedPeers are configured to default value '0.0.0.0/0', '::/0'. This allows connection IP spoofing.")
			trustedPeers = defaultTrustedPeers
		}
		trustedHTTPProxies := s.Config.ReverseProxy.TrustedHTTPProxies
		trustedProxiesCount := s.Config.ReverseProxy.TrustedHTTPProxiesCount
		if len(trustedHTTPProxies) > 0 && trustedProxiesCount > 0 {
			log.WithContext(context.Background()).Warn("TrustedHTTPProxies and TrustedHTTPProxiesCount both are configured. " +
				"This is not recommended way to extract X-Forwarded-For. Consider using one of these options.")
		}
		realipOpts := []realip.Option{
			realip.WithTrustedPeers(trustedPeers),
			realip.WithTrustedProxies(trustedHTTPProxies),
			realip.WithTrustedProxiesCount(trustedProxiesCount),
			realip.WithHeaders([]string{realip.XForwardedFor, realip.XRealIp}),
		}

		// Build interceptor chains
		// Machine Tunnel Fork: Add mTLS interceptors when enabled
		unaryInterceptors := []grpc.UnaryServerInterceptor{
			realip.UnaryServerInterceptorOpts(realipOpts...),
			unaryInterceptor,
		}
		streamInterceptors := []grpc.StreamServerInterceptor{
			realip.StreamServerInterceptorOpts(realipOpts...),
			streamInterceptor,
		}

		if s.Config.HttpConfig.MTLSEnabled {
			log.Info("mTLS authentication enabled for machine peers")
			unaryInterceptors = append(unaryInterceptors, MTLSUnaryInterceptor(s.Config.HttpConfig.MTLSStrictMode))
			streamInterceptors = append(streamInterceptors, MTLSStreamInterceptor(s.Config.HttpConfig.MTLSStrictMode))
		}

		gRPCOpts := []grpc.ServerOption{
			grpc.KeepaliveEnforcementPolicy(kaep),
			grpc.KeepaliveParams(kasp),
			grpc.ChainUnaryInterceptor(unaryInterceptors...),
			grpc.ChainStreamInterceptor(streamInterceptors...),
		}

		if s.Config.HttpConfig.LetsEncryptDomain != "" {
			certManager, err := encryption.CreateCertManager(s.Config.Datadir, s.Config.HttpConfig.LetsEncryptDomain)
			if err != nil {
				log.Fatalf("failed to create certificate manager: %v", err)
			}
			transportCredentials := credentials.NewTLS(certManager.TLSConfig())
			gRPCOpts = append(gRPCOpts, grpc.Creds(transportCredentials))
		} else if s.Config.HttpConfig.CertFile != "" && s.Config.HttpConfig.CertKey != "" {
			var tlsConfig *tls.Config
			var err error

			// Machine Tunnel Fork: Use mTLS config when enabled
			if s.Config.HttpConfig.MTLSEnabled {
				tlsConfig, err = loadMTLSConfig(
					s.Config.HttpConfig.CertFile,
					s.Config.HttpConfig.CertKey,
					s.Config.HttpConfig.MTLSCACertFile,
					s.Config.HttpConfig.MTLSCADir,
				)
				if err != nil {
					log.Fatalf("cannot load mTLS credentials: %v", err)
				}
			} else {
				tlsConfig, err = loadTLSConfig(s.Config.HttpConfig.CertFile, s.Config.HttpConfig.CertKey)
				if err != nil {
					log.Fatalf("cannot load TLS credentials: %v", err)
				}
			}
			transportCredentials := credentials.NewTLS(tlsConfig)
			gRPCOpts = append(gRPCOpts, grpc.Creds(transportCredentials))
		}

		gRPCAPIHandler := grpc.NewServer(gRPCOpts...)
		srv, err := nbgrpc.NewServer(s.Config, s.AccountManager(), s.SettingsManager(), s.SecretsManager(), s.Metrics(), s.AuthManager(), s.IntegratedValidator(), s.NetworkMapController(), s.OAuthConfigProvider())
		if err != nil {
			log.Fatalf("failed to create management server: %v", err)
		}
		mgmtProto.RegisterManagementServiceServer(gRPCAPIHandler, srv)

		return gRPCAPIHandler
	})
}

func loadTLSConfig(certFile string, certKey string) (*tls.Config, error) {
	// Load server's certificate and private key
	serverCert, err := tls.LoadX509KeyPair(certFile, certKey)
	if err != nil {
		return nil, err
	}

	// NewDefaultAppMetrics the credentials and return it
	config := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.NoClientCert,
		NextProtos: []string{
			"h2", "http/1.1", // enable HTTP/2
		},
	}

	return config, nil
}

// loadMTLSConfig creates a TLS config with client certificate verification enabled.
// Machine Tunnel Fork: This enables mTLS for machine peer authentication.
func loadMTLSConfig(certFile, certKey, caCertFile, caDir string) (*tls.Config, error) {
	// Load server's certificate and private key
	serverCert, err := tls.LoadX509KeyPair(certFile, certKey)
	if err != nil {
		return nil, err
	}

	// Load CA certificate pool for client verification
	caCertPool, err := loadCACertPool(caCertFile, caDir)
	if err != nil {
		return nil, err
	}

	// Use VerifyClientCertIfGiven instead of RequireAndVerifyClientCert
	// This allows:
	// - Clients WITH certificates: verified against CA pool
	// - Clients WITHOUT certificates: TLS handshake succeeds, interceptor handles auth
	// This enables fallback to Setup-Key auth for bootstrap
	config := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.VerifyClientCertIfGiven,
		ClientCAs:    caCertPool,
		NextProtos: []string{
			"h2", "http/1.1", // enable HTTP/2
		},
	}

	return config, nil
}

// loadCACertPool loads CA certificates from a file and/or directory.
// This supports multi-tenant scenarios where different customers have different CAs.
func loadCACertPool(caCertFile, caDir string) (*x509.CertPool, error) {
	caCertPool := x509.NewCertPool()
	certsLoaded := 0

	// Load single CA cert file if specified
	if caCertFile != "" {
		caCert, err := os.ReadFile(caCertFile)
		if err != nil {
			return nil, fmt.Errorf("read CA cert file: %w", err)
		}
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse CA certificate from %s", caCertFile)
		}
		certsLoaded++
		log.Infof("Loaded mTLS CA certificate from %s", caCertFile)
	}

	// Load all .crt and .pem files from CA directory
	if caDir != "" {
		entries, err := os.ReadDir(caDir)
		if err != nil {
			return nil, fmt.Errorf("read CA directory: %w", err)
		}

		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			ext := filepath.Ext(entry.Name())
			if ext != ".crt" && ext != ".pem" {
				continue
			}

			certPath := filepath.Join(caDir, entry.Name())
			caCert, err := os.ReadFile(certPath)
			if err != nil {
				log.Warnf("Failed to read CA cert %s: %v", certPath, err)
				continue
			}
			if caCertPool.AppendCertsFromPEM(caCert) {
				certsLoaded++
				log.Infof("Loaded mTLS CA certificate from %s", certPath)
			}
		}
	}

	if certsLoaded == 0 {
		return nil, fmt.Errorf("no CA certificates loaded (caCertFile=%s, caDir=%s)", caCertFile, caDir)
	}

	log.Infof("mTLS CA pool loaded with %d certificate(s)", certsLoaded)
	return caCertPool, nil
}

func unaryInterceptor(
	ctx context.Context,
	req interface{},
	info *grpc.UnaryServerInfo,
	handler grpc.UnaryHandler,
) (interface{}, error) {
	reqID := xid.New().String()
	//nolint
	ctx = context.WithValue(ctx, hook.ExecutionContextKey, hook.GRPCSource)
	//nolint
	ctx = context.WithValue(ctx, nbContext.RequestIDKey, reqID)
	return handler(ctx, req)
}

func streamInterceptor(
	srv interface{},
	ss grpc.ServerStream,
	info *grpc.StreamServerInfo,
	handler grpc.StreamHandler,
) error {
	reqID := xid.New().String()
	wrapped := grpcMiddleware.WrapServerStream(ss)
	//nolint
	ctx := context.WithValue(ss.Context(), hook.ExecutionContextKey, hook.GRPCSource)
	//nolint
	wrapped.WrappedContext = context.WithValue(ctx, nbContext.RequestIDKey, reqID)
	return handler(srv, wrapped)
}
