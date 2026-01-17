package server

// @note this file includes all the lower level dependencies, db, http and grpc BaseServer, metrics, logger, etc.

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/netip"
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
		gRPCOpts := []grpc.ServerOption{
			grpc.KeepaliveEnforcementPolicy(kaep),
			grpc.KeepaliveParams(kasp),
			grpc.ChainUnaryInterceptor(realip.UnaryServerInterceptorOpts(realipOpts...), unaryInterceptor),
			grpc.ChainStreamInterceptor(realip.StreamServerInterceptorOpts(realipOpts...), streamInterceptor),
		}

		if s.Config.HttpConfig.LetsEncryptDomain != "" {
			certManager, err := encryption.CreateCertManager(s.Config.Datadir, s.Config.HttpConfig.LetsEncryptDomain)
			if err != nil {
				log.Fatalf("failed to create certificate manager: %v", err)
			}
			transportCredentials := credentials.NewTLS(certManager.TLSConfig())
			gRPCOpts = append(gRPCOpts, grpc.Creds(transportCredentials))
		} else if s.Config.HttpConfig.CertFile != "" && s.Config.HttpConfig.CertKey != "" {
			tlsConfig, err := loadTLSConfig(s.Config.HttpConfig.CertFile, s.Config.HttpConfig.CertKey)
			if err != nil {
				log.Fatalf("cannot load TLS credentials: %v", err)
			}
			transportCredentials := credentials.NewTLS(tlsConfig)
			gRPCOpts = append(gRPCOpts, grpc.Creds(transportCredentials))
		}

		gRPCAPIHandler := grpc.NewServer(gRPCOpts...)
		srv, err := nbgrpc.NewServer(s.Config, s.AccountManager(), s.SettingsManager(), s.JobManager(), s.SecretsManager(), s.Metrics(), s.AuthManager(), s.IntegratedValidator(), s.NetworkMapController(), s.OAuthConfigProvider())
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
