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
	"sync"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/netbirdio/netbird/proxy/internal/accesslog"
	"github.com/netbirdio/netbird/proxy/internal/acme"
	"github.com/netbirdio/netbird/proxy/internal/auth"
	"github.com/netbirdio/netbird/proxy/internal/certwatch"
	"github.com/netbirdio/netbird/proxy/internal/debug"
	proxygrpc "github.com/netbirdio/netbird/proxy/internal/grpc"
	"github.com/netbirdio/netbird/proxy/internal/health"
	"github.com/netbirdio/netbird/proxy/internal/k8s"
	"github.com/netbirdio/netbird/proxy/internal/metrics"
	"github.com/netbirdio/netbird/proxy/internal/proxy"
	"github.com/netbirdio/netbird/proxy/internal/roundtrip"
	"github.com/netbirdio/netbird/proxy/internal/types"
	"github.com/netbirdio/netbird/proxy/web"
	"github.com/netbirdio/netbird/shared/management/domain"
	"github.com/netbirdio/netbird/shared/management/proto"
	"github.com/netbirdio/netbird/util/embeddedroots"
)

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
	meter         *metrics.Metrics

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
	// ACMEChallengeType specifies the ACME challenge type: "http-01" or "tls-alpn-01".
	// Defaults to "tls-alpn-01" if not specified.
	ACMEChallengeType string
	// CertLockMethod controls how ACME certificate locks are coordinated
	// across replicas. Default: CertLockAuto (detect environment).
	CertLockMethod   acme.CertLockMethod
	OIDCClientId     string
	OIDCClientSecret string
	OIDCEndpoint     string
	OIDCScopes       []string

	// DebugEndpointEnabled enables the debug HTTP endpoint.
	DebugEndpointEnabled bool
	// DebugEndpointAddress is the address for the debug HTTP endpoint (default: ":8444").
	DebugEndpointAddress string
	// HealthAddress is the address for the health probe endpoint (default: "localhost:8080").
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
	// WireguardPort is the port for the WireGuard interface. Use 0 for a
	// random OS-assigned port. A fixed port only works with single-account
	// deployments; multiple accounts will fail to bind the same port.
	WireguardPort int
}

// NotifyStatus sends a status update to management about tunnel connectivity
func (s *Server) NotifyStatus(ctx context.Context, accountID, serviceID, domain string, connected bool) error {
	status := proto.ProxyStatus_PROXY_STATUS_TUNNEL_NOT_CREATED
	if connected {
		status = proto.ProxyStatus_PROXY_STATUS_ACTIVE
	}

	_, err := s.mgmtClient.SendStatusUpdate(ctx, &proto.SendStatusUpdateRequest{
		ServiceId:         serviceID,
		AccountId:         accountID,
		Status:            status,
		CertificateIssued: false,
	})
	return err
}

// NotifyCertificateIssued sends a notification to management that a certificate was issued
func (s *Server) NotifyCertificateIssued(ctx context.Context, accountID, serviceID, domain string) error {
	_, err := s.mgmtClient.SendStatusUpdate(ctx, &proto.SendStatusUpdateRequest{
		ServiceId:         serviceID,
		AccountId:         accountID,
		Status:            proto.ProxyStatus_PROXY_STATUS_ACTIVE,
		CertificateIssued: true,
	})
	return err
}

func (s *Server) ListenAndServe(ctx context.Context, addr string) (err error) {
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

	// Start up metrics gathering
	reg := prometheus.NewRegistry()
	s.meter = metrics.New(reg)

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
	go s.newManagementMappingWorker(ctx, s.mgmtClient)

	// Initialize the netbird client, this is required to build peer connections
	// to proxy over.
	s.netbird = roundtrip.NewNetBird(s.ManagementAddress, s.ID, s.ProxyURL, s.WireguardPort, s.Logger, s, s.mgmtClient)

	tlsConfig, err := s.configureTLS(ctx)
	if err != nil {
		return err
	}

	// Configure the reverse proxy using NetBird's HTTP Client Transport for proxying.
	s.proxy = proxy.NewReverseProxy(s.meter.RoundTripper(s.netbird), s.ForwardedProto, s.TrustedProxies, s.Logger)

	// Configure the authentication middleware with session validator for OIDC group checks.
	s.auth = auth.NewMiddleware(s.Logger, s.mgmtClient)

	// Configure Access logs to management server.
	accessLog := accesslog.NewLogger(s.mgmtClient, s.Logger, s.TrustedProxies)

	s.healthChecker = health.NewChecker(s.Logger, s.netbird)

	if s.DebugEndpointEnabled {
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

	// Start health probe server.
	healthAddr := s.HealthAddress
	if healthAddr == "" {
		healthAddr = "localhost:8080"
	}
	s.healthServer = health.NewServer(healthAddr, s.healthChecker, s.Logger, promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
	healthListener, err := net.Listen("tcp", healthAddr)
	if err != nil {
		return fmt.Errorf("health probe server listen on %s: %w", healthAddr, err)
	}
	go func() {
		if err := s.healthServer.Serve(healthListener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.Logger.Errorf("health probe server: %v", err)
		}
	}()

	// Start the reverse proxy HTTPS server.
	s.https = &http.Server{
		Addr:      addr,
		Handler:   s.meter.Middleware(accessLog.Middleware(web.AssetHandler(s.auth.Protect(s.proxy)))),
		TLSConfig: tlsConfig,
		ErrorLog:  newHTTPServerLogger(s.Logger, logtagValueHTTPS),
	}

	httpsErr := make(chan error, 1)
	go func() {
		s.Logger.Debugf("starting reverse proxy server on %s", addr)
		httpsErr <- s.https.ListenAndServeTLS("", "")
	}()

	select {
	case err := <-httpsErr:
		s.shutdownServices()
		if !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("https server: %w", err)
		}
		return nil
	case <-ctx.Done():
		s.gracefulShutdown()
		return nil
	}
}

const (
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
	s.acme = acme.NewManager(s.CertificateDirectory, s.ACMEDirectory, s, s.Logger, s.CertLockMethod)

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

	// Step 4: Stop all remaining background services.
	s.shutdownServices()
	s.Logger.Info("graceful shutdown complete")
}

// shutdownServices stops all background services concurrently and waits for
// them to finish.
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

	wg.Wait()
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

		if s.healthChecker != nil {
			s.healthChecker.SetManagementConnected(false)
		}

		mappingClient, err := client.GetMappingUpdate(ctx, &proto.GetMappingUpdateRequest{
			ProxyId:   s.ID,
			Version:   s.Version,
			StartedAt: timestamppb.New(s.startTime),
			Address:   s.ProxyURL,
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

			if !*initialSyncDone && msg.GetInitialSyncComplete() {
				if s.healthChecker != nil {
					s.healthChecker.SetInitialSyncComplete()
				}
				*initialSyncDone = true
				s.Logger.Info("Initial mapping sync complete")
			}
		}
	}
}

func (s *Server) processMappings(ctx context.Context, mappings []*proto.ProxyMapping) {
	for _, mapping := range mappings {
		s.Logger.WithFields(log.Fields{
			"type":   mapping.GetType(),
			"domain": mapping.GetDomain(),
			"path":   mapping.GetPath(),
			"id":     mapping.GetId(),
		}).Debug("Processing mapping update")
		switch mapping.GetType() {
		case proto.ProxyMappingUpdateType_UPDATE_TYPE_CREATED:
			if err := s.addMapping(ctx, mapping); err != nil {
				// TODO: Retry this? Or maybe notify the management server that this mapping has failed?
				s.Logger.WithFields(log.Fields{
					"service_id": mapping.GetId(),
					"domain":     mapping.GetDomain(),
					"error":      err,
				}).Error("Error adding new mapping, ignoring this mapping and continuing processing")
			}
		case proto.ProxyMappingUpdateType_UPDATE_TYPE_MODIFIED:
			if err := s.updateMapping(ctx, mapping); err != nil {
				s.Logger.WithFields(log.Fields{
					"service_id": mapping.GetId(),
					"domain":     mapping.GetDomain(),
				}).Errorf("failed to update mapping: %v", err)
			}
		case proto.ProxyMappingUpdateType_UPDATE_TYPE_REMOVED:
			s.removeMapping(ctx, mapping)
		}
	}
}

func (s *Server) addMapping(ctx context.Context, mapping *proto.ProxyMapping) error {
	d := domain.Domain(mapping.GetDomain())
	accountID := types.AccountID(mapping.GetAccountId())
	serviceID := mapping.GetId()
	authToken := mapping.GetAuthToken()

	if err := s.netbird.AddPeer(ctx, accountID, d, authToken, serviceID); err != nil {
		return fmt.Errorf("create peer for domain %q: %w", d, err)
	}
	if s.acme != nil {
		s.acme.AddDomain(d, string(accountID), serviceID)
	}

	// Pass the mapping through to the update function to avoid duplicating the
	// setup, currently update is simply a subset of this function, so this
	// separation makes sense...to me at least.
	if err := s.updateMapping(ctx, mapping); err != nil {
		s.removeMapping(ctx, mapping)
		return fmt.Errorf("update mapping for domain %q: %w", d, err)
	}
	return nil
}

func (s *Server) updateMapping(ctx context.Context, mapping *proto.ProxyMapping) error {
	// Very simple implementation here, we don't touch the existing peer
	// connection or any existing TLS configuration, we simply overwrite
	// the auth and proxy mappings.
	// Note: this does require the management server to always send a
	// full mapping rather than deltas during a modification.
	var schemes []auth.Scheme
	if mapping.GetAuth().GetPassword() {
		schemes = append(schemes, auth.NewPassword(s.mgmtClient, mapping.GetId(), mapping.GetAccountId()))
	}
	if mapping.GetAuth().GetPin() {
		schemes = append(schemes, auth.NewPin(s.mgmtClient, mapping.GetId(), mapping.GetAccountId()))
	}
	if mapping.GetAuth().GetOidc() {
		schemes = append(schemes, auth.NewOIDC(s.mgmtClient, mapping.GetId(), mapping.GetAccountId(), s.ForwardedProto))
	}

	maxSessionAge := time.Duration(mapping.GetAuth().GetMaxSessionAgeSeconds()) * time.Second
	if err := s.auth.AddDomain(mapping.GetDomain(), schemes, mapping.GetAuth().GetSessionKey(), maxSessionAge, mapping.GetAccountId(), mapping.GetId()); err != nil {
		return fmt.Errorf("auth setup for domain %s: %w", mapping.GetDomain(), err)
	}
	s.proxy.AddMapping(s.protoToMapping(mapping))
	s.meter.AddMapping(s.protoToMapping(mapping))
	return nil
}

func (s *Server) removeMapping(ctx context.Context, mapping *proto.ProxyMapping) {
	d := domain.Domain(mapping.GetDomain())
	accountID := types.AccountID(mapping.GetAccountId())
	if err := s.netbird.RemovePeer(ctx, accountID, d); err != nil {
		s.Logger.WithFields(log.Fields{
			"account_id": accountID,
			"domain":     d,
			"error":      err,
		}).Error("Error removing NetBird peer connection for domain, continuing additional domain cleanup but peer connection may still exist")
	}
	if s.acme != nil {
		s.acme.RemoveDomain(d)
	}
	s.auth.RemoveDomain(mapping.GetDomain())
	s.proxy.RemoveMapping(s.protoToMapping(mapping))
	s.meter.RemoveMapping(s.protoToMapping(mapping))
}

func (s *Server) protoToMapping(mapping *proto.ProxyMapping) proxy.Mapping {
	paths := make(map[string]*url.URL)
	for _, pathMapping := range mapping.GetPath() {
		targetURL, err := url.Parse(pathMapping.GetTarget())
		if err != nil {
			// TODO: Should we warn management about this so it can be bubbled up to a user to reconfigure?
			s.Logger.WithFields(log.Fields{
				"service_id": mapping.GetId(),
				"account_id": mapping.GetAccountId(),
				"domain":     mapping.GetDomain(),
				"path":       pathMapping.GetPath(),
				"target":     pathMapping.GetTarget(),
			}).WithError(err).Error("failed to parse target URL for path, skipping")
			continue
		}
		paths[pathMapping.GetPath()] = targetURL
	}
	return proxy.Mapping{
		ID:               mapping.GetId(),
		AccountID:        types.AccountID(mapping.GetAccountId()),
		Host:             mapping.GetDomain(),
		Paths:            paths,
		PassHostHeader:   mapping.GetPassHostHeader(),
		RewriteRedirects: mapping.GetRewriteRedirects(),
	}
}

// debugEndpointAddr returns the address for the debug endpoint.
// If addr is empty, it defaults to localhost:8444 for security.
func debugEndpointAddr(addr string) string {
	if addr == "" {
		return "localhost:8444"
	}
	return addr
}
