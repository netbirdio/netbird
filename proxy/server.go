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
	"net/url"
	"path/filepath"
	"time"

	"github.com/cloudflare/backoff"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/netbirdio/netbird/proxy/internal/accesslog"
	"github.com/netbirdio/netbird/proxy/internal/acme"
	"github.com/netbirdio/netbird/proxy/internal/auth"
	"github.com/netbirdio/netbird/proxy/internal/proxy"
	"github.com/netbirdio/netbird/proxy/internal/roundtrip"
	"github.com/netbirdio/netbird/shared/management/proto"
	"github.com/netbirdio/netbird/util/embeddedroots"
)

type Server struct {
	mgmtConn *grpc.ClientConn
	proxy    *proxy.ReverseProxy
	netbird  *roundtrip.NetBird
	acme     *acme.Manager
	auth     *auth.Middleware
	http     *http.Server
	https    *http.Server

	// Mostly used for debugging on management.
	startTime time.Time

	ID                       string
	Logger                   *log.Logger
	Version                  string
	ProxyURL                 string
	ManagementAddress        string
	CertificateDirectory     string
	GenerateACMECertificates bool
	ACMEChallengeAddress     string
	ACMEDirectory            string
	OIDCClientId             string
	OIDCClientSecret         string
	OIDCEndpoint             string
	OIDCScopes               []string
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

	// The very first thing to do should be to connect to the Management server.
	// Without this connection, the Proxy cannot do anything.
	mgmtURL, err := url.Parse(s.ManagementAddress)
	if err != nil {
		return fmt.Errorf("parse management address: %w", err)
	}
	creds := insecure.NewCredentials()
	// Simple TLS check using management URL.
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
	s.mgmtConn, err = grpc.NewClient(mgmtURL.Host,
		grpc.WithTransportCredentials(creds),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:                20 * time.Second,
			Timeout:             10 * time.Second,
			PermitWithoutStream: true,
		}),
	)
	if err != nil {
		return fmt.Errorf("could not create management connection: %w", err)
	}
	mgmtClient := proto.NewProxyServiceClient(s.mgmtConn)
	go s.newManagementMappingWorker(ctx, mgmtClient)

	// Initialize the netbird client, this is required to build peer connections
	// to proxy over.
	s.netbird = roundtrip.NewNetBird(s.ManagementAddress, s.Logger)

	// When generating ACME certificates, start a challenge server.
	tlsConfig := &tls.Config{}
	if s.GenerateACMECertificates {
		s.Logger.WithField("acme_server", s.ACMEDirectory).Debug("ACME certificates enabled, configuring certificate manager")
		s.acme = acme.NewManager(s.CertificateDirectory, s.ACMEDirectory)
		s.http = &http.Server{
			Addr:    s.ACMEChallengeAddress,
			Handler: s.acme.HTTPHandler(nil),
		}
		go func() {
			if err := s.http.ListenAndServe(); err != nil {
				// Rather than retry, log the issue periodically so that hopefully someone notices and fixes the issue.
				for range time.Tick(10 * time.Second) {
					s.Logger.WithError(err).Error("ACME HTTP-01 challenge server error")
				}
			}
		}()
		tlsConfig = s.acme.TLSConfig()

		// If the ProxyURL is not set, then fallback to the server address.
		// Hopefully that should give at least something that we can use.
		// If it doesn't, then autocert probably won't work correctly.
		if s.ProxyURL == "" {
			s.ProxyURL, _, _ = net.SplitHostPort(addr)
		}
		// ServerName needs to be set to allow for ACME to work correctly
		// when using CNAME URLs to access the proxy.
		tlsConfig.ServerName = s.ProxyURL

		s.Logger.WithFields(log.Fields{
			"ServerName": s.ProxyURL,
		}).Debug("started ACME challenge server")
	} else {
		s.Logger.Debug("ACME certificates disabled, using static certificates")
		// Otherwise pull some certificates from expected locations.
		cert, err := tls.LoadX509KeyPair(
			filepath.Join(s.CertificateDirectory, "tls.crt"),
			filepath.Join(s.CertificateDirectory, "tls.key"),
		)
		if err != nil {
			return fmt.Errorf("load provided certificate: %w", err)
		}
		tlsConfig.Certificates = append(tlsConfig.Certificates, cert)
	}

	// Configure the reverse proxy using NetBird's HTTP Client Transport for proxying.
	s.proxy = proxy.NewReverseProxy(s.netbird)

	// Configure the authentication middleware.
	s.auth = auth.NewMiddleware()

	// Configure Access logs to management server.
	accessLog := accesslog.NewLogger(mgmtClient, s.Logger)

	// Finally, start the reverse proxy.
	s.https = &http.Server{
		Addr:      addr,
		Handler:   accessLog.Middleware(s.auth.Protect(s.proxy)),
		TLSConfig: tlsConfig,
	}
	return s.https.ListenAndServeTLS("", "")
}

func (s *Server) newManagementMappingWorker(ctx context.Context, client proto.ProxyServiceClient) {
	b := backoff.New(0, 0)
	for {
		s.Logger.Debug("Getting mapping updates from management server")
		mappingClient, err := client.GetMappingUpdate(ctx, &proto.GetMappingUpdateRequest{
			ProxyId:   s.ID,
			Version:   s.Version,
			StartedAt: timestamppb.New(s.startTime),
			Address:   s.ProxyURL,
		})
		if err != nil {
			s.Logger.WithError(err).Warn("Could not get mapping updates, will retry")
			backoffDuration := b.Duration()
			s.Logger.WithFields(log.Fields{
				"backoff": backoffDuration,
				"error":   err,
			}).Error("Unable to create mapping client to management server, retrying connection after backoff")
			time.Sleep(backoffDuration)
			continue
		}
		s.Logger.Debug("Got mapping updates client from management server")
		err = s.handleMappingStream(ctx, mappingClient)
		backoffDuration := b.Duration()
		switch {
		case errors.Is(err, context.Canceled),
			errors.Is(err, context.DeadlineExceeded):
			// Context is telling us that it is time to quit so gracefully exit here.
			// No need to log the error as it is a parent context causing this return.
			s.Logger.Debugf("Got context error, will exit loop: %v", err)
			return
		case err != nil:
			// Log the error and then retry the connection.
			s.Logger.WithFields(log.Fields{
				"backoff": backoffDuration,
				"error":   err,
			}).Error("Error processing mapping stream from management server, retrying connection after backoff")
		default:
			// TODO: should this really be at error level? Maybe, if you start getting lots of these this could be an indication of connectivity issues.
			s.Logger.WithField("backoff", backoffDuration).Error("Management mapping connection terminated by the server, retrying connection after backoff")
		}
		time.Sleep(backoffDuration)
	}
}

func (s *Server) handleMappingStream(ctx context.Context, mappingClient proto.ProxyService_GetMappingUpdateClient) error {
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
			// Process msg updates sequentially to avoid conflict, so block
			// additional receiving until this processing is completed.
			for _, mapping := range msg.GetMapping() {
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
					s.updateMapping(ctx, mapping)
				case proto.ProxyMappingUpdateType_UPDATE_TYPE_REMOVED:
					s.removeMapping(ctx, mapping)
				}
			}
			s.Logger.Debug("Processing mapping update completed")
		}
	}
}

func (s *Server) addMapping(ctx context.Context, mapping *proto.ProxyMapping) error {
	if err := s.netbird.AddPeer(ctx, mapping.GetDomain(), mapping.GetSetupKey()); err != nil {
		return fmt.Errorf("create peer for domain %q: %w", mapping.GetDomain(), err)
	}
	if s.acme != nil {
		s.acme.AddDomain(mapping.GetDomain())
	}

	// Pass the mapping through to the update function to avoid duplicating the
	// setup, currently update is simply a subset of this function, so this
	// separation makes sense...to me at least.
	s.updateMapping(ctx, mapping)
	return nil
}

func (s *Server) updateMapping(ctx context.Context, mapping *proto.ProxyMapping) {
	// Very simple implementation here, we don't touch the existing peer
	// connection or any existing TLS configuration, we simply overwrite
	// the auth and proxy mappings.
	// Note: this does require the management server to always send a
	// full mapping rather than deltas during a modification.
	mgmtClient := proto.NewProxyServiceClient(s.mgmtConn)
	var schemes []auth.Scheme
	if mapping.GetAuth().GetPassword() {
		schemes = append(schemes, auth.NewPassword(mgmtClient, mapping.GetId(), mapping.GetAccountId()))
	}
	if mapping.GetAuth().GetPin() {
		schemes = append(schemes, auth.NewPin(mgmtClient, mapping.GetId(), mapping.GetAccountId()))
	}
	if mapping.GetAuth().GetOidc() != nil {
		oidc := mapping.GetAuth().GetOidc()
		schemes = append(schemes, auth.NewOIDC(mgmtClient, mapping.GetId(), mapping.GetAccountId(), auth.OIDCConfig{
			Issuer:             oidc.GetIssuer(),
			Audiences:          oidc.GetAudiences(),
			KeysLocation:       oidc.GetKeysLocation(),
			MaxTokenAgeSeconds: oidc.GetMaxTokenAge(),
		}))
	}
	if mapping.GetAuth().GetLink() {
		schemes = append(schemes, auth.NewLink(mgmtClient, mapping.GetId(), mapping.GetAccountId()))
	}
	s.auth.AddDomain(mapping.GetDomain(), schemes)
	s.proxy.AddMapping(s.protoToMapping(mapping))
}

func (s *Server) removeMapping(ctx context.Context, mapping *proto.ProxyMapping) {
	if err := s.netbird.RemovePeer(ctx, mapping.GetDomain()); err != nil {
		s.Logger.WithFields(log.Fields{
			"domain": mapping.GetDomain(),
			"error":  err,
		}).Error("Error removing NetBird peer connection for domain, continuing additional domain cleanup but peer connection may still exist")
	}
	if s.acme != nil {
		s.acme.RemoveDomain(mapping.GetDomain())
	}
	s.auth.RemoveDomain(mapping.GetDomain())
	s.proxy.RemoveMapping(s.protoToMapping(mapping))
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
				"error":      err,
			}).Error("Error parsing target URL for path, this path will be ignored but other paths will still be configured")
		}
		paths[pathMapping.GetPath()] = targetURL
	}
	return proxy.Mapping{
		ID:        mapping.GetId(),
		AccountID: mapping.AccountId,
		Host:      mapping.GetDomain(),
		Paths:     paths,
	}
}
