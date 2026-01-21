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
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"path/filepath"
	"time"

	"github.com/cloudflare/backoff"
	"github.com/netbirdio/netbird/proxy/internal/accesslog"
	"github.com/netbirdio/netbird/proxy/internal/acme"
	"github.com/netbirdio/netbird/proxy/internal/auth"
	"github.com/netbirdio/netbird/proxy/internal/proxy"
	"github.com/netbirdio/netbird/proxy/internal/roundtrip"
	"github.com/netbirdio/netbird/shared/management/proto"
	"google.golang.org/grpc"
)

type errorLog interface {
	Error(msg string, args ...any)
	ErrorContext(ctx context.Context, msg string, args ...any)
}

type Server struct {
	mgmtConn *grpc.ClientConn
	proxy    *proxy.ReverseProxy
	netbird  *roundtrip.NetBird
	acme     *acme.Manager
	auth     *auth.Middleware
	http     *http.Server
	https    *http.Server

	ErrorLog                 errorLog
	ManagementAddress        string
	CertificateDirectory     string
	GenerateACMECertificates bool
	ACMEChallengeAddress     string
	ACMEDirectory            string
}

func (s *Server) ListenAndServe(ctx context.Context, addr string) (err error) {
	if s.ErrorLog == nil {
		// If no ErrorLog is specified, then just discard the log output.
		s.ErrorLog = slog.New(slog.DiscardHandler)
	}

	// The very first thing to do should be to connect to the Management server.
	// Without this connection, the Proxy cannot do anything.
	s.mgmtConn, err = grpc.NewClient(s.ManagementAddress)
	if err != nil {
		return fmt.Errorf("could not create management connection: %w", err)
	}
	mgmtClient := proto.NewProxyServiceClient(s.mgmtConn)
	go s.newManagementMappingWorker(ctx, mgmtClient)

	// Initialize the netbird client, this is required to build peer connections
	// to proxy over.
	s.netbird = roundtrip.NewNetBird(s.ManagementAddress)

	// When generating ACME certificates, start a challenge server.
	tlsConfig := &tls.Config{}
	if s.GenerateACMECertificates {
		s.acme = acme.NewManager(s.CertificateDirectory, s.ACMEDirectory)
		s.http = &http.Server{
			Addr:    s.ACMEChallengeAddress,
			Handler: s.acme.HTTPHandler(nil),
		}
		go func() {
			if err := s.http.ListenAndServe(); err != nil {
				// Rather than retry, log the issue periodically so that hopefully someone notices and fixes the issue.
				for range time.Tick(10 * time.Second) {
					s.ErrorLog.ErrorContext(ctx, "ACME HTTP-01 challenge server error", "error", err)
				}
			}
		}()
		tlsConfig = s.acme.TLSConfig()
	} else {
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
	accessLog := accesslog.NewLogger(mgmtClient, s.ErrorLog)

	// Finally, start the reverse proxy.
	s.https = &http.Server{
		Addr:      addr,
		Handler:   s.auth.Protect(accessLog.Middleware(s.proxy)),
		TLSConfig: tlsConfig,
	}
	return s.https.ListenAndServeTLS("", "")
}

func (s *Server) newManagementMappingWorker(ctx context.Context, client proto.ProxyServiceClient) func() {
	b := backoff.New(0, 0)
	return func() {
		for {
			mappingClient, err := client.GetMappingUpdate(ctx, &proto.GetMappingUpdateRequest{})
			if err != nil {
				backoffDuration := b.Duration()
				s.ErrorLog.ErrorContext(ctx, "Unable to create mapping client to management server, retrying connection after backoff.",
					"backoff", backoffDuration,
					"error", err)
				time.Sleep(backoffDuration)
				continue
			}
			err = s.handleMappingStream(ctx, mappingClient)
			backoffDuration := b.Duration()
			switch {
			case errors.Is(err, context.Canceled),
				errors.Is(err, context.DeadlineExceeded):
				// Context is telling us that it is time to quit so gracefully exit here.
				// No need to log the error as it is a parent context causing this return.
				return
			case err != nil:
				// Log the error and then retry the connection.
				s.ErrorLog.ErrorContext(ctx, "Error processing mapping stream from management server, retrying connection after backoff.",
					"backoff", backoffDuration,
					"error", err)
			default:
				// TODO: should this really be at error level? Maybe, if you start getting lots of these this could be an indication of connectivity issues.
				s.ErrorLog.ErrorContext(ctx, "Management mapping connection terminated by the server, retrying connection after backoff.",
					"backoff", backoffDuration)
			}
			time.Sleep(backoffDuration)
		}
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

			// Process msg updates sequentially to avoid conflict, so block
			// additional receiving until this processing is completed.
			for _, mapping := range msg.GetMapping() {
				switch mapping.GetType() {
				case proto.ProxyMappingUpdateType_UPDATE_TYPE_CREATED:
					if err := s.addMapping(ctx, mapping); err != nil {
						// TODO: Retry this? Or maybe notify the management server that this mapping has failed?
						s.ErrorLog.ErrorContext(ctx, "Error adding new mapping, ignoring this mapping and continuing processing.",
							"service_id", mapping.GetId(),
							"domain", mapping.GetDomain(),
							"error", err)
					}
				case proto.ProxyMappingUpdateType_UPDATE_TYPE_MODIFIED:
					s.updateMapping(ctx, mapping)
				case proto.ProxyMappingUpdateType_UPDATE_TYPE_REMOVED:
					s.removeMapping(mapping)
				}
			}
		}
	}
}

func (s *Server) addMapping(ctx context.Context, mapping *proto.ProxyMapping) error {
	if err := s.netbird.AddPeer(mapping.GetDomain(), mapping.GetSetupKey()); err != nil {
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
	var schemes []auth.Scheme
	if mapping.GetAuth().GetBasic().GetEnabled() {
		schemes = append(schemes, auth.NewBasicAuth(
			mapping.GetAuth().GetBasic().GetUsername(),
			mapping.GetAuth().GetBasic().GetPassword(),
		))
	}
	if mapping.GetAuth().GetPin().GetEnabled() {
		schemes = append(schemes, auth.NewPin(
			mapping.GetAuth().GetPin().GetPin(),
		))
	}
	if mapping.GetAuth().GetOidc().GetEnabled() {
		oidc := mapping.GetAuth().GetOidc()
		scheme, err := auth.NewOIDC(ctx, auth.OIDCConfig{
			OIDCProviderURL:  oidc.GetOidcProviderUrl(),
			OIDCClientID:     oidc.GetOidcClientId(),
			OIDCClientSecret: oidc.GetOidcClientSecret(),
			OIDCRedirectURL:  oidc.GetOidcRedirectUrl(),
			OIDCScopes:       oidc.GetOidcScopes(),
		})
		if err != nil {
			s.ErrorLog.Error("Failed to create OIDC scheme", "error", err)
		} else {
			schemes = append(schemes, scheme)
		}
	}
	s.auth.AddDomain(mapping.GetDomain(), schemes)
	s.proxy.AddMapping(s.protoToMapping(mapping))
}

func (s *Server) removeMapping(mapping *proto.ProxyMapping) {
	s.netbird.RemovePeer(mapping.GetDomain())
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
			s.ErrorLog.Error("Error parsing target URL for path, this path will be ignored but other paths will still be configured.",
				"service_id", mapping.GetId(),
				"domain", mapping.GetDomain(),
				"path", pathMapping.GetPath(),
				"target", pathMapping.GetTarget(),
				"error", err)
		}
		paths[pathMapping.GetPath()] = targetURL
	}
	return proxy.Mapping{
		ID:    mapping.GetId(),
		Host:  mapping.GetDomain(),
		Paths: paths,
	}
}
