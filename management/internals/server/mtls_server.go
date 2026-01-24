package server

// Machine Tunnel Fork - Separate mTLS Server on Port 33074
// This provides a dedicated port for mTLS-only machine clients with RequireAndVerifyClientCert.

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/netbirdio/netbird/management/internals/shared/mtls"
)

// MTLSServerPort is the default port for the mTLS-only Machine Tunnel server
const MTLSServerPort = 33074

// MTLSServer holds the mTLS-only gRPC server for Machine Tunnel clients
type MTLSServer struct {
	server       *grpc.Server
	listener     net.Listener
	caPool       *x509.CertPool
	tlsConfig    *tls.Config
	port         int
	interceptors []grpc.UnaryServerInterceptor
}

// NewMTLSServer creates a new mTLS-only server for Machine Tunnel clients
func NewMTLSServer(certFile, keyFile, caDir, caCertFile string, port int, interceptors []grpc.UnaryServerInterceptor) (*MTLSServer, error) {
	if port == 0 {
		port = MTLSServerPort
	}

	// Load server certificate
	serverCert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load server certificate: %w", err)
	}

	// Load CA pool for client certificate verification
	caPool, err := loadCAPool(caDir, caCertFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load CA pool: %w", err)
	}

	// Configure TLS with RequireAndVerifyClientCert
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert, // STRICT: Client cert required!
		ClientCAs:    caPool,
		MinVersion:   tls.VersionTLS12, // TLS 1.2+ required
	}

	log.Infof("mTLS server configured: port=%d, CA pool loaded with %d certificates", port, countCertsInPool(caPool))

	return &MTLSServer{
		caPool:       caPool,
		tlsConfig:    tlsConfig,
		port:         port,
		interceptors: interceptors,
	}, nil
}

// CreateGRPCServer creates the gRPC server with mTLS credentials and interceptors
func (s *MTLSServer) CreateGRPCServer() *grpc.Server {
	opts := []grpc.ServerOption{
		grpc.Creds(credentials.NewTLS(s.tlsConfig)),
	}

	// Add interceptors if provided
	if len(s.interceptors) > 0 {
		opts = append(opts, grpc.ChainUnaryInterceptor(s.interceptors...))
	}

	s.server = grpc.NewServer(opts...)
	return s.server
}

// Start starts the mTLS server on the configured port
func (s *MTLSServer) Start(ctx context.Context) error {
	if s.server == nil {
		return fmt.Errorf("gRPC server not created - call CreateGRPCServer first")
	}

	var err error
	s.listener, err = net.Listen("tcp", fmt.Sprintf(":%d", s.port))
	if err != nil {
		return fmt.Errorf("failed to listen on port %d: %w", s.port, err)
	}

	log.WithContext(ctx).Infof("starting mTLS-only Machine Tunnel server on port %d", s.port)

	go func() {
		if err := s.server.Serve(s.listener); err != nil {
			if ctx.Err() == nil {
				log.WithContext(ctx).Errorf("mTLS server error: %v", err)
			}
		}
	}()

	return nil
}

// Stop stops the mTLS server gracefully
func (s *MTLSServer) Stop() {
	if s.server != nil {
		s.server.GracefulStop()
	}
	if s.listener != nil {
		_ = s.listener.Close()
	}
	log.Info("mTLS server stopped")
}

// GetServer returns the underlying gRPC server for service registration
func (s *MTLSServer) GetServer() *grpc.Server {
	return s.server
}

// loadCAPool loads CA certificates from directory and/or single file
func loadCAPool(caDir, caCertFile string) (*x509.CertPool, error) {
	caPool := x509.NewCertPool()
	loaded := 0

	// Load from directory if specified
	if caDir != "" {
		dirLoaded, err := loadCAFromDirectory(caPool, caDir)
		if err != nil {
			log.Warnf("error loading CAs from directory %s: %v", caDir, err)
		}
		loaded += dirLoaded
	}

	// Load from single file if specified
	if caCertFile != "" {
		certPEM, err := os.ReadFile(caCertFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA cert file %s: %w", caCertFile, err)
		}
		if caPool.AppendCertsFromPEM(certPEM) {
			loaded++
			log.Infof("loaded CA certificate: %s", filepath.Base(caCertFile))
		} else {
			log.Warnf("failed to parse CA certificate from %s", caCertFile)
		}
	}

	if loaded == 0 {
		return nil, fmt.Errorf("no CA certificates loaded - mTLS requires at least one CA")
	}

	log.Infof("mTLS CA pool loaded: %d certificates", loaded)
	return caPool, nil
}

// loadCAFromDirectory loads all .crt, .pem, .cer files from a directory
func loadCAFromDirectory(pool *x509.CertPool, caDir string) (int, error) {
	entries, err := os.ReadDir(caDir)
	if err != nil {
		return 0, fmt.Errorf("failed to read CA directory: %w", err)
	}

	loaded := 0
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		name := strings.ToLower(entry.Name())
		if !strings.HasSuffix(name, ".crt") &&
			!strings.HasSuffix(name, ".pem") &&
			!strings.HasSuffix(name, ".cer") {
			continue
		}

		certPath := filepath.Join(caDir, entry.Name())
		certPEM, err := os.ReadFile(certPath)
		if err != nil {
			log.Warnf("failed to read CA cert %s: %v", certPath, err)
			continue
		}

		if pool.AppendCertsFromPEM(certPEM) {
			loaded++
			log.Infof("loaded CA certificate: %s", entry.Name())
		} else {
			log.Warnf("failed to parse CA certificate from %s", entry.Name())
		}
	}

	return loaded, nil
}

// countCertsInPool attempts to estimate certificates in pool (Go doesn't expose this)
// This is a workaround since x509.CertPool doesn't have a Count() method
func countCertsInPool(pool *x509.CertPool) int {
	if pool == nil {
		return 0
	}
	// Use Subjects() to count - each cert has one subject
	return len(pool.Subjects()) //nolint:staticcheck // Subjects() is deprecated but no alternative exists
}

// InitMTLSValidatorConfig initializes the global mTLS validator configuration
// from the server config. This should be called during server startup.
func InitMTLSValidatorConfig(accountAllowedIssuers map[string][]string) {
	if len(accountAllowedIssuers) == 0 {
		log.Warn("mTLS validator: no AccountAllowedIssuers configured - issuer validation will reject all certificates")
		return
	}

	mtls.SetValidatorConfig(&mtls.ValidatorConfig{
		AccountAllowedIssuers: accountAllowedIssuers,
	})
}
