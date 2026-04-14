// Package deviceauth implements mTLS device certificate verification and
// policy enforcement for the NetBird management server.
package deviceauth

import (
	"context"
	"crypto/x509"
	"fmt"
	"sync"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/management/server/types"
)

// DeviceAuthHandler is the interface implemented by Handler.
// It is used for dependency injection in tests and in the gRPC server.
//
//nolint:revive // DeviceAuthHandler is intentionally prefixed; callers use the full deviceauth.DeviceAuthHandler name.
type DeviceAuthHandler interface {
	// VerifyPeerCert is called from tls.Config.VerifyPeerCertificate.
	// Returns nil when the certificate chain is valid (or absent).
	VerifyPeerCert(rawCerts [][]byte, _ [][]*x509.Certificate) error

	// CheckDeviceAuth enforces the DeviceAuthSettings policy for a peer.
	// cert is nil when no client certificate was presented.
	CheckDeviceAuth(ctx context.Context, wgPubKey string, certPresent bool, cert *x509.Certificate, settings *types.DeviceAuthSettings) error

	// UpdateCertPool atomically replaces the trusted CA pool.
	// Called by the background refresh loop when CAs change.
	UpdateCertPool(pool *x509.CertPool)
}

// Handler verifies device certificates and enforces the DeviceAuth policy.
// It is safe for concurrent use.
type Handler struct {
	mu       sync.RWMutex
	certPool *x509.CertPool
}

// NewHandler creates a Handler backed by the given certificate pool.
// An empty pool (x509.NewCertPool()) means no CA is trusted yet.
func NewHandler(pool *x509.CertPool) *Handler {
	return &Handler{certPool: pool}
}

// UpdateCertPool atomically replaces the trusted CA pool.
func (h *Handler) UpdateCertPool(pool *x509.CertPool) {
	h.mu.Lock()
	h.certPool = pool
	h.mu.Unlock()
}

// VerifyPeerCert implements tls.Config.VerifyPeerCertificate.
// If rawCerts is empty the peer presented no certificate — we return nil
// because the policy decision is deferred to CheckDeviceAuth.
func (h *Handler) VerifyPeerCert(rawCerts [][]byte, _ [][]*x509.Certificate) error {
	if len(rawCerts) == 0 {
		return nil
	}

	// Parse the leaf (first) certificate.
	leaf, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return fmt.Errorf("deviceauth: parse client certificate: %w", err)
	}

	h.mu.RLock()
	pool := h.certPool
	h.mu.RUnlock()

	_, err = leaf.Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	if err != nil {
		return fmt.Errorf("deviceauth: certificate verification failed: %w", err)
	}

	return nil
}

// CheckDeviceAuth applies the DeviceAuth policy matrix for a peer login attempt.
//
// Policy matrix:
//
//	Mode            | cert present & valid | cert absent
//	disabled        | pass                 | pass
//	optional        | pass                 | pass
//	cert-only       | pass (CN check)      | deny
//	cert-and-sso    | pass (CN check)      | deny
func (h *Handler) CheckDeviceAuth(
	_ context.Context,
	wgPubKey string,
	certPresent bool,
	cert *x509.Certificate,
	settings *types.DeviceAuthSettings,
) error {
	// Nil or disabled settings → no-op.
	if settings == nil || settings.Mode == "" || settings.Mode == types.DeviceAuthModeDisabled {
		return nil
	}

	switch settings.Mode {
	case types.DeviceAuthModeOptional:
		// Optional: cert is nice to have but not enforced.
		if certPresent && cert != nil {
			return checkCNCert(cert, wgPubKey)
		}
		return nil

	case types.DeviceAuthModeCertOnly, types.DeviceAuthModeCertAndSSO:
		if !certPresent || cert == nil {
			return status.Errorf(codes.PermissionDenied, "device certificate required for this account")
		}
		return checkCNCert(cert, wgPubKey)
	}

	// Unknown mode — fail closed to avoid silently bypassing device auth enforcement.
	return status.Errorf(codes.Internal, "deviceauth: unknown mode %q", settings.Mode)
}

// checkCNCert verifies that the certificate's Common Name matches the
// WireGuard public key of the connecting peer.
func checkCNCert(cert *x509.Certificate, wgPubKey string) error {
	if cert.Subject.CommonName != wgPubKey {
		return status.Errorf(codes.PermissionDenied,
			"deviceauth: certificate CN mismatch: got %q, want %q",
			cert.Subject.CommonName, wgPubKey)
	}
	return nil
}
