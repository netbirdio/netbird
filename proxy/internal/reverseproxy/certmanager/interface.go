package certmanager

import (
	"context"
	"crypto/tls"
	"net/http"
)

// Manager defines the interface for certificate management
type Manager interface {
	// IsEnabled returns whether certificate management is enabled
	IsEnabled() bool

	// AddDomain adds a domain to the allowed hosts list
	AddDomain(domain string)

	// RemoveDomain removes a domain from the allowed hosts list
	RemoveDomain(domain string)

	// IssueCertificate eagerly issues a certificate for a domain
	IssueCertificate(ctx context.Context, domain string) error

	// TLSConfig returns the TLS configuration for the HTTPS server
	TLSConfig() *tls.Config

	// HTTPHandler returns the HTTP handler for ACME challenges (or fallback)
	HTTPHandler(fallback http.Handler) http.Handler
}
