package acme

import (
	"context"
	"crypto/tls"
)

// CertBackend is the issuer and on-disk store for ACME certificates. The
// orchestrator (Manager) layers domain tracking, distributed locking, and
// wildcard pre-filtering on top of any backend that satisfies this
// interface, so different ACME challenge types can plug in uniformly.
//
// Implementations are responsible for:
//   - Issuing certificates against an ACME server when GetCertificate is
//     called for an unknown domain
//   - Persisting issued certificates and their keys to disk
//   - Reading already-issued certificates back from disk, in whatever
//     storage layout the backend uses
//
// Implementations are NOT responsible for:
//   - Domain registration or state tracking (orchestrator's job)
//   - Cross-replica locking (the orchestrator wraps issuance in a lock)
//   - Wildcard cert pre-matching (orchestrator handles this above the backend)
type CertBackend interface {
	// GetCertificate returns a usable TLS certificate for hello.ServerName.
	// Implementations may issue fresh via ACME if needed, or load from
	// their on-disk cache. Called from the TLS handshake path and from
	// the orchestrator's prefetch loop with a synthetic ClientHello.
	GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error)

	// ReadCertFromDisk loads an already-issued certificate from the
	// backend's on-disk cache without triggering issuance. Used by the
	// orchestrator's prefetch loop to detect when another replica has
	// written the certificate, allowing the local issuance attempt to
	// short-circuit. Returns an error if no valid certificate is on disk.
	ReadCertFromDisk(ctx context.Context, name string) (*tls.Certificate, error)
}

// HostPolicySetter is an optional interface that backends with a host-level
// policy gate (such as autocert) can implement so the orchestrator can
// install a domain-registration check that runs before issuance.
//
// Backends that issue certificates only when explicitly invoked for a
// specific domain (such as Lego's DNS-01 path) do not need to implement
// this interface — there is no callback path through which they could
// issue certs for unregistered domains.
type HostPolicySetter interface {
	SetHostPolicy(fn func(ctx context.Context, host string) error)
}
