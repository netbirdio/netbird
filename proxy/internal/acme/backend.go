package acme

import (
	"crypto/tls"

	"github.com/netbirdio/netbird/proxy/internal/types"
	"github.com/netbirdio/netbird/shared/management/domain"
)

// CertBackend abstracts the ACME certificate engine so different challenge
// types can satisfy the same call sites in the proxy: autocert for
// tls-alpn-01 / http-01 (existing behavior) and Lego for dns-01 (new).
//
// SPIKE NOTE: this interface is sketched as part of the DNS-01 spike (see
// roadmap.md and p1-plan.md, Wave 1 task 1.1). Production work will lift
// the existing distributed locker above this interface so it wraps either
// backend uniformly. The existing *Manager already satisfies this shape
// implicitly, which is itself useful evidence that the abstraction is a
// good fit (see compile-time assertion below).
type CertBackend interface {
	GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error)
	AddDomain(d domain.Domain, accountID types.AccountID, serviceID types.ServiceID) (wildcardHit bool)
	RemoveDomain(d domain.Domain)
}

// Compile-time assertion that the existing *Manager (autocert-backed)
// satisfies CertBackend. This is the architectural proof: the abstraction
// fits the existing call sites without forcing a method signature change.
var _ CertBackend = (*Manager)(nil)
