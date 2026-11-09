package modeldiscovery

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"os"
	"syscall"
)

// Fetch serves two callers with different needs: the model picker, which only
// needs to know it failed, and the provider credential check, which has to
// tell an operator whether the URL or the key is at fault. Each failure
// carries a type so the second does not have to branch on a message.

// VendorStatusError reports a listing answered with something other than 200.
// Only the vendor's own code separates a refused credential (401, 403) from a
// URL that does not serve this API (404, 405) from an unwell vendor (5xx).
type VendorStatusError struct {
	Provider string
	Status   int
}

func (e *VendorStatusError) Error() string {
	return fmt.Sprintf("%s returned %d for its model listing", e.Provider, e.Status)
}

// UnreachableError reports that the request never reached the vendor: the
// name did not resolve, the connection was refused, TLS failed, or it timed
// out. Nothing was authenticated, so only the URL is implicated.
type UnreachableError struct {
	Provider string
	Err      error
}

func (e *UnreachableError) Error() string {
	return fmt.Sprintf("reach %s: %v", e.Provider, e.Err)
}

func (e *UnreachableError) Unwrap() error { return e.Err }

// Reason names the transport failure in words an operator can act on: a wrong
// port and a wrong hostname fail differently and are worth telling apart.
// Empty means unrecognised, and the caller should say only that the host could
// not be reached rather than paste a Go error into the UI.
func (e *UnreachableError) Reason() string {
	err := e.Err

	var dns *net.DNSError
	if errors.As(err, &dns) {
		if dns.IsNotFound {
			return "no such host"
		}
		// Named apart from the dial timeout below. A resolver that never
		// answered and an upstream that never answered send an operator to
		// different places, and the generic "connection timed out" would
		// describe a connection that was never attempted.
		if dns.IsTimeout {
			return "dns lookup timed out"
		}
		return "dns lookup failed"
	}

	// Timeouts are checked before the syscall cases: a dial that times out is
	// reported as a net.OpError wrapping a timeout, and the operator needs to
	// hear "timed out" rather than the syscall underneath it.
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) {
		return "connection timed out"
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return "connection timed out"
	}

	if errors.Is(err, syscall.ECONNREFUSED) {
		return "connection refused"
	}
	if errors.Is(err, syscall.EHOSTUNREACH) || errors.Is(err, syscall.ENETUNREACH) {
		return "host unreachable"
	}

	var certErr *tls.CertificateVerificationError
	if errors.As(err, &certErr) {
		return "tls certificate not trusted"
	}
	var recordErr tls.RecordHeaderError
	if errors.As(err, &recordErr) {
		return "not a tls endpoint"
	}

	return ""
}

// ErrUnparseableListing marks a 200 whose body is not a listing in the shape
// the catalog declared. Distinct from a status refusal: the host answered and
// authenticated fine, it is just not the API — a login page, say.
var ErrUnparseableListing = errors.New("response is not a model listing")

// ErrNoDiscoveryHost marks a provider whose listing host cannot be derived
// from the record: Bedrock's control-plane host comes from the region in the
// upstream, so a proxied endpoint leaves nowhere to send it, and inventing one
// would spend the credential somewhere never configured.
//
// Wraps ErrInvalidRequest so the discovery endpoint still answers 400, while a
// credential check can read it as "cannot be checked" rather than "broken".
var ErrNoDiscoveryHost = errors.New("provider has no derivable discovery host")

// ErrPrivateHost marks an upstream resolving somewhere management will not
// dial. A self-hosted endpoint on a private network is a legitimate provider
// the proxy reaches through the tunnel, so this means the check cannot run,
// not that the record is wrong.
var ErrPrivateHost = errors.New("discovery host is not publicly routable")
