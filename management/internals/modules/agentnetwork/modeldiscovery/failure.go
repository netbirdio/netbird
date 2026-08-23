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

// The errors below exist so a caller can tell one discovery failure from
// another without reading the message. Fetch is used for two jobs now: filling
// the model picker, which only needs to know that it failed, and checking a
// provider's credential at save time, which has to tell the operator whether
// the URL or the key is the problem. A string is the wrong thing to branch on
// for the second, so each failure carries its own type.

// VendorStatusError reports that the vendor answered the listing with
// something other than 200. Status is the vendor's own code: 401 and 403 mean
// the credential was refused, 404 and 405 mean the URL does not serve this
// API at all, and 5xx means the vendor is unwell — three different things to
// tell an operator, and only the number separates them.
type VendorStatusError struct {
	Provider string
	Status   int
}

func (e *VendorStatusError) Error() string {
	return fmt.Sprintf("%s returned %d for its model listing", e.Provider, e.Status)
}

// UnreachableError reports that the request never reached the vendor at all:
// the name did not resolve, the connection was refused, TLS failed, or the
// attempt timed out. Nothing was authenticated, so the credential is not
// implicated — only the URL is.
type UnreachableError struct {
	Provider string
	Err      error
}

func (e *UnreachableError) Error() string {
	return fmt.Sprintf("reach %s: %v", e.Provider, e.Err)
}

func (e *UnreachableError) Unwrap() error { return e.Err }

// Reason names the transport failure in the words an operator can act on.
// "connection refused" and "no such host" are the difference between a wrong
// port and a wrong hostname, which is worth the few lines it takes to tell
// them apart. An empty string means the cause was not one we recognise, and
// the caller should say only that the host could not be reached rather than
// paste a Go error into the UI.
func (e *UnreachableError) Reason() string {
	err := e.Err

	var dns *net.DNSError
	if errors.As(err, &dns) {
		if dns.IsNotFound {
			return "no such host"
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

// ErrUnparseableListing marks a 200 whose body is not a model listing in the
// shape the catalog declared. It is a distinct outcome from a status refusal:
// the host answered and authenticated fine, it just is not the API we were
// aiming at — a login page or an unrelated service on the configured URL.
var ErrUnparseableListing = errors.New("response is not a model listing")

// ErrNoDiscoveryHost marks a provider whose listing host cannot be worked out
// from the record. Bedrock's listing lives on a control-plane host derived
// from the region in the upstream, so an operator pointing the record at a
// proxied or self-hosted endpoint leaves nowhere to send it. Inventing a host
// would spend their credential somewhere they never configured.
//
// It wraps ErrInvalidRequest so the discovery endpoint keeps answering 400,
// while a credential check can recognise it as "cannot be checked" rather
// than "is broken".
var ErrNoDiscoveryHost = errors.New("provider has no derivable discovery host")

// ErrPrivateHost marks an upstream that resolves somewhere the management
// server will not dial. A self-hosted vendor endpoint on a private network is
// a legitimate provider — the proxy reaches it through the tunnel — so this
// means the check cannot run, not that the record is wrong.
var ErrPrivateHost = errors.New("discovery host is not publicly routable")
