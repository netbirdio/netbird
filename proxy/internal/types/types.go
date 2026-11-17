// Package types defines common types used across the proxy package.
package types

import (
	"context"
	"net"
	"time"
)

// AccountID represents a unique identifier for a NetBird account.
type AccountID string

// ServiceID represents a unique identifier for a proxy service.
type ServiceID string

// ServiceMode describes how a reverse proxy service is exposed.
type ServiceMode string

const (
	ServiceModeHTTP ServiceMode = "http"
	ServiceModeTCP  ServiceMode = "tcp"
	ServiceModeUDP  ServiceMode = "udp"
	ServiceModeTLS  ServiceMode = "tls"
)

// IsL4 returns true for TCP, UDP, and TLS modes.
func (m ServiceMode) IsL4() bool {
	return m == ServiceModeTCP || m == ServiceModeUDP || m == ServiceModeTLS
}

// RelayDirection indicates the direction of a relayed packet.
type RelayDirection string

const (
	RelayDirectionClientToBackend RelayDirection = "client_to_backend"
	RelayDirectionBackendToClient RelayDirection = "backend_to_client"
)

// DialContextFunc dials a backend through the WireGuard tunnel.
type DialContextFunc func(ctx context.Context, network, address string) (net.Conn, error)

// dialTimeoutKey is the context key for a per-request dial timeout.
type dialTimeoutKey struct{}

// WithDialTimeout returns a context carrying a dial timeout that
// DialContext wrappers can use to scope the timeout to just the
// connection establishment phase.
func WithDialTimeout(ctx context.Context, d time.Duration) context.Context {
	return context.WithValue(ctx, dialTimeoutKey{}, d)
}

// DialTimeoutFromContext returns the dial timeout from the context, if set.
func DialTimeoutFromContext(ctx context.Context) (time.Duration, bool) {
	d, ok := ctx.Value(dialTimeoutKey{}).(time.Duration)
	return d, ok && d > 0
}

// overlayOriginKey is the context key set by per-account inbound
// listeners to mark a request as originating from the WireGuard
// overlay rather than the public-facing host listener.
type overlayOriginKey struct{}

// WithOverlayOrigin marks the context as originating from the
// embedded NetBird overlay (tunnel-side inbound listener).
func WithOverlayOrigin(ctx context.Context) context.Context {
	return context.WithValue(ctx, overlayOriginKey{}, true)
}

// IsOverlayOrigin reports whether the request reached the proxy via
// the overlay listener. Middlewares that only make sense for WAN
// traffic (geolocation, CrowdSec IP reputation) should short-circuit
// when this is true.
func IsOverlayOrigin(ctx context.Context) bool {
	v, _ := ctx.Value(overlayOriginKey{}).(bool)
	return v
}
