package embed

import (
	"context"
	"errors"

	"github.com/netbirdio/netbird/client/internal/expose"
)

const (
	// ExposeProtocolHTTP exposes the service as HTTP.
	ExposeProtocolHTTP = expose.ProtocolHTTP
	// ExposeProtocolHTTPS exposes the service as HTTPS.
	ExposeProtocolHTTPS = expose.ProtocolHTTPS
	// ExposeProtocolTCP exposes the service as TCP.
	ExposeProtocolTCP = expose.ProtocolTCP
	// ExposeProtocolUDP exposes the service as UDP.
	ExposeProtocolUDP = expose.ProtocolUDP
	// ExposeProtocolTLS exposes the service as TLS.
	ExposeProtocolTLS = expose.ProtocolTLS
)

// ExposeRequest is a request to expose a local service via the NetBird reverse proxy.
type ExposeRequest = expose.Request

// ExposeProtocolType represents the protocol used for exposing a service.
type ExposeProtocolType = expose.ProtocolType

// ExposeSession represents an active expose session. Use Wait to block until the session ends.
type ExposeSession struct {
	Domain      string
	ServiceName string
	ServiceURL  string

	mgr *expose.Manager
}

// Wait blocks while keeping the expose session alive.
// It returns when ctx is cancelled or a keep-alive error occurs, then terminates the session.
func (s *ExposeSession) Wait(ctx context.Context) error {
	if s == nil || s.mgr == nil {
		return errors.New("expose session is not initialized")
	}
	return s.mgr.KeepAlive(ctx, s.Domain)
}
