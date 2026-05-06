package device

import (
	"net"
	"net/netip"

	"github.com/netbirdio/netbird/client/iface/bind"
)

// EndpointManager manages fake IP to connection mappings for userspace bind implementations.
// Implemented by bind.ICEBind and bind.RelayBindJS.
type EndpointManager interface {
	SetEndpoint(fakeIP netip.Addr, conn net.Conn)
	RemoveEndpoint(fakeIP netip.Addr)
	// ActivityRecorder exposes the per-bind ActivityRecorder so the
	// engine can wire its OnActivity callback (Codex review 2026-05-05,
	// fast-path Relay -> P2P upgrade trigger). Always non-nil on
	// userspace binds. Kernel-mode WG returns nil from GetICEBind so
	// callers MUST nil-check the EndpointManager itself before
	// dereferencing.
	ActivityRecorder() *bind.ActivityRecorder
}
