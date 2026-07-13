package portforward

import (
	"context"
	"net"
	"time"
)

// Mapping represents an active NAT port mapping.
type Mapping struct {
	Protocol     string
	InternalPort uint16
	ExternalPort uint16
	ExternalIP   net.IP
	NATType      string
	// TTL is the lease duration. Zero means a permanent lease that never expires.
	TTL time.Duration
}

// Manager is a stub for js/wasm builds where NAT-PMP/UPnP is not supported.
type Manager struct{}

// NewManager returns a stub manager for js/wasm builds.
func NewManager() *Manager {
	return &Manager{}
}

// Start is a no-op on js/wasm: NAT-PMP/UPnP is not available in browser environments.
func (m *Manager) Start(context.Context, uint16) {
	// no NAT traversal in wasm
}

// GracefullyStop is a no-op on js/wasm.
func (m *Manager) GracefullyStop(context.Context) error { return nil }

// GetMapping always returns nil on js/wasm.
func (m *Manager) GetMapping() *Mapping {
	return nil
}
