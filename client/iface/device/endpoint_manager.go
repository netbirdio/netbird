package device

import (
	"net"
	"net/netip"
)

// EndpointManager manages fake IP to connection mappings for userspace bind implementations.
// Implemented by bind.ICEBind and bind.RelayBindJS.
type EndpointManager interface {
	SetEndpoint(fakeIP netip.Addr, conn net.Conn)
	RemoveEndpoint(fakeIP netip.Addr)
}
