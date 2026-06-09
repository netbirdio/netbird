//go:build !android

package system

import (
	"context"
	"net"
)

// getNetInterfaces returns the list of system network interfaces.
// On non-Android platforms net.Interfaces() works fine and the context is unused.
func getNetInterfaces(_ context.Context) ([]net.Interface, error) {
	return net.Interfaces()
}

// getInterfaceAddrs returns the addresses of a specific interface.
func getInterfaceAddrs(_ context.Context, iface *net.Interface) ([]net.Addr, error) {
	return iface.Addrs()
}

// WithIFaceDiscover is a no-op on non-Android platforms; the parent context
// is returned unchanged. Defined here so callers (e.g. the engine) can call
// it unconditionally without build-tag gymnastics.
func WithIFaceDiscover(parent context.Context, _ IFaceDiscoverFunc) context.Context {
	return parent
}
