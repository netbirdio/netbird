//go:build !linux && !darwin && !freebsd && !windows

package ipcauth

import (
	"errors"
	"net"

	"google.golang.org/grpc/credentials"
)

// errUnsupported is returned on platforms with no local peer-identity
// primitive, so consumers fail closed instead of guessing an identity.
var errUnsupported = errors.New("peer identity is not available on this platform")

// NewTransportCredentials returns nil: without a peer-identity primitive the
// daemon cannot authenticate local callers, and the caller must treat that as
// "authorization cannot be enforced".
func NewTransportCredentials() credentials.TransportCredentials {
	return nil
}

// PeerIdentity always fails on this platform.
func PeerIdentity(net.Conn) (Identity, error) {
	return Identity{}, errUnsupported
}

// ConnIdentity always fails on this platform.
func ConnIdentity(net.Conn) (Identity, error) {
	return Identity{}, errUnsupported
}
