//go:build !linux && !darwin && !freebsd && !windows

package ipcauth

import (
	"fmt"
	"net"
	"runtime"

	"google.golang.org/grpc/credentials"
)

// NewTransportCredentials returns nil on platforms without a peer-identity
// primitive.
func NewTransportCredentials() credentials.TransportCredentials {
	return nil
}

// ConnIdentity is unsupported on platforms without a peer-identity primitive.
func ConnIdentity(net.Conn) (Identity, error) {
	return Identity{}, fmt.Errorf("peer identity not supported on %s", runtime.GOOS)
}
