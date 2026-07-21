//go:build !linux && !darwin && !freebsd && !windows

package ipcauth

import "google.golang.org/grpc/credentials"

// NewTransportCredentials returns nil on platforms without a peer-identity
// primitive. The daemon falls back to insecure credentials and skips per-RPC
// authorization (logging a warning), preserving pre-hardening behavior until
// the transport gains an identity primitive.
func NewTransportCredentials() credentials.TransportCredentials {
	return nil
}
