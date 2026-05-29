//go:build !linux && !darwin && !freebsd

package owner

import "google.golang.org/grpc/credentials"

// NewUnixTransportCredentials returns nil on platforms without Unix socket peer credentials.
// The daemon should use insecure credentials and skip owner enforcement.
func NewUnixTransportCredentials() credentials.TransportCredentials {
	return nil
}
