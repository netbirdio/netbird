package owner

import (
	"context"

	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

// UnixAuthInfo implements credentials.AuthInfo carrying the peer's UID from SO_PEERCRED.
type UnixAuthInfo struct {
	credentials.CommonAuthInfo
	UID UID
	GID uint32
	PID int32
}

// AuthType returns the authentication type.
func (u UnixAuthInfo) AuthType() string {
	return "unix_peercred"
}

// UIDFromContext extracts the caller's UID from the gRPC peer context.
// Returns uid and true if Unix credentials were available, 0 and false otherwise.
func UIDFromContext(ctx context.Context) (UID, bool) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return 0, false
	}

	info, ok := p.AuthInfo.(UnixAuthInfo)
	if !ok {
		return 0, false
	}

	return info.UID, true
}
