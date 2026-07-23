// Package ipcauth provides the kernel-authenticated identity of a local IPC
// (gRPC) caller and the transport credentials that surface it into the gRPC
// context, so the daemon can authorize each RPC by caller identity.
//
// On Unix the identity is read from the kernel via SO_PEERCRED (Linux) or
// LOCAL_PEERCRED (Darwin/FreeBSD). On Windows it is derived from the named-pipe
// client token. Platforms without a peer-identity primitive get no credentials
// and therefore no enforcement (the daemon logs a warning and stays open,
// preserving today's behavior until the transport gains an identity primitive).
package ipcauth

import (
	"context"
	"fmt"

	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

// sidLocalSystem is the well-known Windows SID for the LocalSystem account.
const sidLocalSystem = "S-1-5-18"

// Identity is the kernel-authenticated identity of a local IPC caller. The zero
// value is not a valid identity; obtain one via IdentityFromContext (which
// reports presence) or PeerIdentity.
type Identity struct {
	// UID and GID are the caller's Unix user ID and primary group ID.
	// Zero on Windows, where SID is authoritative instead.
	UID uint32
	GID uint32

	// PID is the caller's process ID, for audit only. HasPID is false when the
	// platform cannot supply it (e.g. Darwin/FreeBSD xucred carries no PID).
	PID    int32
	HasPID bool

	// SID is the caller's Windows security identifier (empty on Unix).
	SID string

	// Groups holds the caller's Windows group SIDs, captured from the client
	// token at handshake (empty on Unix, where supplementary group membership is
	// resolved on demand via NSS/getent by the authorizer).
	Groups []string

	// Elevated reports whether the Windows client token is elevated (run as
	// administrator). Always false on Unix, where privilege is uid==0.
	Elevated bool
}

// IsWindows reports whether this identity is a Windows principal (SID-based)
// rather than a Unix uid/gid principal.
func (i Identity) IsWindows() bool {
	return i.SID != ""
}

// IsPrivileged reports whether the caller is the platform's administrative
// principal — Unix root (uid 0), or on Windows an elevated token or LocalSystem.
// It deliberately requires actual elevation on Windows (a non-elevated member of
// Administrators has a filtered token and is NOT privileged), mirroring "must
// really be root" on Unix.
func (i Identity) IsPrivileged() bool {
	if i.IsWindows() {
		return i.Elevated || i.SID == sidLocalSystem
	}
	return i.UID == 0
}

// String renders the identity for audit logs.
func (i Identity) String() string {
	if i.IsWindows() {
		if i.HasPID {
			return fmt.Sprintf("sid=%s elevated=%t pid=%d", i.SID, i.Elevated, i.PID)
		}
		return fmt.Sprintf("sid=%s elevated=%t", i.SID, i.Elevated)
	}
	if i.HasPID {
		return fmt.Sprintf("uid=%d gid=%d pid=%d", i.UID, i.GID, i.PID)
	}
	return fmt.Sprintf("uid=%d gid=%d", i.UID, i.GID)
}

// AuthInfo carries the peer Identity as a gRPC credentials.AuthInfo so the
// interceptor can retrieve it from the request context via IdentityFromContext.
type AuthInfo struct {
	credentials.CommonAuthInfo
	Identity Identity
}

// AuthType identifies the authentication scheme.
func (AuthInfo) AuthType() string { return "netbird-ipc-peercred" }

// IdentityFromContext extracts the caller's kernel-authenticated identity from
// the gRPC peer context. The second return value is false when no IPC transport
// credentials were negotiated (e.g. an unsupported platform, or a caller that
// did not come through the daemon socket) — callers MUST fail closed in that case.
func IdentityFromContext(ctx context.Context) (Identity, bool) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return Identity{}, false
	}
	info, ok := p.AuthInfo.(AuthInfo)
	if !ok {
		return Identity{}, false
	}
	return info.Identity, true
}
