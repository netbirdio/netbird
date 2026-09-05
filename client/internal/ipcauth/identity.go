// Package ipcauth provides the kernel-authenticated identity of a local IPC
// (gRPC) caller and the transport credentials that surface it into the gRPC
// context, so the daemon can authorize individual RPCs by caller identity.
//
// On Unix the identity is read from the kernel via SO_PEERCRED (Linux) or
// LOCAL_PEERCRED (Darwin/FreeBSD). On Windows it is derived from the
// named-pipe client token. Platforms without a peer-identity primitive get no
// credentials, and every consumer must fail closed when no identity is
// available.
package ipcauth

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

// Well-known Windows SIDs that identify a fully privileged principal.
const (
	sidLocalSystem    = "S-1-5-18"     // NT AUTHORITY\SYSTEM
	sidLocalService   = "S-1-5-19"     // NT AUTHORITY\LOCAL SERVICE
	sidNetworkService = "S-1-5-20"     // NT AUTHORITY\NETWORK SERVICE
	sidAdministrators = "S-1-5-32-544" // BUILTIN\Administrators
)

// Identity is the kernel-authenticated identity of a local IPC caller. The
// zero value is not a valid identity: consumers must only use one obtained
// with a true ok/nil error return.
type Identity struct {
	// UID and GID are the caller's Unix user ID and primary group ID. Both are
	// zero on Windows, where SID is authoritative instead.
	UID uint32
	GID uint32

	// SID is the caller's Windows security identifier, empty on Unix.
	SID string

	// Groups holds the caller's Windows group SIDs, captured from the client
	// token at handshake time. Only groups that are enabled and not
	// deny-only are captured, so a group listed here is one the caller can
	// actually exercise. Empty on Unix.
	Groups []string

	// Elevated reports whether the Windows client token is elevated (running
	// as administrator, or an administrator with UAC turned off). Always false
	// on Unix, where privilege is uid 0.
	Elevated bool

	// PID is the caller's process ID where the platform reports it (Linux's
	// SO_PEERCRED), and 0 where it does not. It identifies the daemon's own
	// process dialling itself, which is what the JSON gateway does, and is never
	// used to grant anything.
	PID int32
}

// IsWindows reports whether this identity is a Windows principal (SID-based)
// rather than a Unix uid/gid principal.
func (i Identity) IsWindows() bool {
	return i.SID != ""
}

// IsPrivileged reports whether the caller is the platform's administrative
// principal, which is what the daemon requires for changes that cross the
// user-to-root boundary.
//
// On Windows the decision comes from the caller's token rather than from
// account names or group RIDs: an elevated token, one of the service accounts
// the daemon itself may run as, or a token with BUILTIN\Administrators
// enabled. A UAC-filtered administrator has that group marked deny-only, and
// deny-only groups are dropped when the identity is captured, so such a
// caller is correctly reported as unprivileged. Domain group memberships
// (Domain Admins and friends) are deliberately not consulted: they say
// nothing about what this token may do on this machine.
func (i Identity) IsPrivileged() bool {
	if !i.IsWindows() {
		return i.UID == 0
	}

	if i.Elevated {
		return true
	}

	switch i.SID {
	case sidLocalSystem, sidLocalService, sidNetworkService:
		return true
	}

	return slices.Contains(i.Groups, sidAdministrators)
}

// SameUser reports whether two identities are the same local principal. Only
// the account is compared: the group set and the elevation flag describe what a
// token may do, not who it belongs to. A SID on either side decides the
// comparison, so a Windows principal never matches a Unix one on the UID both
// happen to leave at zero. The zero Identity carries uid 0, so callers must
// establish that both identities are real before the answer means anything.
func (i Identity) SameUser(other Identity) bool {
	if i.SID != "" || other.SID != "" {
		return i.SID == other.SID
	}
	return i.UID == other.UID
}

// String renders the identity for audit logs and denial messages.
func (i Identity) String() string {
	if i.IsWindows() {
		return fmt.Sprintf("sid=%s elevated=%t", i.SID, i.Elevated)
	}
	return fmt.Sprintf("uid=%d gid=%d", i.UID, i.GID)
}

// AuthInfo carries the peer Identity as a gRPC credentials.AuthInfo so
// handlers can retrieve it from the request context via IdentityFromContext.
type AuthInfo struct {
	credentials.CommonAuthInfo
	Identity Identity
}

// AuthType identifies the authentication scheme.
func (AuthInfo) AuthType() string { return "netbird-ipc-peercred" }

// IdentityFromContext extracts the caller's kernel-authenticated identity from
// the gRPC peer context. The second return value is false when no IPC
// transport credentials were negotiated, which happens on a TCP daemon socket
// and on platforms without a peer-identity primitive. Callers MUST fail closed
// in that case.
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

// PrincipalKind is the type of an owner principal.
type PrincipalKind string

const (
	KindUID PrincipalKind = "uid" // Unix user ID
	KindSID PrincipalKind = "sid" // Windows user or group SID
)

// Principal is a parsed owner entry from a profile's Owners list.
type Principal struct {
	Kind  PrincipalKind
	Value string
}

// ParsePrincipal parses a "kind:value" owner string. Returns false for empty
// values or unknown kinds so malformed entries are ignored rather than trusted.
func ParsePrincipal(s string) (Principal, bool) {
	kind, value, ok := strings.Cut(s, ":")
	if !ok || value == "" {
		return Principal{}, false
	}
	switch PrincipalKind(kind) {
	case KindUID, KindSID:
		return Principal{Kind: PrincipalKind(kind), Value: value}, true
	default:
		return Principal{}, false
	}
}

// UIDPrincipal builds the owner string for a Unix user ID.
func UIDPrincipal(uid uint32) string {
	return string(KindUID) + ":" + strconv.FormatUint(uint64(uid), 10)
}

// SIDPrincipal builds the owner string for a Windows SID.
func SIDPrincipal(sid string) string { return string(KindSID) + ":" + sid }

// OwnerPrincipalForIdentity returns the self-ownership principal for an identity:
// the user's UID on Unix, or the user's SID on Windows.
func OwnerPrincipalForIdentity(id Identity) string {
	if id.IsWindows() {
		return SIDPrincipal(id.SID)
	}
	return UIDPrincipal(id.UID)
}
