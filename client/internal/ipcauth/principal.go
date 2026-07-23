package ipcauth

import (
	"strconv"
	"strings"
)

// PrincipalKind is the type of an owner principal.
type PrincipalKind string

const (
	KindUID   PrincipalKind = "uid"   // Unix user ID
	KindGID   PrincipalKind = "gid"   // Unix group ID
	KindGroup PrincipalKind = "group" // Unix group name (NSS-resolved)
	KindSID   PrincipalKind = "sid"   // Windows user or group SID
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
	case KindUID, KindGID, KindGroup, KindSID:
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
// the user's UID on Unix, or the user's SID on Windows. Used to auto-isolate a
// new profile to its creator.
func OwnerPrincipalForIdentity(id Identity) string {
	if id.IsWindows() {
		return SIDPrincipal(id.SID)
	}
	return UIDPrincipal(id.UID)
}
