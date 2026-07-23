package ipcauth

import (
	"slices"
	"strconv"
)

// Ownership is a profile's access policy: the typed owner principals plus the
// opt-in shared flag.
type Ownership struct {
	Owners []string
	Shared bool
}

// GroupResolver resolves a Unix caller's effective group IDs (primary +
// supplementary, NSS-aware) and owner group names to GIDs. It is only consulted
// for Unix `gid:`/`group:` owners; Windows uses the SIDs carried in the Identity.
// A nil resolver disables group matching.
type GroupResolver interface {
	// CallerGIDs returns the set of group IDs the caller belongs to.
	CallerGIDs(id Identity) map[uint32]struct{}
	// GroupNameGID resolves a group name to its GID.
	GroupNameGID(name string) (uint32, bool)
}

// Authorize reports whether the identity may control a profile with the given
// ownership. Privileged callers (root / elevated-admin / LocalSystem) and shared
// profiles are always allowed; otherwise the identity must match one of the
// owner principals.
func Authorize(o Ownership, id Identity, r GroupResolver) bool {
	if id.IsPrivileged() {
		return true
	}
	if o.Shared {
		return true
	}
	for _, raw := range o.Owners {
		p, ok := ParsePrincipal(raw)
		if !ok {
			continue
		}
		if principalMatches(p, id, r) {
			return true
		}
	}
	return false
}

func principalMatches(p Principal, id Identity, r GroupResolver) bool {
	switch p.Kind {
	case KindUID:
		if id.IsWindows() {
			return false
		}
		uid, err := strconv.ParseUint(p.Value, 10, 32)
		return err == nil && uint32(uid) == id.UID
	case KindGID:
		if id.IsWindows() {
			return false
		}
		gid, err := strconv.ParseUint(p.Value, 10, 32)
		return err == nil && callerHasGID(uint32(gid), id, r)
	case KindGroup:
		if id.IsWindows() || r == nil {
			return false
		}
		gid, ok := r.GroupNameGID(p.Value)
		return ok && callerHasGID(gid, id, r)
	case KindSID:
		if !id.IsWindows() {
			return false
		}
		return id.SID == p.Value || slices.Contains(id.Groups, p.Value)
	default:
		return false
	}
}

// callerHasGID reports whether gid is the caller's primary GID (from peercred,
// no lookup) or one of their supplementary groups (NSS-resolved via r).
func callerHasGID(gid uint32, id Identity, r GroupResolver) bool {
	if id.GID == gid {
		return true
	}
	if r == nil {
		return false
	}
	_, ok := r.CallerGIDs(id)[gid]
	return ok
}
