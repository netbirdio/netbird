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

// GroupResolver resolves a Unix caller's effective group IDs and owner group
// names to GIDs. A nil resolver disables group matching.
type GroupResolver interface {
	// CallerGIDs returns the set of group IDs the caller belongs to.
	CallerGIDs(id Identity) map[uint32]struct{}
	// GroupNameGID resolves a group name to its GID.
	GroupNameGID(name string) (uint32, bool)
}

// Authorize reports whether the identity may control a profile with the given
// ownership. Privileged callers and shared profiles are always allowed.
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
