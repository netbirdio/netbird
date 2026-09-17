package ipcauth

import (
	gstatus "google.golang.org/grpc/status"
)

// AuthzLevel is the authority a caller holds over the daemon's current state.
// The values are ordered, and each level can do everything the levles below
// it can. A MethodPolicy is satisfied when the caller's level is at least
// the level the method requires.
type AuthzLevel uint8

const (
	// AuthzLevelNone is a caller whose kernel identity could not be established.
	AuthzLevelNone AuthzLevel = iota

	// AuthzLevelIdentified is any caller the kernel could verify.
	AuthzLevelIdentified

	// AuthzLevelProfileOwner is a caller being the owner of the current targeted
	// profile
	AuthzLevelProfileOwner

	// AuthzLevelSessionHolder is a caller that owns the current active profile
	// and the session is currently connected (after running UP).
	AuthzLevelSessionHolder

	// AuthzLevelPrivileged is root, an elevated administrator or the daemon's
	// own identity (if running as less privileges than root).
	AuthzLevelPrivileged
)

// String() resolves a AuthzLevel to a human readable debug string.
func (l AuthzLevel) String() string {
	switch l {
	case AuthzLevelIdentified:
		return "identified"
	case AuthzLevelProfileOwner:
		return "profile owner"
	case AuthzLevelSessionHolder:
		return "session holder"
	case AuthzLevelPrivileged:
		return "privileged"
	default:
		return "unidentified"
	}
}

// resolveLevel is the authority the caller holds over the profile the request
// names. The second return is what was wrong with the handle, when that is
// worth showing the caller instead of a refusal. It never raises the level: a
// resolution that failed still denies.
func resolveLevel(id Identity, target string, st DaemonState) (AuthzLevel, error) {
	if !id.Known() {
		return AuthzLevelNone, nil
	}
	if IsPrivilegedCaller(id) {
		return AuthzLevelPrivileged, nil
	}
	ownsProfile, err := st.OwnsProfile(id, target)
	if _, ok := gstatus.FromError(err); !ok {
		return AuthzLevelIdentified, err
	}
	if !ownsProfile {
		return AuthzLevelIdentified, nil
	}
	if holder, running := st.SessionHolder(); !running || holder.Matches(id) {
		return AuthzLevelSessionHolder, nil
	}
	return AuthzLevelProfileOwner, nil
}
