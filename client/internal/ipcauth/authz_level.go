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
// resolved to. A profile the caller does not own confers nothing beyond being
// identified, which is also what an unresolved handle leaves them with.
func resolveLevel(id Identity, target Target, st DaemonState) AuthzLevel {
	if !id.Known() {
		return AuthzLevelNone
	}
	if IsPrivilegedCaller(id) {
		return AuthzLevelPrivileged
	}
	if !target.Owned {
		return AuthzLevelIdentified
	}
	if holder, running := st.SessionHolder(); !running || holder.Matches(id) {
		return AuthzLevelSessionHolder
	}
	return AuthzLevelProfileOwner
}

// presentableHandleError keeps a resolution failure only when the gate can put
// it in front of the caller in place of its own refusal. Everything else is
// dropped, and the caller gets the refusal their level earned.
func presentableHandleError(handle string, err error) error {
	if err == nil {
		return nil
	}

	// An empty handle is the active profile rather than something the caller
	// typed, so a failure to resolve it is not theirs to correct.
	if handle == "" {
		return nil
	}

	// Only a gRPC status reaches the caller as a sentence the CLI and the UI
	// render. A plain error is a daemon-side failure, and putting it on the
	// wire would tell the caller about the daemon rather than about the handle
	// they gave.
	if _, ok := gstatus.FromError(err); !ok {
		return nil
	}
	return err
}
