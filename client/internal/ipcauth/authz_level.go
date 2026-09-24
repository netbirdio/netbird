package ipcauth

import (
	"google.golang.org/grpc/codes"
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

// RequireLevel builds a rule from a level, for composing inside another rule.
func RequireLevel(want AuthzLevel) Rule {
	return func(r Request) error {
		if r.Level >= want {
			return nil
		}
		return denyLevel(r, want)
	}
}

func denyLevel(r Request, want AuthzLevel) error {
	return gstatus.Errorf(codes.PermissionDenied,
		"%s requires %s, caller %s is %s", r.Method, want, r.Identity, r.Level)
}

// denyPolicyLevel refuses a caller at the gate, where the policy is in hand.
//
// A privileged method that declares no action keeps the plain message. Rules
// deny through denyLevel instead: they cannot reach the policy table without an
// initialization cycle, and no rule requires privilege.
func denyPolicyLevel(r Request, p MethodPolicy, target Target) error {
	switch p.Level {
	case AuthzLevelPrivileged:
		if p.Action != "" {
			return denyPrivileged(p, target)
		}

	case AuthzLevelSessionHolder:
		// resolveLevel stops at profile owner only when a session is running and
		// somebody else holds it.
		if r.Level == AuthzLevelProfileOwner {
			return SessionHeldError(p.Action)
		}
		return denyOwnership(p.Action, r.Identity, target)

	case AuthzLevelProfileOwner:
		return denyOwnership(p.Action, r.Identity, target)
	}

	return denyLevel(r, p.Level)
}

// denyPrivileged refuses a method that needs a privileged caller.
// Claiming a profile is currently the only privileged method
func denyPrivileged(p MethodPolicy, target Target) error {
	actor, command := RequiredActor(ClaimCommand(target.Handle))
	return PrivilegeError(PrivilegeSummary(p.Action, actor), command)
}

// denyOwnership refuses a caller with no standing on the profile. Only a profile
// nobody has claimed is theirs to put right, so only that one carries a command.
func denyOwnership(action string, id Identity, target Target) error {
	if target.UnOwned {
		return UnownedError(action, target.Handle, consoleLookup(id))
	}
	return NotOwnerError(action)
}
