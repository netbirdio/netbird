package ipcauth

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

// Strint() resolves a AuthzLevel to a human readable debug string.
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

func resolveLevel(id Identity, target string, st DaemonState) AuthzLevel {
	if !id.Known() {
		return AuthzLevelNone
	}
	if IsPrivilegedCaller(id) {
		return AuthzLevelPrivileged
	}
	if !st.OwnsProfile(id, target) {
		return AuthzLevelIdentified
	}
	if holder, running := st.SessionHolder(); !running || holder.Matches(id) {
		return AuthzLevelSessionHolder
	}
	return AuthzLevelProfileOwner
}
