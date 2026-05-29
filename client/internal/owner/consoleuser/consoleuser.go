// Package consoleuser provides the OS-level "active console user" UID lookup
// used to gate ownership TOFU. The active console user is the local user
// physically at the machine (or in the foreground GUI session): the user that
// can legitimately claim the daemon as theirs on first run.
package consoleuser

// ActiveUID returns the UID of the currently active console / GUI session
// user, and true if such a user exists. Returns 0, false on platforms without
// a console concept (ios, android), on headless servers with no active
// session, or on lookup failure.
//
// Implementations must fail closed: any error or ambiguity returns (0, false)
// so that the caller treats the result as "no console user" rather than
// granting access to an unverified UID.
func ActiveUID() (uint32, bool) {
	return activeUID()
}
