//go:build freebsd

package server

// describeProcess records nothing: FreeBSD runs virtual sessions but mounts no
// procfs by default, so there is no start time to pin an identity to, and
// without a way to tell a reused PID from the original a record would only
// invite an unsafe kill later.
//
// FreeBSD-only rather than shared with the other non-Linux platforms: Windows
// and macOS have no virtual sessions to describe, so a stub there is dead code.
func describeProcess(_ int) sessionProcess {
	return sessionProcess{}
}
