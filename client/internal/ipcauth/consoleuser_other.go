//go:build !linux && !darwin && !freebsd && !windows

package ipcauth

// isConsoleUser has no meaning on a platform that exposes no console-user
// lookup, where nobody is ever at a console.
//
// Android is not built from here: it satisfies linux and takes that lookup,
// which is present but never finds a seat.
func isConsoleUser(Identity) bool {
	return false
}
