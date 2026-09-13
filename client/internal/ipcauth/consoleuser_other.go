//go:build !linux && !darwin && !freebsd && !windows

package ipcauth

// isConsoleUser has no meaning on a platform that exposes no console-user
// lookup, where nobody is ever at a console.
//
// Mobile is not built from here: ios satisfies darwin and android satisfies
// linux, so both take those lookups, which are present but never find a GUI
// session or a seat.
func isConsoleUser(Identity) bool {
	return false
}
