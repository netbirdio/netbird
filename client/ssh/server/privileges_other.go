//go:build !windows

package server

// isProcessElevated is only meaningful on Windows; other platforms use the
// effective UID check in isCurrentProcessPrivileged.
func isProcessElevated() bool {
	return false
}

// isWindowsAccountPrivileged is only reachable on Windows. Fail closed if it
// is ever called on another platform.
func isWindowsAccountPrivileged(string) bool {
	return true
}
