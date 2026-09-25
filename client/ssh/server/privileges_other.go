//go:build !windows

package server

// isProcessElevated is only meaningful on Windows; other platforms use the
// effective UID check in isCurrentProcessPrivileged.
func isProcessElevated() bool {
	return false
}

// isWindowsAccountPrivilegedOrUnknown is only reachable on Windows. Report
// privileged on other platforms so a caller refusing privileged accounts fails
// closed.
func isWindowsAccountPrivilegedOrUnknown(string) bool {
	return true
}
