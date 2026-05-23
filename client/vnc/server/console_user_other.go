//go:build !darwin && !windows

package server

// consoleHasInteractiveUser is unused outside service mode (darwin/windows)
// but the symbol must exist so gateApproval compiles on all platforms.
func consoleHasInteractiveUser() bool { return true }
