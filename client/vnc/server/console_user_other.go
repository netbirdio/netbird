//go:build !darwin && !windows

package server

// interactiveUserError is unused outside service mode (darwin/windows) but
// the symbol must exist so gateApproval compiles on all platforms.
func interactiveUserError() error { return nil }
