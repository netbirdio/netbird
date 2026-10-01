//go:build !linux

package firewalld

import "context"

// SetParentContext is a no-op on non-Linux platforms because firewalld only
// runs on Linux.
func SetParentContext(context.Context) {
	// intentionally empty: firewalld is a Linux-only daemon
}

// TrustInterface is a no-op on non-Linux platforms because firewalld only
// runs on Linux.
func TrustInterface(string) error {
	// intentionally empty: firewalld is a Linux-only daemon
	return nil
}

// UntrustInterface is a no-op on non-Linux platforms because firewalld only
// runs on Linux.
func UntrustInterface(string) error {
	// intentionally empty: firewalld is a Linux-only daemon
	return nil
}
