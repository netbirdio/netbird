//go:build !linux && !darwin && !freebsd && !windows

package ipcauth

// activeUID has no meaning on platforms without a console-user concept
// (ios, android).
func activeIdentity() (Identity, bool) {
	return Identity{}, false
}
