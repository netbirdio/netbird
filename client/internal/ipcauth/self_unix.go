//go:build !windows

package ipcauth

import "os"

// CurrentProcessIdentity returns this process's identity as the daemon would
// see it if this process connected to the local IPC. It lets a client (the UI)
// decide up front whether a privileged operation can succeed, without a
// round-trip and without duplicating the rules: the answer comes from the same
// Identity.IsPrivileged the daemon applies.
func CurrentProcessIdentity() (Identity, error) {
	return Identity{
		UID: uint32(os.Geteuid()),
		GID: uint32(os.Getegid()),
	}, nil
}
