//go:build darwin || freebsd

package ipcauth

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

// PeerIdentity reads the kernel-authenticated identity of the process on the
// other end of a Unix socket connection via LOCAL_PEERCRED (xucred). xucred
// carries the uid and primary group.
func PeerIdentity(c net.Conn) (Identity, error) {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return Identity{}, fmt.Errorf("connection is not a unix socket: %T", c)
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return Identity{}, fmt.Errorf("raw conn: %w", err)
	}

	var cred *unix.Xucred
	var credErr error
	if err := raw.Control(func(fd uintptr) {
		cred, credErr = unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	}); err != nil {
		return Identity{}, fmt.Errorf("getsockopt control: %w", err)
	}
	if credErr != nil {
		return Identity{}, fmt.Errorf("LOCAL_PEERCRED: %w", credErr)
	}

	id := Identity{UID: cred.Uid}
	// Groups[0] is the effective (primary) GID; guard against an empty list.
	if cred.Ngroups > 0 {
		id.GID = cred.Groups[0]
	}
	return id, nil
}
