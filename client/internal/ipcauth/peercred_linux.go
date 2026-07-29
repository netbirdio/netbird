//go:build linux

package ipcauth

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

// PeerIdentity reads the kernel-authenticated identity of the process on the
// other end of a Unix socket connection via SO_PEERCRED. The credentials are
// captured by the kernel at connect() time and cannot be spoofed or changed for
// the life of the connection.
func PeerIdentity(c net.Conn) (Identity, error) {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return Identity{}, fmt.Errorf("connection is not a unix socket: %T", c)
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return Identity{}, fmt.Errorf("raw conn: %w", err)
	}

	var cred *unix.Ucred
	var credErr error
	if err := raw.Control(func(fd uintptr) {
		cred, credErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return Identity{}, fmt.Errorf("getsockopt control: %w", err)
	}
	if credErr != nil {
		return Identity{}, fmt.Errorf("SO_PEERCRED: %w", credErr)
	}

	return Identity{
		UID: cred.Uid,
		GID: cred.Gid,
	}, nil
}
