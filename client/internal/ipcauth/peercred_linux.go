//go:build linux

package ipcauth

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

// PeerIdentity reads the kernel-authenticated identity of the process on the
// other end of a Unix socket via SO_PEERCRED. The credentials are recorded by
// the kernel at connect() time and cannot be changed for the life of the
// connection, so they are not spoofable by the caller.
func PeerIdentity(conn net.Conn) (Identity, error) {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return Identity{}, fmt.Errorf("connection is not a unix socket: %T", conn)
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
		return Identity{}, fmt.Errorf("control raw conn: %w", err)
	}
	if credErr != nil {
		return Identity{}, fmt.Errorf("read SO_PEERCRED: %w", credErr)
	}

	return Identity{UID: cred.Uid, GID: cred.Gid, PID: cred.Pid}, nil
}
