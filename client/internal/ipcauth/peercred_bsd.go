//go:build darwin || freebsd

package ipcauth

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

// PeerIdentity reads the kernel-authenticated identity of the process on the
// other end of a Unix socket via LOCAL_PEERCRED. The xucred is recorded by the
// kernel at connect() time and carries the peer's uid and its group list, of
// which the first entry is the primary group.
func PeerIdentity(conn net.Conn) (Identity, error) {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return Identity{}, fmt.Errorf("connection is not a unix socket: %T", conn)
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
		return Identity{}, fmt.Errorf("control raw conn: %w", err)
	}
	if credErr != nil {
		return Identity{}, fmt.Errorf("read LOCAL_PEERCRED: %w", credErr)
	}

	id := Identity{UID: cred.Uid}
	if cred.Ngroups > 0 {
		id.GID = cred.Groups[0]
	}
	return id, nil
}
