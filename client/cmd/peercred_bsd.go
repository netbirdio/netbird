//go:build darwin || freebsd

package cmd

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

// peerUID returns the uid of the process on the other end of a unix socket
// connection, read via LOCAL_PEERCRED (xucred). Note: xucred carries the uid
// and group list but no pid, so audit on these platforms is uid-based.
func peerUID(c net.Conn) (int, error) {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return 0, fmt.Errorf("connection is not a unix socket: %T", c)
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return 0, fmt.Errorf("raw conn: %w", err)
	}

	var cred *unix.Xucred
	var credErr error
	if err := raw.Control(func(fd uintptr) {
		cred, credErr = unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	}); err != nil {
		return 0, fmt.Errorf("getsockopt control: %w", err)
	}
	if credErr != nil {
		return 0, fmt.Errorf("LOCAL_PEERCRED: %w", credErr)
	}
	return int(cred.Uid), nil
}
