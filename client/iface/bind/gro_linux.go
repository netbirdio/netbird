//go:build linux

package bind

import (
	"net"

	"golang.org/x/sys/unix"
)

// disableUDPGRO turns UDP GRO off on conn, so the kernel delivers one datagram
// per message again.
func disableUDPGRO(conn *net.UDPConn) error {
	rc, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var sockErr error
	if err := rc.Control(func(fd uintptr) {
		sockErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_UDP, unix.UDP_GRO, 0)
	}); err != nil {
		return err
	}
	return sockErr
}
