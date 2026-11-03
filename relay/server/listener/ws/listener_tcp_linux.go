package ws

import (
	"fmt"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const tcpUserTimeout = 20 * time.Second

func controlTCP(_, _ string, c syscall.RawConn) error {
	var sockErr error
	if err := c.Control(func(fd uintptr) {
		sockErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_USER_TIMEOUT, int(tcpUserTimeout.Milliseconds()))
	}); err != nil {
		return fmt.Errorf("control socket: %w", err)
	}
	if sockErr != nil {
		return fmt.Errorf("set TCP_USER_TIMEOUT: %w", sockErr)
	}
	return nil
}
