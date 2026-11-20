package keepalive

import (
	"fmt"
	"net"
	"time"

	"golang.org/x/sys/unix"
)

// Idle returns the keepalive idle time set on the TCP socket below conn.
func Idle(conn net.Conn) (time.Duration, error) {
	tc, ok := TCPConn(conn)
	if !ok {
		return 0, ErrNotTCP
	}
	raw, err := tc.SyscallConn()
	if err != nil {
		return 0, fmt.Errorf("raw conn: %w", err)
	}
	var secs int
	var serr error
	if err := raw.Control(func(fd uintptr) {
		secs, serr = unix.GetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_KEEPALIVE)
	}); err != nil {
		return 0, fmt.Errorf("control: %w", err)
	}
	if serr != nil {
		return 0, fmt.Errorf("getsockopt: %w", serr)
	}
	return time.Duration(secs) * time.Second, nil
}
