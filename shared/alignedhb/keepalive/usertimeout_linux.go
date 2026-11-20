package keepalive

import (
	"fmt"
	"net"
	"time"

	"golang.org/x/sys/unix"
)

// setUserTimeout sets TCP_USER_TIMEOUT on the socket below tc: how long
// unacknowledged data may sit before the kernel closes the connection.
func setUserTimeout(tc *net.TCPConn, timeout time.Duration) error {
	raw, err := tc.SyscallConn()
	if err != nil {
		return fmt.Errorf("raw conn: %w", err)
	}
	var serr error
	if err := raw.Control(func(fd uintptr) {
		serr = unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_USER_TIMEOUT, int(timeout.Milliseconds()))
	}); err != nil {
		return fmt.Errorf("control: %w", err)
	}
	if serr != nil {
		return fmt.Errorf("setsockopt: %w", serr)
	}
	return nil
}

// userTimeout returns the TCP_USER_TIMEOUT set on the socket below tc.
func userTimeout(tc *net.TCPConn) (time.Duration, error) {
	raw, err := tc.SyscallConn()
	if err != nil {
		return 0, fmt.Errorf("raw conn: %w", err)
	}
	var millis int
	var serr error
	if err := raw.Control(func(fd uintptr) {
		millis, serr = unix.GetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_USER_TIMEOUT)
	}); err != nil {
		return 0, fmt.Errorf("control: %w", err)
	}
	if serr != nil {
		return 0, fmt.Errorf("getsockopt: %w", serr)
	}
	return time.Duration(millis) * time.Millisecond, nil
}
