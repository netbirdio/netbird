//go:build !android

package net

import (
	"fmt"
	"syscall"
)

// SetSocketMark sets the SO_MARK option on the given socket connection
func SetSocketMark(conn syscall.Conn) error {
	sysconn, err := conn.SyscallConn()
	if err != nil {
		return fmt.Errorf("get raw conn: %w", err)
	}

	return SetRawSocketMark(sysconn)
}

func SetRawSocketMark(conn syscall.RawConn) error {
	var setErr error

	err := conn.Control(func(fd uintptr) {
		setErr = SetSocketOpt(int(fd))
	})
	if err != nil {
		return fmt.Errorf("control: %w", err)
	}

	if setErr != nil {
		return fmt.Errorf("set SO_MARK: %w", setErr)
	}

	return nil
}

func SetSocketOpt(fd int) error {
	if CustomRoutingDisabled() {
		return nil
	}

	return syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_MARK, NetbirdFwmark)
}
