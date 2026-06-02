//go:build !android

package net

import (
	"fmt"
	"syscall"
)

// SetSocketMark sets the SO_MARK option on the given socket connection
func SetSocketMark(conn syscall.Conn) error {
	if !AdvancedRouting() {
		return nil
	}

	sysconn, err := conn.SyscallConn()
	if err != nil {
		return fmt.Errorf("get raw conn: %w", err)
	}

	return setRawSocketMark(sysconn)
}

// SetSocketOpt sets the SO_MARK option on the given file descriptor
func SetSocketOpt(fd int) error {
	if !AdvancedRouting() {
		return nil
	}

	return setSocketOptInt(fd)
}

func setRawSocketMark(conn syscall.RawConn) error {
	var setErr error

	err := conn.Control(func(fd uintptr) {
		if !AdvancedRouting() {
			return
		}
		setErr = setSocketOptInt(int(fd))
	})
	if err != nil {
		return fmt.Errorf("control: %w", err)
	}

	if setErr != nil {
		return fmt.Errorf("set SO_MARK: %w", setErr)
	}

	return nil
}

func setSocketOptInt(fd int) error {
	return syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_MARK, ControlPlaneMark)
}
