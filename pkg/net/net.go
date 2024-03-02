package net

import (
	"fmt"
	"syscall"
)

const (
	// NetbirdFwmark is the fwmark value used by Netbird via wireguard
	NetbirdFwmark = 0x1BD00
)

// SetSocketMark sets the SO_MARK option on the given socket connection
func SetSocketMark(conn syscall.Conn) error {
	sysconn, err := conn.SyscallConn()
	if err != nil {
		return fmt.Errorf("failed to obtain syscall.Conn: %v", err)
	}

	return SetRawSocketMark(sysconn)
}

func SetRawSocketMark(conn syscall.RawConn) error {
	var setErr error

	err := conn.Control(func(fd uintptr) {
		setErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, NetbirdFwmark)
	})
	if err != nil {
		return fmt.Errorf("control: %v", err)
	}

	if setErr != nil {
		return fmt.Errorf("set SO_MARK: %w", setErr)
	}

	return nil
}
