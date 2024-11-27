//go:build !android

package net

import (
	"fmt"
	"syscall"

	log "github.com/sirupsen/logrus"
)

// SetSocketMark sets the SO_MARK option on the given socket connection
func SetSocketMark(conn syscall.Conn) error {
	if isSocketMarkDisabled() {
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
	if isSocketMarkDisabled() {
		return nil
	}

	return setSocketOptInt(fd)
}

func setRawSocketMark(conn syscall.RawConn) error {
	var setErr error

	err := conn.Control(func(fd uintptr) {
		if isSocketMarkDisabled() {
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
	return syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_MARK, NetbirdFwmark)
}

func isSocketMarkDisabled() bool {
	if CustomRoutingDisabled() {
		log.Infof("Custom routing is disabled, skipping SO_MARK")
		return true
	}

	if SkipSocketMark() {
		return true
	}
	return false
}
