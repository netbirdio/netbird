//go:build !android

package net

import (
	"fmt"
	"os"
	"syscall"

	log "github.com/sirupsen/logrus"
)

const EnvSkipSocketMark = "NB_SKIP_SOCKET_MARK"

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
		log.Infof("Custom routing is disabled, skipping SO_MARK")
		return nil
	}

	// Check for the new environment variable
	if skipSocketMark := os.Getenv(EnvSkipSocketMark); skipSocketMark == "true" {
		log.Info("NB_SKIP_SOCKET_MARK is set to true, skipping SO_MARK")
		return nil
	}

	return syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_MARK, NetbirdFwmark)
}
