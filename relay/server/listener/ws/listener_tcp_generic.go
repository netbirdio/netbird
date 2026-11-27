//go:build !linux

package ws

import "syscall"

func controlTCP(_, _ string, _ syscall.RawConn) error {
	return nil
}
