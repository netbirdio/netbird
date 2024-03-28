//go:build !android

package net

import (
	"syscall"
)

// init configures the net.ListenerConfig Control function to set the fwmark on the socket
func (l *ListenerConfig) init() {
	l.ListenConfig.Control = func(_, _ string, c syscall.RawConn) error {
		return SetRawSocketMark(c)
	}
}
