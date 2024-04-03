//go:build !android

package net

import "syscall"

// init configures the net.Dialer Control function to set the fwmark on the socket
func (d *Dialer) init() {
	d.Dialer.Control = func(_, _ string, c syscall.RawConn) error {
		return SetRawSocketMark(c)
	}
}
