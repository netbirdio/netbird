package net

import (
	"syscall"
)

func (d *Dialer) init() {
	d.Dialer.Control = func(network, address string, c syscall.RawConn) error {
		return applyUnicastIFToSocket(network, address, c)
	}
}
