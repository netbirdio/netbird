package net

import (
	"syscall"

	log "github.com/sirupsen/logrus"
)

func (d *Dialer) init() {
	d.Dialer.Control = func(_, _ string, c syscall.RawConn) error {
		err := c.Control(func(fd uintptr) {
			androidProtectSocketLock.Lock()
			f := androidProtectSocket
			androidProtectSocketLock.Unlock()
			if f == nil {
				return
			}
			ok := f(int32(fd))
			if !ok {
				log.Errorf("failed to protect socket: %d", fd)
			}
		})
		return err
	}
}
