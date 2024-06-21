package net

import (
	"syscall"

	log "github.com/sirupsen/logrus"
)

// init configures the net.ListenerConfig Control function to set the fwmark on the socket
func (l *ListenerConfig) init() {
	l.ListenConfig.Control = func(_, _ string, c syscall.RawConn) error {
		err := c.Control(func(fd uintptr) {
			androidProtectSocketLock.Lock()
			f := androidProtectSocket
			androidProtectSocketLock.Unlock()
			if f == nil {
				return
			}
			ok := f(int32(fd))
			if !ok {
				log.Errorf("failed to protect listener socket: %d", fd)
			}
		})
		return err
	}
}
