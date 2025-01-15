package net

import (
	"fmt"
	"sync"
	"syscall"
)

var (
	androidProtectSocketLock sync.Mutex
	androidProtectSocket     func(fd int32) bool
)

func SetAndroidProtectSocketFn(fn func(fd int32) bool) {
	androidProtectSocketLock.Lock()
	androidProtectSocket = fn
	androidProtectSocketLock.Unlock()
}

// ControlProtectSocket is a Control function that sets the fwmark on the socket
func ControlProtectSocket(_, _ string, c syscall.RawConn) error {
	var aErr error
	err := c.Control(func(fd uintptr) {
		androidProtectSocketLock.Lock()
		defer androidProtectSocketLock.Unlock()

		if androidProtectSocket == nil {
			aErr = fmt.Errorf("socket protection function not set")
			return
		}

		if !androidProtectSocket(int32(fd)) {
			aErr = fmt.Errorf("failed to protect socket via Android")
		}
	})

	if err != nil {
		return err
	}

	return aErr
}
