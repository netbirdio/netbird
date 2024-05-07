package net

import "sync"

var (
	androidProtectSocketLock sync.Mutex
	androidProtectSocket     func(fd int32) bool
)

func SetAndroidProtectSocketFn(f func(fd int32) bool) {
	androidProtectSocketLock.Lock()
	androidProtectSocket = f
	androidProtectSocketLock.Unlock()
}
