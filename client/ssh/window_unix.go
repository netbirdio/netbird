//go:build linux || darwin

package ssh

import (
	"os"
	"syscall"
	"unsafe"
)

func setWinSize(file *os.File, width, height int) {
	syscall.Syscall(syscall.SYS_IOCTL, file.Fd(), uintptr(syscall.TIOCSWINSZ), //nolint
		uintptr(unsafe.Pointer(&struct{ h, w, x, y uint16 }{uint16(height), uint16(width), 0, 0})))
}
