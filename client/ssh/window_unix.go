//go:build linux || darwin

package ssh

import (
	"os"
	"syscall"
	"unsafe"
)

func setWinSize(file *os.File, w, h int) {
	syscall.Syscall(syscall.SYS_IOCTL, file.Fd(), uintptr(syscall.TIOCSWINSZ), //nolint
		uintptr(unsafe.Pointer(&struct{ h, w, x, y uint16 }{uint16(h), uint16(w), 0, 0})))
}
