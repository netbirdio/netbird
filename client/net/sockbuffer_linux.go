//go:build linux

package net

import (
	"syscall"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

type rawConnProvider interface {
	SyscallConn() (syscall.RawConn, error)
}

func growSocketBuffers(conn any, size int) {
	rc, ok := conn.(rawConnProvider)
	if !ok {
		log.Debugf("relay socket buffer sizing skipped: %T has no raw connection", conn)
		return
	}
	raw, err := rc.SyscallConn()
	if err != nil {
		log.Debugf("relay socket buffer sizing skipped: get raw conn: %v", err)
		return
	}

	growSocketBuffer(raw, "receive", unix.SO_RCVBUF, unix.SO_RCVBUFFORCE, size)
	growSocketBuffer(raw, "send", unix.SO_SNDBUF, unix.SO_SNDBUFFORCE, size)
}

// growSocketBuffer raises one buffer to size unless it is already at least that large.
// The forced option goes first because it ignores rmem_max/wmem_max. The unforced
// fallback is capped by them, so it only shrinks a buffer already above twice that cap.
func growSocketBuffer(raw syscall.RawConn, name string, opt, forceOpt, size int) {
	before, err := getSockoptInt(raw, opt)
	if err != nil {
		log.Debugf("relay socket %s buffer sizing skipped: read current size: %v", name, err)
		return
	}
	// The kernel doubles a requested size for its own overhead and reports the doubled
	// value, but reports an untouched socket's default as is.
	if before >= 2*size {
		log.Debugf("relay socket %s buffer already %d bytes, keeping it", name, before)
		return
	}

	if err := setSockoptInt(raw, forceOpt, size); err != nil {
		log.Debugf("forced relay socket %s buffer sizing unavailable: %v", name, err)
		if err := setSockoptInt(raw, opt, size); err != nil {
			log.Debugf("failed to set relay socket %s buffer to %d bytes: %v", name, size, err)
			return
		}
	}

	after, err := getSockoptInt(raw, opt)
	if err != nil {
		log.Debugf("failed to read back relay socket %s buffer: %v", name, err)
		return
	}
	log.Debugf("relay socket %s buffer set from %d to %d bytes (kernel-reported)", name, before, after)
}

func getSockoptInt(raw syscall.RawConn, opt int) (int, error) {
	var value int
	var sockErr error
	if err := raw.Control(func(fd uintptr) {
		value, sockErr = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, opt)
	}); err != nil {
		return 0, err
	}
	return value, sockErr
}

func setSockoptInt(raw syscall.RawConn, opt, value int) error {
	var sockErr error
	if err := raw.Control(func(fd uintptr) {
		sockErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, opt, value)
	}); err != nil {
		return err
	}
	return sockErr
}
