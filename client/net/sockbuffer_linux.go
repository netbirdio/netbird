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

// forceSocketBuffers sets the receive and send buffers with SO_RCVBUFFORCE /
// SO_SNDBUFFORCE, which bypass net.core.rmem_max/wmem_max when the process holds
// CAP_NET_ADMIN (typically when running as root). Returns true only when both
// options were set, so the caller can fall back to the portable path otherwise.
func forceSocketBuffers(conn any, size int) bool {
	rc, ok := conn.(rawConnProvider)
	if !ok {
		return false
	}
	raw, err := rc.SyscallConn()
	if err != nil {
		log.Debugf("failed to get raw conn for forced relay socket sizing: %s", err)
		return false
	}

	var setErr error
	ctrlErr := raw.Control(func(fd uintptr) {
		if e := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUFFORCE, size); e != nil {
			setErr = e
			return
		}
		if e := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_SNDBUFFORCE, size); e != nil {
			setErr = e
		}
	})
	if ctrlErr != nil {
		log.Debugf("failed to control relay socket for forced sizing: %s", ctrlErr)
		return false
	}
	if setErr != nil {
		log.Debugf("forced relay socket sizing unavailable (%s); using portable sizing", setErr)
		return false
	}
	return true
}

// logRelaySocketBuffers reads back the effective SO_RCVBUF/SO_SNDBUF and logs
// them at debug level. The kernel stores roughly twice the requested value for
// its own bookkeeping, so the reported numbers are about 2x what was asked for.
func logRelaySocketBuffers(conn any) {
	rc, ok := conn.(rawConnProvider)
	if !ok {
		return
	}
	raw, err := rc.SyscallConn()
	if err != nil {
		return
	}

	var rcv, snd int
	if err := raw.Control(func(fd uintptr) {
		rcv, _ = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF)
		snd, _ = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_SNDBUF)
	}); err != nil {
		return
	}
	log.Debugf("relay socket buffers: rcvbuf=%d sndbuf=%d (kernel-reported, ~2x requested)", rcv, snd)
}
