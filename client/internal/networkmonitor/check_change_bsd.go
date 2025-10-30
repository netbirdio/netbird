//go:build dragonfly || freebsd || netbsd || openbsd

package networkmonitor

import (
	"context"
	"errors"
	"fmt"
	"syscall"
	"unsafe"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	"github.com/netbirdio/netbird/client/internal/routemanager/systemops"
)

func checkChange(ctx context.Context, nexthopv4, nexthopv6 systemops.Nexthop) error {
	fd, err := unix.Socket(syscall.AF_ROUTE, syscall.SOCK_RAW, syscall.AF_UNSPEC)
	if err != nil {
		return fmt.Errorf("open routing socket: %v", err)
	}
	defer func() {
		err := unix.Close(fd)
		if err != nil && !errors.Is(err, unix.EBADF) {
			log.Warnf("Network monitor: failed to close routing socket: %v", err)
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			buf := make([]byte, 2048)
			n, err := unix.Read(fd, buf)
			if err != nil {
				if !errors.Is(err, unix.EBADF) && !errors.Is(err, unix.EINVAL) {
					log.Warnf("Network monitor: failed to read from routing socket: %v", err)
				}
				continue
			}
			if n < unix.SizeofRtMsghdr {
				log.Debugf("Network monitor: read from routing socket returned less than expected: %d bytes", n)
				continue
			}

			msg := (*unix.RtMsghdr)(unsafe.Pointer(&buf[0]))

			if handleRouteMessage(msg, buf[:n], nexthopv4, nexthopv6) {
				return
			}
		}
	}
}
