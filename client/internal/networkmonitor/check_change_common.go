//go:build dragonfly || freebsd || netbsd || openbsd || darwin

package networkmonitor

import (
	"context"
	"errors"
	"fmt"
	"syscall"
	"unsafe"

	log "github.com/sirupsen/logrus"
	"golang.org/x/net/route"
	"golang.org/x/sys/unix"

	"github.com/netbirdio/netbird/client/internal/routemanager/systemops"
)

func prepareFd() (int, error) {
	return unix.Socket(syscall.AF_ROUTE, syscall.SOCK_RAW, syscall.AF_UNSPEC)
}

func routeCheck(ctx context.Context, fd int, nexthopv4, nexthopv6 systemops.Nexthop) error {
	for {
		// Wait until fd is readable or context is cancelled, to avoid a busy-loop
		// when the routing socket returns EAGAIN (e.g. immediately after wakeup).
		if err := waitReadable(ctx, fd); err != nil {
			return err
		}

		buf := make([]byte, 2048)
		n, err := unix.Read(fd, buf)
		if err != nil {
			if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR) {
				continue
			}
			if errors.Is(err, unix.EBADF) || errors.Is(err, unix.EINVAL) {
				return fmt.Errorf("routing socket closed: %w", err)
			}
			return fmt.Errorf("read routing socket: %w", err)
		}

		if n < unix.SizeofRtMsghdr {
			log.Debugf("Network monitor: read from routing socket returned less than expected: %d bytes", n)
			continue
		}

		msg := (*unix.RtMsghdr)(unsafe.Pointer(&buf[0]))

		switch msg.Type {
		// handle route changes
		case unix.RTM_ADD, syscall.RTM_DELETE:
			route, err := parseRouteMessage(buf[:n])
			if err != nil {
				log.Debugf("Network monitor: error parsing routing message: %v", err)
				continue
			}

			if route.Dst.Bits() != 0 {
				continue
			}

			intf := "<nil>"
			if route.Interface != nil {
				intf = route.Interface.Name
			}
			switch msg.Type {
			case unix.RTM_ADD:
				log.Infof("Network monitor: default route changed: via %s, interface %s", route.Gw, intf)
				return nil
			case unix.RTM_DELETE:
				if nexthopv4.Intf != nil && route.Gw.Compare(nexthopv4.IP) == 0 || nexthopv6.Intf != nil && route.Gw.Compare(nexthopv6.IP) == 0 {
					log.Infof("Network monitor: default route removed: via %s, interface %s", route.Gw, intf)
					return nil
				}
			}
		}
	}
}

func parseRouteMessage(buf []byte) (*systemops.Route, error) {
	msgs, err := route.ParseRIB(route.RIBTypeRoute, buf)
	if err != nil {
		return nil, fmt.Errorf("parse RIB: %v", err)
	}

	if len(msgs) != 1 {
		return nil, fmt.Errorf("unexpected RIB message msgs: %v", msgs)
	}

	msg, ok := msgs[0].(*route.RouteMessage)
	if !ok {
		return nil, fmt.Errorf("unexpected RIB message type: %T", msgs[0])
	}

	return systemops.MsgToRoute(msg)
}

// waitReadable blocks until fd has data to read, or ctx is cancelled.
func waitReadable(ctx context.Context, fd int) error {
	var fdset unix.FdSet
	if fd < 0 || fd/unix.NFDBITS >= len(fdset.Bits) {
		return fmt.Errorf("fd %d out of range for FdSet", fd)
	}

	for {
		if err := ctx.Err(); err != nil {
			return err
		}

		fdset = unix.FdSet{}
		fdset.Set(fd)
		// Use a 1-second timeout so we can re-check ctx periodically.
		tv := unix.Timeval{Sec: 1}
		n, err := unix.Select(fd+1, &fdset, nil, nil, &tv)
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			return fmt.Errorf("select on routing socket: %w", err)
		}
		if n > 0 {
			return nil
		}
		// timeout — loop back and re-check ctx
	}
}
