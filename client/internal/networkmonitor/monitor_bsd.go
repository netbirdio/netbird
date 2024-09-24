//go:build (darwin && !ios) || dragonfly || freebsd || netbsd || openbsd

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

func checkChange(ctx context.Context, nexthopv4, nexthopv6 systemops.Nexthop, callback func()) error {
	fd, err := unix.Socket(syscall.AF_ROUTE, syscall.SOCK_RAW, syscall.AF_UNSPEC)
	if err != nil {
		return fmt.Errorf("failed to open routing socket: %v", err)
	}
	defer func() {
		err := unix.Close(fd)
		if err != nil && !errors.Is(err, unix.EBADF) {
			log.Warnf("Network monitor: failed to close routing socket: %v", err)
		}
	}()

	go func() {
		<-ctx.Done()
		err := unix.Close(fd)
		if err != nil && !errors.Is(err, unix.EBADF) {
			log.Debugf("Network monitor: closed routing socket: %v", err)
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return ErrStopped
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
					go callback()
				case unix.RTM_DELETE:
					if nexthopv4.Intf != nil && route.Gw.Compare(nexthopv4.IP) == 0 || nexthopv6.Intf != nil && route.Gw.Compare(nexthopv6.IP) == 0 {
						log.Infof("Network monitor: default route removed: via %s, interface %s", route.Gw, intf)
						go callback()
					}
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
