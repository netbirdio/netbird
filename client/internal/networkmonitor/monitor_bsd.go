//go:build (darwin && !ios) || dragonfly || freebsd || netbsd || openbsd

package networkmonitor

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"syscall"
	"unsafe"

	log "github.com/sirupsen/logrus"
	"golang.org/x/net/route"
	"golang.org/x/sys/unix"

	"github.com/netbirdio/netbird/client/internal/routemanager"
)

func checkChange(ctx context.Context, nexthopv4 netip.Addr, intfv4 *net.Interface, nexthopv6 netip.Addr, intfv6 *net.Interface, callback func()) error {
	fd, err := unix.Socket(syscall.AF_ROUTE, syscall.SOCK_RAW, syscall.AF_UNSPEC)
	if err != nil {
		return fmt.Errorf("failed to open routing socket: %v", err)
	}
	defer func() {
		if err := unix.Close(fd); err != nil {
			log.Errorf("Network monitor: failed to close routing socket: %v", err)
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
				log.Errorf("Network monitor: failed to read from routing socket: %v", err)
				continue
			}
			if n < unix.SizeofRtMsghdr {
				log.Errorf("Network monitor: read from routing socket returned less than expected: %d bytes", n)
				continue
			}

			msg := (*unix.RtMsghdr)(unsafe.Pointer(&buf[0]))

			switch msg.Type {

			// handle interface state changes
			case unix.RTM_IFINFO:
				ifinfo, err := parseInterfaceMessage(buf[:n])
				if err != nil {
					log.Errorf("Network monitor: error parsing interface message: %v", err)
					continue
				}
				if msg.Flags&unix.IFF_UP != 0 {
					continue
				}
				if (intfv4 == nil || ifinfo.Index != intfv4.Index) && (intfv6 == nil || ifinfo.Index != intfv6.Index) {
					continue
				}

				log.Infof("Network monitor: monitored interface (%s) is down.", ifinfo.Name)
				go callback()

			// handle route changes
			case unix.RTM_ADD, syscall.RTM_DELETE:
				route, err := parseRouteMessage(buf[:n])
				if err != nil {
					log.Errorf("Network monitor: error parsing routing message: %v", err)
					continue
				}

				if !route.Dst.Addr().IsUnspecified() {
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
					if intfv4 != nil && route.Gw.Compare(nexthopv4) == 0 || intfv6 != nil && route.Gw.Compare(nexthopv6) == 0 {
						log.Infof("Network monitor: default route removed: via %s, interface %s", route.Gw, intf)
						go callback()
					}
				}
			}
		}
	}
}

func parseInterfaceMessage(buf []byte) (*route.InterfaceMessage, error) {
	msgs, err := route.ParseRIB(route.RIBTypeInterface, buf)
	if err != nil {
		return nil, fmt.Errorf("parse RIB: %v", err)
	}

	if len(msgs) != 1 {
		return nil, fmt.Errorf("unexpected RIB message msgs: %v", msgs)
	}

	msg, ok := msgs[0].(*route.InterfaceMessage)
	if !ok {
		return nil, fmt.Errorf("unexpected RIB message type: %T", msgs[0])
	}

	return msg, nil
}

func parseRouteMessage(buf []byte) (*routemanager.Route, error) {
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

	return routemanager.MsgToRoute(msg)
}
