//go:build (darwin && !ios) || dragonfly || freebsd || netbsd || openbsd

package networkmonitor

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"syscall"
	"unsafe"

	log "github.com/sirupsen/logrus"
	"golang.org/x/net/route"
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
			isRouteMessage := n >= unix.SizeofRtMsghdr
			// Route socket supports more than just route messages, skip non route messages
			if !isRouteMessage {
				continue
			}

			msg := (*unix.RtMsghdr)(unsafe.Pointer(&buf[0]))
			isRouteChange := msg.Type == syscall.RTM_CHANGE || msg.Type == syscall.RTM_ADD || msg.Type == syscall.RTM_DELETE

			if isRouteChange {
				route, err := parseRouteMessage(buf[:n])
				if err != nil {
					log.Debugf("Network monitor: error parsing routing message: %v", err)
					continue
				}
				isDefaultRoute := route.Dst.Bits() == 0
				if !isDefaultRoute {
					continue
				}
				if hasDefaultRouteChanged(nexthopv4, nexthopv6) {
					return nil
				}
			}
		}
	}
}

func hasDefaultRouteChanged(nexthopv4, nexthopv6 systemops.Nexthop) bool {
	// Compare current with saved netxhop
	newNexthopv4, errv4 := systemops.GetNextHop(netip.IPv4Unspecified())
	newNexthopv6, errv6 := systemops.GetNextHop(netip.IPv6Unspecified())
	if errv4 != nil || errv6 != nil {
		err := errors.Join(errv4, errv6)
		log.Infof("Network monitor: failed to check next hop, assuming no network connection available: %s", err)
		return true
	}

	hasValidV4Ifaces := nexthopv4.Intf != nil && newNexthopv4.Intf != nil
	hasValidV6Ifaces := nexthopv6.Intf != nil && newNexthopv6.Intf != nil
	hasV4GatewayChanged := nexthopv4.IP.Compare(newNexthopv4.IP) != 0
	hasV6GatewayChanged := nexthopv6.IP.Compare(newNexthopv6.IP) != 0
	hasV4IntfChanged := (nexthopv4.Intf != nil && newNexthopv4.Intf == nil) || (nexthopv4.Intf == nil && newNexthopv4.Intf != nil) || (hasValidV4Ifaces && nexthopv4.Intf.Name != newNexthopv4.Intf.Name)
	hasV6IntfChanged := (nexthopv6.Intf != nil && newNexthopv6.Intf == nil) || (nexthopv6.Intf == nil && newNexthopv6.Intf != nil) || (hasValidV6Ifaces && nexthopv6.Intf.Name != newNexthopv6.Intf.Name)

	if hasV4GatewayChanged || hasV6GatewayChanged || hasV4IntfChanged || hasV6IntfChanged {
		log.Infof("Network monitor: default route changed v4 stats, GatewayChanged: %t Gateway: %#v, IntfChanged: %t, Intf: new - %s vs old - %s", hasV4GatewayChanged, newNexthopv4.IP.String(), hasV4IntfChanged, newNexthopv4.Intf.Name, nexthopv4.Intf.Name)
		log.Infof("Network monitor: default route changed v6 stats, GatewayChanged: %t Gateway: %#v, IntfChanged: %t, Intf: new - %s vs old - %s", hasV6GatewayChanged, newNexthopv6.IP.String(), hasV6IntfChanged, newNexthopv6.Intf.Name, nexthopv6.Intf.Name)
		return true
	}
	return false
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
