//go:build darwin || dragonfly || freebsd || netbsd || openbsd

package networkmonitor

import (
	"fmt"
	"syscall"

	log "github.com/sirupsen/logrus"
	"golang.org/x/net/route"
	"golang.org/x/sys/unix"

	"github.com/netbirdio/netbird/client/internal/routemanager/systemops"
)

// Common route parsing function shared across BSD-like systems.
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

func handleRouteMessage(msg *unix.RtMsghdr, buf []byte, nexthopv4, nexthopv6 systemops.Nexthop) bool {
	switch msg.Type {
	// handle route changes
	case unix.RTM_ADD, syscall.RTM_DELETE:
		route, err := parseRouteMessage(buf)
		if err != nil {
			log.Debugf("Network monitor: error parsing routing message: %v", err)
			return false
		}

		if route.Dst.Bits() != 0 {
			return false
		}

		intf := "<nil>"
		if route.Interface != nil {
			intf = route.Interface.Name
		}

		switch msg.Type {
		case unix.RTM_ADD:
			log.Infof("Network monitor: default route changed: via %s, interface %s", route.Gw, intf)
			return true
		case unix.RTM_DELETE:
			if (nexthopv4.Intf != nil && route.Gw.Compare(nexthopv4.IP) == 0) ||
				(nexthopv6.Intf != nil && route.Gw.Compare(nexthopv6.IP) == 0) {
				log.Infof("Network monitor: default route removed: via %s, interface %s", route.Gw, intf)
				return true
			}
		}
	}
	return false
}
