//go:build !android

package networkmonitor

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"syscall"

	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

func checkChange(ctx context.Context, nexthopv4 netip.Addr, intfv4 *net.Interface, nexthop6 netip.Addr, intfv6 *net.Interface, callback func()) error {
	if intfv4 == nil && intfv6 == nil {
		return errors.New("no interfaces available")
	}

	linkChan := make(chan netlink.LinkUpdate)
	done := make(chan struct{})
	defer close(done)

	if err := netlink.LinkSubscribe(linkChan, done); err != nil {
		return fmt.Errorf("subscribe to link updates: %v", err)
	}

	routeChan := make(chan netlink.RouteUpdate)
	if err := netlink.RouteSubscribe(routeChan, done); err != nil {
		return fmt.Errorf("subscribe to route updates: %v", err)
	}

	log.Info("Network monitor: started")
	for {
		select {
		case <-ctx.Done():
			return ErrStopped

		// handle interface state changes
		case update := <-linkChan:
			if (intfv4 == nil || update.Index != int32(intfv4.Index)) && (intfv6 == nil || update.Index != int32(intfv6.Index)) {
				continue
			}

			switch update.Header.Type {
			case syscall.RTM_DELLINK:
				log.Infof("Network monitor: monitored interface (%s) is gone", update.Link.Attrs().Name)
				go callback()
				return nil
			case syscall.RTM_NEWLINK:
				if (update.IfInfomsg.Flags&syscall.IFF_RUNNING) == 0 && update.Link.Attrs().OperState == netlink.OperDown {
					log.Infof("Network monitor: monitored interface (%s) is down.", update.Link.Attrs().Name)
					go callback()
					return nil
				}
			}

		// handle route changes
		case route := <-routeChan:
			// default route and main table
			if route.Dst != nil || route.Table != syscall.RT_TABLE_MAIN {
				continue
			}
			switch route.Type {
			// triggered on added/replaced routes
			case syscall.RTM_NEWROUTE:
				log.Infof("Network monitor: default route changed: via %s, interface %d", route.Gw, route.LinkIndex)
				go callback()
				return nil
			case syscall.RTM_DELROUTE:
				if intfv4 != nil && route.Gw.Equal(nexthopv4.AsSlice()) || intfv6 != nil && route.Gw.Equal(nexthop6.AsSlice()) {
					log.Infof("Network monitor: default route removed: via %s, interface %d", route.Gw, route.LinkIndex)
					go callback()
					return nil
				}
			}
		}
	}
}
