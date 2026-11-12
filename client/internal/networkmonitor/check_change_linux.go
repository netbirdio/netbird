//go:build !android

package networkmonitor

import (
	"context"
	"errors"
	"fmt"
	"net"
	"syscall"

	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"

	"github.com/netbirdio/netbird/client/internal/routemanager/systemops"
)

func checkChange(ctx context.Context, nexthopv4, nexthopv6 systemops.Nexthop) error {
	if nexthopv4.Intf == nil && nexthopv6.Intf == nil {
		return errors.New("no interfaces available")
	}

	done := make(chan struct{})
	defer close(done)

	routeChan := make(chan netlink.RouteUpdate)
	if err := netlink.RouteSubscribe(routeChan, done); err != nil {
		return fmt.Errorf("subscribe to route updates: %v", err)
	}

	log.Info("Network monitor: started")
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		// handle route changes
		case route := <-routeChan:
			// default route and main table
			if !isDefaultRoute(route.Dst) || route.Table != syscall.RT_TABLE_MAIN {
				continue
			}
			switch route.Type {
			// triggered on added/replaced routes
			case syscall.RTM_NEWROUTE:
				log.Infof("Network monitor: default route changed: via %s, interface %d", route.Gw, route.LinkIndex)
				return nil
			case syscall.RTM_DELROUTE:
				if nexthopv4.Intf != nil && route.Gw.Equal(nexthopv4.IP.AsSlice()) || nexthopv6.Intf != nil && route.Gw.Equal(nexthopv6.IP.AsSlice()) {
					log.Infof("Network monitor: default route removed: via %s, interface %d", route.Gw, route.LinkIndex)
					return nil
				}
			}
		}
	}
}

// isDefaultRoute reports whether dst is a default route. netlink v1.3 reports
// the default as 0.0.0.0/0 or ::/0, older versions as a nil Dst.
func isDefaultRoute(dst *net.IPNet) bool {
	if dst == nil {
		return true
	}
	ones, _ := dst.Mask.Size()
	return ones == 0
}
