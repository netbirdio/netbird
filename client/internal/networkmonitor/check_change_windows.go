package networkmonitor

import (
	"context"
	"fmt"
	"strings"
	"unsafe"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/windows"

	"github.com/netbirdio/netbird/client/internal/routemanager/systemops"
)

func checkChange(ctx context.Context, nexthopv4, nexthopv6 systemops.Nexthop) error {
	routeMonitor, err := systemops.NewRouteMonitor(ctx)
	if err != nil {
		return fmt.Errorf("create route monitor: %w", err)
	}
	defer func() {
		if err := routeMonitor.Stop(); err != nil {
			log.Errorf("Network monitor: failed to stop route monitor: %v", err)
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case route := <-routeMonitor.RouteUpdates():
			if route.Destination.Bits() != 0 {
				continue
			}

			checker, err := newSoftInterfaceChecker()
			if err != nil {
				log.Warnf("Network monitor: failed to build soft interface checker: %v", err)
			}

			if routeChanged(route, nexthopv4, nexthopv6, checker) {
				return nil
			}
		}
	}
}

func routeChanged(route systemops.RouteUpdate, nexthopv4, nexthopv6 systemops.Nexthop, checker *softInterfaceChecker) bool {
	if intf := route.NextHop.Intf; intf != nil && checker != nil {
		if checker.IsSoft(intf.Name, intf.Index) {
			log.Debugf(
				"Network monitor: ignoring default route change for soft interface %s (index %d)",
				intf.Name,
				intf.Index,
			)
			return false
		}
	}

	// TODO: for the empty nexthop ip (on-link), determine the family differently
	nexthop := nexthopv4
	if route.NextHop.IP.Is6() {
		nexthop = nexthopv6
	}

	switch route.Type {
	case systemops.RouteModified, systemops.RouteAdded:
		return handleRouteAddedOrModified(route, nexthop)
	case systemops.RouteDeleted:
		return handleRouteDeleted(route, nexthop)
	}

	return false
}

func handleRouteAddedOrModified(route systemops.RouteUpdate, nexthop systemops.Nexthop) bool {
	// For added/modified routes, we care about different next hops
	if !nexthop.Equal(route.NextHop) {
		action := "changed"
		if route.Type == systemops.RouteAdded {
			action = "added"
		}
		log.Infof("Network monitor: default route %s: via %s", action, route.NextHop)
		return true
	}
	return false
}

func handleRouteDeleted(route systemops.RouteUpdate, nexthop systemops.Nexthop) bool {
	// For deleted routes, we care about our tracked next hop being deleted
	if nexthop.Equal(route.NextHop) {
		log.Infof("Network monitor: default route removed: via %s", route.NextHop)
		return true
	}
	return false
}

type softInterfaceChecker struct {
	softByIndex map[int]bool
}

func newSoftInterfaceChecker() (*softInterfaceChecker, error) {
	// Checks the Name and Description for each interface
	size := uint32(15000)
	buf := make([]byte, size)
	flags := uint32(
		windows.GAA_FLAG_SKIP_UNICAST |
			windows.GAA_FLAG_SKIP_ANYCAST |
			windows.GAA_FLAG_SKIP_MULTICAST |
			windows.GAA_FLAG_SKIP_DNS_SERVER,
	)

	err := windows.GetAdaptersAddresses(
		windows.AF_UNSPEC,
		flags,
		0,
		(*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0])),
		&size,
	)
	if err == windows.ERROR_BUFFER_OVERFLOW {
		buf = make([]byte, size)
		err = windows.GetAdaptersAddresses(
			windows.AF_UNSPEC,
			flags,
			0,
			(*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0])),
			&size,
		)
	}
	if err != nil {
		return nil, err
	}

	checker := &softInterfaceChecker{
		softByIndex: make(map[int]bool),
	}

	for addr := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0])); addr != nil; addr = addr.Next {
		index := int(addr.IfIndex)

		name := strings.ToLower(windows.UTF16PtrToString(addr.FriendlyName))
		desc := strings.ToLower(windows.UTF16PtrToString(addr.Description))

		if isSoftInterface(name) || isSoftInterface(desc) {
			checker.softByIndex[index] = true
		}
	}

	return checker, nil
}

func (s *softInterfaceChecker) IsSoft(intfName string, intfIndex int) bool {
	// Perform lookup against pre-built map
	if isSoftInterface(intfName) {
		return true
	}

	return s.softByIndex[intfIndex]
}

func isSoftInterface(name string) bool {
	name = strings.ToLower(name)
	return strings.Contains(name, "isatap") || strings.Contains(name, "teredo") || strings.Contains(name, "pangp")
}
