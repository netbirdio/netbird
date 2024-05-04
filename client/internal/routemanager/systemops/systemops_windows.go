//go:build windows

package systemops

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/peer"
	"github.com/netbirdio/netbird/client/internal/routemanager/refcounter"
	"github.com/netbirdio/netbird/iface"
)

type Win32_IP4RouteTable struct {
	Destination string
	Mask        string
}

var prefixList []netip.Prefix
var lastUpdate time.Time
var mux = sync.Mutex{}

var refCounter *refcounter.Counter

func SetupRouting(initAddresses []net.IP, wgIface *iface.WGIface) (peer.BeforeAddPeerHookFunc, peer.AfterRemovePeerHookFunc, error) {
	return setupRoutingWithRefCounter(&refCounter, initAddresses, wgIface)
}

func CleanupRouting() error {
	return cleanupRoutingWithRefManager(refCounter)
}

func getRoutesFromTable() ([]netip.Prefix, error) {
	mux.Lock()
	defer mux.Unlock()

	query := "SELECT Destination, Mask FROM Win32_IP4RouteTable"

	// If many routes are added at the same time this might block for a long time (seconds to minutes), so we cache the result
	if !isCacheDisabled() && time.Since(lastUpdate) < 2*time.Second {
		return prefixList, nil
	}

	var routes []Win32_IP4RouteTable
	err := wmi.Query(query, &routes)
	if err != nil {
		return nil, fmt.Errorf("get routes: %w", err)
	}

	prefixList = nil
	for _, route := range routes {
		addr, err := netip.ParseAddr(route.Destination)
		if err != nil {
			log.Warnf("Unable to parse route destination %s: %v", route.Destination, err)
			continue
		}
		maskSlice := net.ParseIP(route.Mask).To4()
		if maskSlice == nil {
			log.Warnf("Unable to parse route mask %s", route.Mask)
			continue
		}
		mask := net.IPv4Mask(maskSlice[0], maskSlice[1], maskSlice[2], maskSlice[3])
		cidr, _ := mask.Size()

		routePrefix := netip.PrefixFrom(addr, cidr)
		if routePrefix.IsValid() && routePrefix.Addr().Is4() {
			prefixList = append(prefixList, routePrefix)
		}
	}

	lastUpdate = time.Now()
	return prefixList, nil
}

func addRouteCmd(prefix netip.Prefix, nexthop netip.Addr, intf *net.Interface) error {
	args := []string{"add", prefix.String()}

	if nexthop.IsValid() {
		args = append(args, nexthop.Unmap().String())
	} else {
		addr := "0.0.0.0"
		if prefix.Addr().Is6() {
			addr = "::"
		}
		args = append(args, addr)
	}

	if intf != nil {
		args = append(args, "if", strconv.Itoa(intf.Index))
	}

	out, err := exec.Command("route", args...).CombinedOutput()
	log.Tracef("route %s: %s", strings.Join(args, " "), out)
	if err != nil {
		return fmt.Errorf("route add: %w", err)
	}

	return nil
}

func addToRouteTable(prefix netip.Prefix, nexthop netip.Addr, intf *net.Interface) error {
	if nexthop.Zone() != "" && intf == nil {
		zone, err := strconv.Atoi(nexthop.Zone())
		if err != nil {
			return fmt.Errorf("invalid zone: %w", err)
		}
		intf = &net.Interface{Index: zone}
		nexthop.WithZone("")
	}

	return addRouteCmd(prefix, nexthop, intf)
}

func removeFromRouteTable(prefix netip.Prefix, nexthop netip.Addr, _ *net.Interface) error {
	args := []string{"delete", prefix.String()}
	if nexthop.IsValid() {
		nexthop.WithZone("")
		args = append(args, nexthop.Unmap().String())
	}

	out, err := exec.Command("route", args...).CombinedOutput()
	log.Tracef("route %s: %s", strings.Join(args, " "), out)

	if err != nil {
		return fmt.Errorf("remove route: %w", err)
	}
	return nil
}

func isCacheDisabled() bool {
	return os.Getenv("NB_DISABLE_ROUTE_CACHE") == "true"
}
