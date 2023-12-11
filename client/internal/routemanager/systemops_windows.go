//go:build windows
// +build windows

package routemanager

import (
	"net"
	"net/netip"

	"github.com/yusufpapurcu/wmi"
)

type Win32_IP4RouteTable struct {
	Destination string
	Mask        string
}

func getRoutesFromTable() ([]netip.Prefix, error) {
	var routes []Win32_IP4RouteTable
	query := "SELECT Destination, Mask FROM Win32_IP4RouteTable"

	err := wmi.Query(query, &routes)
	if err != nil {
		return nil, err
	}

	var prefixList []netip.Prefix
	for _, route := range routes {
		addr, err := netip.ParseAddr(route.Destination)
		if err != nil {
			continue
		}
		maskSlice := net.ParseIP(route.Mask).To4()
		if maskSlice == nil {
			continue
		}
		mask := net.IPv4Mask(maskSlice[0], maskSlice[1], maskSlice[2], maskSlice[3])
		cidr, _ := mask.Size()

		routePrefix := netip.PrefixFrom(addr, cidr)
		if routePrefix.IsValid() && routePrefix.Addr().Is4() {
			prefixList = append(prefixList, routePrefix)
		}
	}
	return prefixList, nil
}
