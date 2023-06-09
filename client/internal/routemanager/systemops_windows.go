//go:build windows
// +build windows

package routemanager

import (
	"fmt"
	"net/netip"

	"github.com/StackExchange/wmi"
)

type Win32_IP4RouteTable struct {
	Destination  string
	Mask         string
	NextHop      string
	InterfaceIdx int
}

func existsInRouteTable(prefix netip.Prefix) (bool, error) {
	var routes []Win32_IP4RouteTable
	query := "SELECT Destination, Mask, NextHop, InterfaceIndex FROM Win32_IP4RouteTable"

	err := wmi.Query(query, &routes)
	if err != nil {
		return true, err
	}

	fmt.Println("Destination Networks:")
	for _, route := range routes {
		fmt.Println("Destination :", route.Destination)
		fmt.Println("Mask :", route.Mask)
		// mask, _ := toIPAddr(m.Addrs[2])
		// cidr, _ := net.IPMask(mask.To4()).Size()
		// if route.Destination == prefix.Addr().String() && cidr == prefix.Bits() {
		// 	return true, nil
		// }
	}
	return false, nil
}
