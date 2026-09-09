//go:build privileged

package iptables

import (
	"fmt"
	"net"
	"net/netip"
)

func pfx(ip net.IP) []netip.Prefix {
	if ip == nil {
		return []netip.Prefix{netip.PrefixFrom(netip.IPv4Unspecified(), 0)}
	}
	if ip.IsUnspecified() {
		if ip.To4() != nil {
			return []netip.Prefix{netip.PrefixFrom(netip.IPv4Unspecified(), 0)}
		}
		return []netip.Prefix{netip.PrefixFrom(netip.IPv6Unspecified(), 0)}
	}
	a, ok := netip.AddrFromSlice(ip)
	if !ok {
		panic(fmt.Sprintf("invalid IP length: %d", len(ip)))
	}
	a = a.Unmap()
	return []netip.Prefix{netip.PrefixFrom(a, a.BitLen())}
}
