package util

import (
	"fmt"
	"net"
	"net/netip"
)

// GetPrefixFromIP returns a netip.Prefix from a net.IP address.
func GetPrefixFromIP(ip net.IP) (netip.Prefix, error) {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return netip.Prefix{}, fmt.Errorf("parse IP address: %s", ip)
	}

	addr = addr.Unmap()
	prefix := netip.PrefixFrom(addr, addr.BitLen())
	return prefix, nil
}
