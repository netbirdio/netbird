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

	var prefixLength int
	switch {
	case addr.Is4():
		prefixLength = 32
	case addr.Is6():
		prefixLength = 128
	default:
		return netip.Prefix{}, fmt.Errorf("invalid IP address: %s", addr)
	}

	prefix := netip.PrefixFrom(addr, prefixLength)
	return prefix, nil
}
