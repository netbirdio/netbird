package server

import (
	"fmt"
	"net/netip"
)

// parseAddr parses a string into a netip.Addr, stripping any port or zone.
func parseAddr(s string) (netip.Addr, error) {
	// Try as plain IP first
	if addr, err := netip.ParseAddr(s); err == nil {
		return addr, nil
	}

	// Try as IP:port
	if addrPort, err := netip.ParseAddrPort(s); err == nil {
		return addrPort.Addr(), nil
	}

	return netip.Addr{}, fmt.Errorf("invalid IP address: %s", s)
}
