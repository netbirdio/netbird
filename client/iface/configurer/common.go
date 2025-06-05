package configurer

import (
	"net"
	"net/netip"
)

func prefixesToIPNets(prefixes []netip.Prefix) []net.IPNet {
	ipNets := make([]net.IPNet, len(prefixes))
	for i, prefix := range prefixes {
		ipNets[i] = net.IPNet{
			IP:   prefix.Addr().AsSlice(),                             // Convert netip.Addr to net.IP
			Mask: net.CIDRMask(prefix.Bits(), prefix.Addr().BitLen()), // Create subnet mask
		}
	}
	return ipNets
}
