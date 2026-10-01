package configurer

import (
	"net"
	"net/netip"
)

// prefixesToIPNets converts prefixes on their way to a device. It is the only place that
// conversion happens, so it also normalizes: the device is then given the same form the
// store records, and a v4-mapped prefix cannot reach net.IPNet, which prints such an
// address as v4 while taking the length from its 16 byte mask and so turns
// ::ffff:10.1.2.3/64 into 10.1.2.3/0 — an allowed IP matching every v4 address.
func prefixesToIPNets(prefixes []netip.Prefix) []net.IPNet {
	ipNets := make([]net.IPNet, len(prefixes))
	for i, prefix := range prefixes {
		normalized := normalizePrefix(prefix)
		ipNets[i] = net.IPNet{
			IP:   normalized.Addr().AsSlice(),
			Mask: net.CIDRMask(normalized.Bits(), normalized.Addr().BitLen()),
		}
	}
	return ipNets
}

// normalizePrefix puts a prefix into the form the store recognises it by. It clears the
// host bits, which a device does on its own, so a caller passing 10.20.0.1/16 still matches
// the 10.20.0.0/16 read back from the device; and it unmaps a v4-mapped prefix so that it
// compares equal to, and marshals like, the plain v4 prefix for the same network.
//
// Masking comes first because it also decides the address family: only a prefix at least 96
// bits long keeps the mapped marker through the mask, so a shorter prefix inside the mapped
// range is a genuine v6 prefix and unmapping it would yield an invalid v4 prefix.
func normalizePrefix(prefix netip.Prefix) netip.Prefix {
	masked := prefix.Masked()

	addr := masked.Addr()
	if !addr.Is4In6() {
		return masked
	}
	return netip.PrefixFrom(addr.Unmap(), masked.Bits()-96)
}

// normalizePrefixes returns a normalized copy without changing the caller's slice.
func normalizePrefixes(prefixes []netip.Prefix) []netip.Prefix {
	normalized := make([]netip.Prefix, len(prefixes))
	for i, prefix := range prefixes {
		normalized[i] = normalizePrefix(prefix)
	}
	return normalized
}
