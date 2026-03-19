// Package netiputil provides compact binary encoding for IP prefixes used in
// the management proto wire format.
//
// Format: [IP bytes][1 byte prefix_len]
//   - IPv4: 5 bytes total (4 IP + 1 prefix_len, 0-32)
//   - IPv6: 17 bytes total (16 IP + 1 prefix_len, 0-128)
//
// Address family is determined by length: 5 = v4, 17 = v6.
package netiputil

import (
	"fmt"
	"net/netip"
)

// EncodePrefix encodes a netip.Prefix into compact bytes.
// The address is always unmapped before encoding.
func EncodePrefix(p netip.Prefix) []byte {
	addr := p.Addr().Unmap()
	raw := addr.As16()

	if addr.Is4() {
		b := make([]byte, 5)
		copy(b, raw[12:16])
		b[4] = byte(p.Bits())
		return b
	}

	b := make([]byte, 17)
	copy(b, raw[:])
	b[16] = byte(p.Bits())
	return b
}

// DecodePrefix decodes compact bytes into a netip.Prefix.
func DecodePrefix(b []byte) (netip.Prefix, error) {
	switch len(b) {
	case 5:
		ip4 := [4]byte(b[:4])
		addr := netip.AddrFrom4(ip4)
		return netip.PrefixFrom(addr, int(b[4])), nil
	case 17:
		ip6 := [16]byte(b[:16])
		addr := netip.AddrFrom16(ip6).Unmap()
		bits := int(b[16])
		// Clamp prefix length when unmapping v4-mapped v6 to v4
		if addr.Is4() && bits > 32 {
			bits = 32
		}
		return netip.PrefixFrom(addr, bits), nil
	default:
		return netip.Prefix{}, fmt.Errorf("invalid compact prefix length %d (expected 5 or 17)", len(b))
	}
}

// EncodeAddr encodes a netip.Addr into compact prefix bytes with a host prefix
// length (/32 for v4, /128 for v6). The address is always unmapped before encoding.
func EncodeAddr(a netip.Addr) []byte {
	a = a.Unmap()
	bits := 128
	if a.Is4() {
		bits = 32
	}
	return EncodePrefix(netip.PrefixFrom(a, bits))
}

// DecodeAddr decodes compact prefix bytes and returns only the address,
// discarding the prefix length. Useful when the prefix length is implied
// (e.g. peer overlay IPs are always /32 or /128).
func DecodeAddr(b []byte) (netip.Addr, error) {
	p, err := DecodePrefix(b)
	if err != nil {
		return netip.Addr{}, err
	}
	return p.Addr(), nil
}
