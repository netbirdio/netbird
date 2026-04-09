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
// The address is always unmapped before encoding. If unmapping produces a v4
// address, the prefix length is clamped to 32.
func EncodePrefix(p netip.Prefix) []byte {
	addr := p.Addr().Unmap()
	bits := p.Bits()
	if addr.Is4() && bits > 32 {
		bits = 32
	}
	return append(addr.AsSlice(), byte(bits))
}

// DecodePrefix decodes compact bytes into a netip.Prefix.
func DecodePrefix(b []byte) (netip.Prefix, error) {
	switch len(b) {
	case 5:
		var ip4 [4]byte
		copy(ip4[:], b)
		bits := int(b[len(b)-1])
		if bits > 32 {
			return netip.Prefix{}, fmt.Errorf("invalid IPv4 prefix length %d (max 32)", bits)
		}
		return netip.PrefixFrom(netip.AddrFrom4(ip4), bits), nil
	case 17:
		var ip6 [16]byte
		copy(ip6[:], b)
		addr := netip.AddrFrom16(ip6).Unmap()
		bits := int(b[len(b)-1])
		if addr.Is4() {
			if bits > 32 {
				bits = 32
			}
		} else if bits > 128 {
			return netip.Prefix{}, fmt.Errorf("invalid IPv6 prefix length %d (max 128)", bits)
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
