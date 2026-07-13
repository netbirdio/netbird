package wgaddr

import (
	"fmt"
	"net/netip"

	"github.com/netbirdio/netbird/shared/netiputil"
)

// Address WireGuard parsed address
type Address struct {
	IP      netip.Addr
	Network netip.Prefix

	// IPv6 overlay address, if assigned.
	IPv6    netip.Addr
	IPv6Net netip.Prefix
}

// ParseWGAddress parse a string ("1.2.3.4/24") address to WG Address
func ParseWGAddress(address string) (Address, error) {
	prefix, err := netip.ParsePrefix(address)
	if err != nil {
		return Address{}, err
	}
	return Address{
		IP:      prefix.Addr().Unmap(),
		Network: prefix.Masked(),
	}, nil
}

// HasIPv6 reports whether a v6 overlay address is assigned.
func (addr Address) HasIPv6() bool {
	return addr.IPv6.IsValid()
}

func (addr Address) String() string {
	return addr.Prefix().String()
}

// IPv6String returns the v6 address in CIDR notation, or empty string if none.
func (addr Address) IPv6String() string {
	if !addr.HasIPv6() {
		return ""
	}
	return addr.IPv6Prefix().String()
}

// Prefix returns the v4 host address with its network prefix length (e.g. 100.64.0.1/16).
func (addr Address) Prefix() netip.Prefix {
	return netip.PrefixFrom(addr.IP, addr.Network.Bits())
}

// IPv6Prefix returns the v6 host address with its network prefix length, or a zero prefix if none.
func (addr Address) IPv6Prefix() netip.Prefix {
	if !addr.HasIPv6() {
		return netip.Prefix{}
	}
	return netip.PrefixFrom(addr.IPv6, addr.IPv6Net.Bits())
}

// SetIPv6FromCompact decodes a compact prefix (5 or 17 bytes) and sets the IPv6 fields.
// Returns an error if the bytes are invalid. A nil or empty input is a no-op.
//
//nolint:recvcheck
func (addr *Address) SetIPv6FromCompact(raw []byte) error {
	if len(raw) == 0 {
		return nil
	}
	prefix, err := netiputil.DecodePrefix(raw)
	if err != nil {
		return fmt.Errorf("decode v6 overlay address: %w", err)
	}
	if !prefix.Addr().Is6() {
		return fmt.Errorf("expected IPv6 address, got %s", prefix.Addr())
	}
	addr.IPv6 = prefix.Addr()
	addr.IPv6Net = prefix.Masked()
	return nil
}

// ClearIPv6 removes the IPv6 overlay address, leaving only v4.
//
//nolint:recvcheck
func (addr *Address) ClearIPv6() {
	addr.IPv6 = netip.Addr{}
	addr.IPv6Net = netip.Prefix{}
}
