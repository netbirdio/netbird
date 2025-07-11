package wgaddr

import (
	"fmt"
	"net/netip"
)

// Address WireGuard parsed address
type Address struct {
	IP      netip.Addr
	Network netip.Prefix
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

func (addr Address) String() string {
	return fmt.Sprintf("%s/%d", addr.IP.String(), addr.Network.Bits())
}
