package wgaddr

import (
	"fmt"
	"net"
)

// Address WireGuard parsed address
type Address struct {
	IP      net.IP
	Network *net.IPNet
}

// ParseWGAddress parse a string ("1.2.3.4/24") address to WG Address
func ParseWGAddress(address string) (Address, error) {
	ip, network, err := net.ParseCIDR(address)
	if err != nil {
		return Address{}, err
	}
	return Address{
		IP:      ip,
		Network: network,
	}, nil
}

func (addr Address) String() string {
	maskSize, _ := addr.Network.Mask.Size()
	return fmt.Sprintf("%s/%d", addr.IP.String(), maskSize)
}
