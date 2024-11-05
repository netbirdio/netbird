package device

import (
	"fmt"
	"net"
)

// WGAddress WireGuard parsed address
type WGAddress struct {
	IP      net.IP
	Network *net.IPNet
}

// ParseWGAddress parse a string ("1.2.3.4/24") address to WG Address
func ParseWGAddress(address string) (WGAddress, error) {
	ip, network, err := net.ParseCIDR(address)
	if err != nil {
		return WGAddress{}, err
	}
	return WGAddress{
		IP:      ip,
		Network: network,
	}, nil
}

func (addr WGAddress) String() string {
	maskSize, _ := addr.Network.Mask.Size()
	return fmt.Sprintf("%s/%d", addr.IP.String(), maskSize)
}
