package iface

import (
	"fmt"
	"net"
)

// WGAddress Wireguard parsed address
type WGAddress struct {
	IP      net.IP
	Network *net.IPNet
}

// parseWGAddress parse a string ("1.2.3.4/24") address to WG Address
func parseWGAddress(address string) (WGAddress, error) {
	ip, network, err := net.ParseCIDR(address)
	if err != nil {
		return WGAddress{}, err
	}
	return WGAddress{
		IP:      ip,
		Network: network,
	}, nil
}

// Masked returns the WGAddress with the IP address part masked according to its network mask.
func (addr WGAddress) Masked() WGAddress {
	ip := addr.IP.To4()
	if ip == nil {
		ip = addr.IP.To16()
	}

	maskedIP := make(net.IP, len(ip))
	for i := range ip {
		maskedIP[i] = ip[i] & addr.Network.Mask[i]
	}

	return WGAddress{
		IP:      maskedIP,
		Network: addr.Network,
	}
}

func (addr WGAddress) String() string {
	maskSize, _ := addr.Network.Mask.Size()
	return fmt.Sprintf("%s/%d", addr.IP.String(), maskSize)
}
