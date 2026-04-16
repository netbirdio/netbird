//go:build !ios

package system

import (
	"net"
	"net/netip"
)

func networkAddresses() ([]NetworkAddress, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	var netAddresses []NetworkAddress
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		if iface.HardwareAddr.String() == "" {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, address := range addrs {
			ipNet, ok := address.(*net.IPNet)
			if !ok {
				continue
			}

			if ipNet.IP.IsLoopback() {
				continue
			}

			netAddr := NetworkAddress{
				NetIP: netip.MustParsePrefix(ipNet.String()),
				Mac:   iface.HardwareAddr.String(),
			}

			if isDuplicated(netAddresses, netAddr) {
				continue
			}

			netAddresses = append(netAddresses, netAddr)
		}
	}
	return netAddresses, nil
}

func isDuplicated(addresses []NetworkAddress, addr NetworkAddress) bool {
	for _, duplicated := range addresses {
		if duplicated.NetIP == addr.NetIP {
			return true
		}
	}
	return false
}
