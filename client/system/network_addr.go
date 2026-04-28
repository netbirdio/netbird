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

		mac := iface.HardwareAddr.String()
		for _, address := range addrs {
			netAddr, ok := toNetworkAddress(address, mac)
			if !ok {
				continue
			}
			if isDuplicated(netAddresses, netAddr) {
				continue
			}
			netAddresses = append(netAddresses, netAddr)
		}
	}
	return netAddresses, nil
}

func toNetworkAddress(address net.Addr, mac string) (NetworkAddress, bool) {
	ipNet, ok := address.(*net.IPNet)
	if !ok {
		return NetworkAddress{}, false
	}
	if ipNet.IP.IsLoopback() {
		return NetworkAddress{}, false
	}
	prefix, err := netip.ParsePrefix(ipNet.String())
	if err != nil {
		return NetworkAddress{}, false
	}
	return NetworkAddress{NetIP: prefix, Mac: mac}, true
}

func isDuplicated(addresses []NetworkAddress, addr NetworkAddress) bool {
	for _, duplicated := range addresses {
		if duplicated.NetIP == addr.NetIP {
			return true
		}
	}
	return false
}
