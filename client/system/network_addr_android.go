package system

import (
	"net/netip"
	"strings"
)

var iFaceDiscover IFaceDiscover

type IFaceDiscover interface {
	IFaces() (string, error)
}

// SetIFaceDiscover configures the Android interface discovery provider.
func SetIFaceDiscover(discover IFaceDiscover) {
	iFaceDiscover = discover
}

func networkAddresses() ([]NetworkAddress, error) {
	if iFaceDiscover == nil {
		return nil, nil
	}
	ifaces, err := iFaceDiscover.IFaces()
	if err != nil {
		return nil, err
	}

	var netAddresses []NetworkAddress
	for _, line := range strings.Split(ifaces, "\n") {
		addresses, ok := interfaceAddresses(line)
		if !ok {
			continue
		}
		for _, address := range addresses {
			netAddr, ok := toNetworkAddress(address)
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

func interfaceAddresses(line string) ([]string, bool) {
	parts := strings.Split(line, "|")
	if len(parts) != 2 {
		return nil, false
	}
	flags := strings.Fields(parts[0])
	if len(flags) != 8 {
		return nil, false
	}
	up, loopback := flags[3], flags[5]
	if up != "true" || loopback == "true" {
		return nil, false
	}
	return strings.Fields(parts[1]), true
}

func toNetworkAddress(address string) (NetworkAddress, bool) {
	prefix, err := netip.ParsePrefix(address)
	if err != nil {
		return NetworkAddress{}, false
	}
	if prefix.Addr().Is4In6() {
		if prefix.Bits() < 96 {
			return NetworkAddress{}, false
		}
		prefix = netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()-96)
	}
	ip := prefix.Addr()
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsMulticast() {
		return NetworkAddress{}, false
	}
	return NetworkAddress{NetIP: prefix}, true
}

func isDuplicated(addresses []NetworkAddress, addr NetworkAddress) bool {
	for _, duplicated := range addresses {
		if duplicated.NetIP == addr.NetIP {
			return true
		}
	}
	return false
}
