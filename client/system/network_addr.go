//go:build !ios

package system

import (
	"context"
	"net"
	"net/netip"
)

// NetworkAddresses returns the current set of non-loopback network addresses.
// It is intentionally lightweight (no posture-check file/process scanning) so
// callers can poll for address changes without the overhead of GetInfoWithChecks.
func NetworkAddresses(ctx context.Context) ([]NetworkAddress, error) {
	return networkAddresses(ctx)
}

func networkAddresses(ctx context.Context) ([]NetworkAddress, error) {
	interfaces, err := getNetInterfaces(ctx)
	if err != nil {
		return nil, err
	}

	// On Android (and any other platform where we received interfaces via
	// an external discoverer) the Java host application has already
	// filtered the list to "real" administrative interfaces and may not
	// expose the hardware MAC. Skip the no-MAC filter in that case so
	// posture checks see the actual addresses; on platforms where we
	// went through the standard library we keep the upstream behaviour
	// of dropping virtual interfaces without MAC.
	skipNoMacFilter := ctx.Value(IFaceDiscoverCtxKey) != nil

	var netAddresses []NetworkAddress
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		if !skipNoMacFilter && iface.HardwareAddr.String() == "" {
			continue
		}
		addrs, err := getInterfaceAddrs(ctx, &iface)
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
