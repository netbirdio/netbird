//go:build linux

package vpnplugin

import (
	"encoding/binary"
	"net"

	"github.com/vishvananda/netlink"
)

// defaultIPv4Gateway returns the host's current default IPv4 gateway, in
// the network-byte-order form NetworkManager's VPN plugin D-Bus API
// documents for the Config signal's "gateway" key
// (NM_VPN_PLUGIN_CONFIG_EXT_GATEWAY). NetworkManager hard-requires this key
// to accept a VPN's Config reply at all -- it uses it to pin a route to the
// VPN's own endpoints via the pre-existing gateway, bypassing the tunnel.
func defaultIPv4Gateway() (uint32, bool) {
	routes, err := netlink.RouteList(nil, netlink.FAMILY_V4)
	if err != nil {
		return 0, false
	}

	for _, route := range routes {
		if !isDefaultDst(route.Dst) || route.Gw == nil {
			continue
		}
		gw := route.Gw.To4()
		if gw == nil {
			continue
		}
		return binary.BigEndian.Uint32(gw), true
	}
	return 0, false
}

// isDefaultDst reports whether dst represents the default route (0.0.0.0/0):
// either a nil destination, or an explicit zero-length-prefix network,
// depending on how the platform's route table represents it.
func isDefaultDst(dst *net.IPNet) bool {
	if dst == nil {
		return true
	}
	ones, _ := dst.Mask.Size()
	return ones == 0
}
