package firewall

import (
	wgdevice "golang.zx2c4.com/wireguard/device"

	"github.com/netbirdio/netbird/client/iface/device"
	"github.com/netbirdio/netbird/client/iface/wgaddr"
)

// EnvForceUserspaceFirewall forces the use of the userspace packet filter even when
// native iptables/nftables is available. This only applies when the WireGuard interface
// runs in userspace mode. When set, peer ACLs are handled by USPFilter instead of
// kernel netfilter rules.
const EnvForceUserspaceFirewall = "NB_FORCE_USERSPACE_FIREWALL"

// IFaceMapper defines subset methods of interface required for manager
type IFaceMapper interface {
	Name() string
	Address() wgaddr.Address
	IsUserspaceBind() bool
	SetFilter(device.PacketFilter) error
	GetDevice() *device.FilteredDevice
	GetWGDevice() *wgdevice.Device
}
