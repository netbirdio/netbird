package dns

import (
	wgdevice "golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"

	"github.com/netbirdio/netbird/client/iface/device"
	"github.com/netbirdio/netbird/client/iface/wgaddr"
)

// WGIface defines subset methods of interface required for manager
type WGIface interface {
	Name() string
	Address() wgaddr.Address
	IsUserspaceBind() bool
	GetFilter() device.PacketFilter
	GetDevice() *device.FilteredDevice
	GetWGDevice() *wgdevice.Device
	GetNet() *netstack.Net
	GetInterfaceGUIDString() (string, error)
}
