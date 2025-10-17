package common

import (
	wgdevice "github.com/amnezia-vpn/amneziawg-go/device"

	"github.com/netbirdio/netbird/client/iface/device"
	"github.com/netbirdio/netbird/client/iface/wgaddr"
)

// IFaceMapper defines subset methods of interface required for manager
type IFaceMapper interface {
	SetFilter(device.PacketFilter) error
	Address() wgaddr.Address
	GetWGDevice() *wgdevice.Device
	GetDevice() *device.FilteredDevice
}
