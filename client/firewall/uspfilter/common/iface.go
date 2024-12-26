package common

import (
	device2 "golang.zx2c4.com/wireguard/device"

	"github.com/netbirdio/netbird/client/iface"
	"github.com/netbirdio/netbird/client/iface/device"
)

// IFaceMapper defines subset methods of interface required for manager
type IFaceMapper interface {
	SetFilter(device.PacketFilter) error
	Address() iface.WGAddress
	GetWGDevice() *device2.Device
	GetDevice() *device.FilteredDevice
}
