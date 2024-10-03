package firewall

import (
	"github.com/netbirdio/netbird/client/iface/device"
)

// IFaceMapper defines subset methods of interface required for manager
type IFaceMapper interface {
	Name() string
	Address() device.WGAddress
	IsUserspaceBind() bool
	SetFilter(device.PacketFilter) error
}
