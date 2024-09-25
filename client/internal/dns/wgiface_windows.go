package dns

import (
	"github.com/netbirdio/netbird/iface"
	"github.com/netbirdio/netbird/iface/configurer"
	"github.com/netbirdio/netbird/iface/device"
)

// WGIface defines subset methods of interface required for manager
type WGIface interface {
	Name() string
	Address() iface.WGAddress
	IsUserspaceBind() bool
	GetFilter() device.PacketFilter
	GetDevice() *device.FilteredDevice
	GetStats(peerKey string) (configurer.WGStats, error)
	GetInterfaceGUIDString() (string, error)
}
