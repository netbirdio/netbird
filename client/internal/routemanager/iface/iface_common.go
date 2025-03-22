package iface

import (
	"net"

	"github.com/netbirdio/netbird/client/iface/device"
	"github.com/netbirdio/netbird/client/iface/wgaddr"
)

type wgIfaceBase interface {
	AddAllowedIP(peerKey string, allowedIP string) error
	RemoveAllowedIP(peerKey string, allowedIP string) error

	Name() string
	Address() wgaddr.Address
	ToInterface() *net.Interface
	IsUserspaceBind() bool
	GetFilter() device.PacketFilter
	GetDevice() *device.FilteredDevice
}
