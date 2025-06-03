package iface

import (
	"net"
	"net/netip"

	"github.com/netbirdio/netbird/client/iface/device"
	"github.com/netbirdio/netbird/client/iface/wgaddr"
)

type wgIfaceBase interface {
	AddAllowedIP(peerKey string, allowedIP netip.Prefix) error
	RemoveAllowedIP(peerKey string, allowedIP string) error

	Name() string
	Address() wgaddr.Address
	ToInterface() *net.Interface
	IsUserspaceBind() bool
	GetFilter() device.PacketFilter
	GetDevice() *device.FilteredDevice
}
