package iface

import (
	wgdevice "golang.zx2c4.com/wireguard/device"

	"golang.zx2c4.com/wireguard/tun/netstack"

	"github.com/netbirdio/netbird/client/iface/bind"
	"github.com/netbirdio/netbird/client/iface/device"
	"github.com/netbirdio/netbird/client/iface/wgaddr"
	"github.com/netbirdio/netbird/management/domain"
)

type WGTunDevice interface {
	Create(routes []string, dns string, searchDomains domain.List) (device.WGConfigurer, error)
	Up() (*bind.UniversalUDPMuxDefault, error)
	UpdateAddr(address wgaddr.Address) error
	WgAddress() wgaddr.Address
	DeviceName() string
	Close() error
	FilteredDevice() *device.FilteredDevice
	Device() *wgdevice.Device
	GetNet() *netstack.Net
}
