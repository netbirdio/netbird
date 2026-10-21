package iface

import (
	wgdevice "github.com/netbirdio/wireguard-go/device"

	"github.com/netbirdio/wireguard-go/tun/netstack"

	"github.com/netbirdio/netbird/client/iface/device"
	"github.com/netbirdio/netbird/client/iface/udpmux"
	"github.com/netbirdio/netbird/client/iface/wgaddr"
)

type WGTunDevice interface {
	Create(routes []string, dns string, searchDomains []string) (device.WGConfigurer, error)
	Up() (*udpmux.UniversalUDPMuxDefault, error)
	UpdateAddr(address wgaddr.Address) error
	WgAddress() wgaddr.Address
	MTU() uint16
	DeviceName() string
	Close() error
	FilteredDevice() *device.FilteredDevice
	Device() *wgdevice.Device
	GetNet() *netstack.Net
	RenewTun(fd int) error
	GetICEBind() device.EndpointManager
}
