package iface

import (
	wgdevice "golang.zx2c4.com/wireguard/device"

	"golang.zx2c4.com/wireguard/tun/netstack"

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
	// CloseKeepInterface releases process-owned resources like Close, but leaves
	// the OS-level interface in place. Android has no persistent kernel WireGuard
	// object to preserve, so implementations just call Close.
	CloseKeepInterface() error
	FilteredDevice() *device.FilteredDevice
	Device() *wgdevice.Device
	GetNet() *netstack.Net
	RenewTun(fd int) error
	GetICEBind() device.EndpointManager
}
