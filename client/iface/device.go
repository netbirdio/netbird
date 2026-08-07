//go:build !android

package iface

import (
	"golang.zx2c4.com/wireguard/tun/netstack"

	wgdevice "golang.zx2c4.com/wireguard/device"

	"github.com/netbirdio/netbird/client/iface/device"
	"github.com/netbirdio/netbird/client/iface/udpmux"
	"github.com/netbirdio/netbird/client/iface/wgaddr"
)

type WGTunDevice interface {
	Create() (device.WGConfigurer, error)
	Up() (*udpmux.UniversalUDPMuxDefault, error)
	UpdateAddr(address wgaddr.Address) error
	WgAddress() wgaddr.Address
	MTU() uint16
	DeviceName() string
	Close() error
	// CloseKeepInterface releases process-owned resources (proxy, UDP mux) like
	// Close, but leaves the OS-level interface in place instead of destroying it.
	// Used when the daemon is stopping ahead of an in-place binary upgrade, so the
	// next process can reuse the same kernel WireGuard link. Implementations that
	// have no OS-level object to preserve (userspace TUN) just call Close.
	CloseKeepInterface() error
	FilteredDevice() *device.FilteredDevice
	Device() *wgdevice.Device
	GetNet() *netstack.Net
	GetICEBind() device.EndpointManager
}
