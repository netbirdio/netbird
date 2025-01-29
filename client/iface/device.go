//go:build !android

package iface

import (
	"golang.zx2c4.com/wireguard/tun/netstack"

	"github.com/netbirdio/netbird/client/iface/bind"
	"github.com/netbirdio/netbird/client/iface/device"
)

type WGTunDevice interface {
	Create() (device.WGConfigurer, error)
	Up() (*bind.UniversalUDPMuxDefault, error)
	UpdateAddr(address WGAddress) error
	WgAddress() WGAddress
	DeviceName() string
	Close() error
	FilteredDevice() *device.FilteredDevice
	GetNet() *netstack.Net
}
