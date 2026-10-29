package iface

import (
	"github.com/netbirdio/netbird/client/iface/device"
	"github.com/netbirdio/netbird/client/iface/udpmux"
	"github.com/netbirdio/netbird/client/iface/wgaddr"
	"github.com/netbirdio/netbird/client/iface/wgbackend"
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
	Device() *wgbackend.Device
	GetNet() *wgbackend.NetstackNet
	RenewTun(fd int) error
	GetICEBind() device.EndpointManager
}
