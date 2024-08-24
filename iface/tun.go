//go:build !android
// +build !android

package iface

import (
	"github.com/netbirdio/netbird/iface/bind"
)

const defaultWindowsGUIDSTring = "{f2f29e61-d91f-4d76-8151-119b20c4bdeb}"

// CustomWindowsGUIDString is a custom GUID string for the interface
var CustomWindowsGUIDString string

type wgTunDevice interface {
	Create() (wgConfigurer, error)
	Up() (*bind.UniversalUDPMuxDefault, error)
	UpdateAddr(address WGAddress) error
	WgAddress() WGAddress
	DeviceName() string
	Close() error
	Wrapper() *DeviceWrapper // todo eliminate this function
}
