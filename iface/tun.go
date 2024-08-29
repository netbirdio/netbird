//go:build !android
// +build !android

package iface

import (
	"github.com/netbirdio/netbird/iface/bind"
)

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
