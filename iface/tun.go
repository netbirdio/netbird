//go:build !android
// +build !android

package iface

import (
	"github.com/netbirdio/netbird/iface/bind"
)

type wgTunDevice interface {
	Create() (wgConfigurer, error)
	Up() (*bind.UniversalUDPMuxDefault, error)
	UpdateAddr(address WGAddress) error
	WgAddress() WGAddress
	UpdateAddr6(addr6 *WGAddress) error
	WgAddress6() *WGAddress
	DeviceName() string
	Close() error
	Wrapper() *DeviceWrapper // todo eliminate this function
}
