//go:build !android
// +build !android

package device

import (
	"github.com/netbirdio/netbird/client/iface/bind"
	"github.com/netbirdio/netbird/client/iface/configurer"
)

type WGTunDevice interface {
	Create() (configurer.WGConfigurer, error)
	Up() (*bind.UniversalUDPMuxDefault, error)
	UpdateAddr(address WGAddress) error
	WgAddress() WGAddress
	DeviceName() string
	Close() error
	FilteredDevice() *FilteredDevice
}
