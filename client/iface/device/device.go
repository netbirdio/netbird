//go:build !android
// +build !android

package device

import (
	"github.com/netbirdio/netbird/client/iface/bind"
)

type WGTunDevice interface {
	Create() (WGConfigurer, error)
	Up() (*bind.UniversalUDPMuxDefault, error)
	UpdateAddr(address WGAddress) error
	WgAddress() WGAddress
	DeviceName() string
	Close() error
	FilteredDevice() *FilteredDevice
}
