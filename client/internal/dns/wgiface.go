//go:build !windows

package dns

import (
	"net"

	"github.com/netbirdio/netbird/iface"
)

// WGIface defines subset methods of interface required for manager
type WGIface interface {
	Name() string
	Address() iface.WGAddress
	ToInterface() *net.Interface
	IsUserspaceBind() bool
	GetFilter() iface.PacketFilter
	GetDevice() *iface.DeviceWrapper
	GetStats(peerKey string) (iface.WGStats, error)
}
