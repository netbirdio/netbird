//go:build !windows

package dns

import "github.com/netbirdio/netbird/iface"

// WGIface defines subset methods of interface required for manager
type WGIface interface {
	Name() string
	Address() iface.WGAddress
	IsUserspaceBind() bool
	GetFilter() iface.PacketFilter
	GetDevice() *iface.DeviceWrapper
	GetStats(peerKey string) (iface.WGStats, error)
}
