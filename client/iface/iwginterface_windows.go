package iface

import (
	"net"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/netbirdio/netbird/client/iface/bind"
	"github.com/netbirdio/netbird/client/iface/configurer"
	"github.com/netbirdio/netbird/client/iface/device"
	"github.com/netbirdio/netbird/client/iface/wgproxy"
)

type IWGIface interface {
	Create() error
	CreateOnAndroid(routeRange []string, ip string, domains []string) error
	IsUserspaceBind() bool
	Name() string
	Address() device.WGAddress
	ToInterface() *net.Interface
	Up() (*bind.UniversalUDPMuxDefault, error)
	UpdateAddr(newAddr string) error
	GetProxy() wgproxy.Proxy
	UpdatePeer(peerKey string, allowedIps string, keepAlive time.Duration, endpoint *net.UDPAddr, preSharedKey *wgtypes.Key) error
	RemovePeer(peerKey string) error
	AddAllowedIP(peerKey string, allowedIP string) error
	RemoveAllowedIP(peerKey string, allowedIP string) error
	Close() error
	SetFilter(filter device.PacketFilter) error
	GetFilter() device.PacketFilter
	GetDevice() *device.FilteredDevice
	GetStats(peerKey string) (configurer.WGStats, error)
	GetInterfaceGUIDString() (string, error)
}
