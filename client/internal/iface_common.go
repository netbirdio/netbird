package internal

import (
	"net"
	"net/netip"
	"time"

	wgdevice "golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/netbirdio/netbird/client/iface/configurer"
	"github.com/netbirdio/netbird/client/iface/device"
	"github.com/netbirdio/netbird/client/iface/udpmux"
	"github.com/netbirdio/netbird/client/iface/wgaddr"
	"github.com/netbirdio/netbird/client/iface/wgproxy"
	"github.com/netbirdio/netbird/monotime"
)

type wgIfaceBase interface {
	Create() error
	CreateOnAndroid(routeRange []string, ip string, domains []string) error
	RenewTun(fd int) error
	IsUserspaceBind() bool
	Name() string
	Address() wgaddr.Address
	ToInterface() *net.Interface
	Up() (*udpmux.UniversalUDPMuxDefault, error)
	UpdateAddr(newAddr string) error
	GetProxy() wgproxy.Proxy
	UpdatePeer(peerKey string, allowedIps []netip.Prefix, keepAlive time.Duration, endpoint *net.UDPAddr, preSharedKey *wgtypes.Key) error
	RemoveEndpointAddress(key string) error
	RemovePeer(peerKey string) error
	AddAllowedIP(peerKey string, allowedIP netip.Prefix) error
	RemoveAllowedIP(peerKey string, allowedIP netip.Prefix) error
	Close() error
	SetFilter(filter device.PacketFilter) error
	GetFilter() device.PacketFilter
	GetDevice() *device.FilteredDevice
	GetWGDevice() *wgdevice.Device
	GetStats() (map[string]configurer.WGStats, error)
	GetNet() *netstack.Net
	FullStats() (*configurer.Stats, error)
	LastActivities() map[string]monotime.Time
}
