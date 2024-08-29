package iface

import (
	"net"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/netbirdio/netbird/iface/bind"
)

type IWGIface interface {
	Create() error
	CreateOnAndroid(routeRange []string, ip string, domains []string) error
	IsUserspaceBind() bool
	Name() string
	Address() WGAddress
	ToInterface() *net.Interface
	Up() (*bind.UniversalUDPMuxDefault, error)
	UpdateAddr(newAddr string) error
	UpdatePeer(peerKey string, allowedIps string, keepAlive time.Duration, endpoint *net.UDPAddr, preSharedKey *wgtypes.Key) error
	RemovePeer(peerKey string) error
	AddAllowedIP(peerKey string, allowedIP string) error
	RemoveAllowedIP(peerKey string, allowedIP string) error
	Close() error
	SetFilter(filter PacketFilter) error
	GetFilter() PacketFilter
	GetDevice() *DeviceWrapper
	GetStats(peerKey string) (WGStats, error)
	GetInterfaceGUIDString() (string, error)
}
