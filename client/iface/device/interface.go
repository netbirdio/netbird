package device

import (
	"net"
	"net/netip"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/netbirdio/netbird/client/iface/configurer"
	"github.com/netbirdio/netbird/monotime"
)

type WGConfigurer interface {
	ConfigureInterface(privateKey string, port int) error
	UpdatePeer(peerKey string, allowedIps []netip.Prefix, keepAlive time.Duration, endpoint *net.UDPAddr, preSharedKey *wgtypes.Key) error
	RemovePeer(peerKey string) error
	AddAllowedIP(peerKey string, allowedIP netip.Prefix) error
	RemoveAllowedIP(peerKey string, allowedIP netip.Prefix) error
	SetPresharedKey(peerKey string, psk wgtypes.Key, updateOnly bool) error
	Close()
	GetStats() (map[string]configurer.WGStats, error)
	FullStats() (*configurer.Stats, error)
	LastActivities() map[string]monotime.Time
	RemoveEndpointAddress(peerKey string) error
}
