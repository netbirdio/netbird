package device

import (
	"net"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/netbirdio/netbird/client/iface/configurer"
)

type WGConfigurer interface {
	ConfigureInterface(privateKey string, port int) error
	UpdatePeer(peerKey string, allowedIps []net.IPNet, keepAlive time.Duration, endpoint *net.UDPAddr, preSharedKey *wgtypes.Key) error
	RemovePeer(peerKey string) error
	AddAllowedIP(peerKey string, allowedIP string) error
	RemoveAllowedIP(peerKey string, allowedIP string) error
	Close()
	GetStats() (map[string]configurer.WGStats, error)
	FullStats() (*configurer.Stats, error)
}
