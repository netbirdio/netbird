package peer

import (
	"net"
	"time"

	"github.com/netbirdio/netbird/client/iface/configurer"
	"github.com/netbirdio/netbird/client/iface/wgproxy"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type WGIface interface {
	UpdatePeer(peerKey string, allowedIps string, keepAlive time.Duration, endpoint *net.UDPAddr, preSharedKey *wgtypes.Key) error
	RemovePeer(peerKey string) error
	GetStats(peerKey string) (configurer.WGStats, error)
	GetProxy() wgproxy.Proxy
}
