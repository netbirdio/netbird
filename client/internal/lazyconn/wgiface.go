package lazyconn

import (
	"net"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/netbirdio/netbird/client/iface/configurer"
)

type WGIface interface {
	Transfers() (map[wgtypes.Key]configurer.WGStats, error)
	RemovePeer(key wgtypes.Key) error
	UpdatePeer(peerKey string, allowedIps string, keepAlive time.Duration, endpoint *net.UDPAddr, preSharedKey *wgtypes.Key) error
}
