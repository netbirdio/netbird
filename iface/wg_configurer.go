package iface

import (
	"net"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type wgConfigurer interface {
	configureInterface(privateKey string, port int) error
	updatePeer(peerKey string, allowedIps string, keepAlive time.Duration, endpoint *net.UDPAddr, preSharedKey *wgtypes.Key) error
	removePeer(peerKey string) error
	addAllowedIP(peerKey string, allowedIP string) error
	removeAllowedIP(peerKey string, allowedIP string) error
	close()
	getStats(peerKey string) (WGStats, error)
}
