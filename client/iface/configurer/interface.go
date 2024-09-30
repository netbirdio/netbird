package configurer

import (
	"errors"
	"net"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

var ErrPeerNotFound = errors.New("peer not found")

type WGConfigurer interface {
	ConfigureInterface(privateKey string, port int) error
	UpdatePeer(peerKey string, allowedIps string, keepAlive time.Duration, endpoint *net.UDPAddr, preSharedKey *wgtypes.Key) error
	RemovePeer(peerKey string) error
	AddAllowedIP(peerKey string, allowedIP string) error
	RemoveAllowedIP(peerKey string, allowedIP string) error
	Close()
	GetStats(peerKey string) (WGStats, error)
}
