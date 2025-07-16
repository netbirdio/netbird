package lazyconn

import (
	"net"
	"net/netip"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/netbirdio/netbird/monotime"
)

type WGIface interface {
	RemovePeer(peerKey string) error
	UpdatePeer(peerKey string, allowedIps []netip.Prefix, keepAlive time.Duration, endpoint *net.UDPAddr, preSharedKey *wgtypes.Key) error
	IsUserspaceBind() bool
	LastActivities() map[string]monotime.Time
}
