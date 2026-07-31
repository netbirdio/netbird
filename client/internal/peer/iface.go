package peer

import (
	"net"
	"net/netip"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/netbirdio/netbird/client/iface/configurer"
	"github.com/netbirdio/netbird/client/iface/wgaddr"
	"github.com/netbirdio/netbird/client/iface/wgproxy"
	"github.com/netbirdio/netbird/monotime"
)

type WGIface interface {
	UpdatePeer(peerKey string, allowedIps []netip.Prefix, keepAlive time.Duration, endpoint *net.UDPAddr, preSharedKey *wgtypes.Key) error
	RemovePeer(peerKey string) error
	GetStats() (map[string]configurer.WGStats, error)
	GetProxy() wgproxy.Proxy
	Address() wgaddr.Address
	RemoveEndpointAddress(key string) error
	// LastActivities returns the last real-data activity time per peer (WireGuard
	// keepalives excluded), used to gate post-quantum PSK rotation on active tunnels.
	LastActivities() map[string]monotime.Time
}
