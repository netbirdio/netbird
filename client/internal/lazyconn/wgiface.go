package lazyconn

import (
	"net"
	"net/netip"

	"github.com/netbirdio/netbird/client/iface/wgaddr"
	"github.com/netbirdio/netbird/monotime"
)

type WGIface interface {
	RemovePeer(peerKey string) error
	IdlePeerEndpoint(peerKey string, allowedIPs []netip.Prefix, endpoint *net.UDPAddr) error
	IsUserspaceBind() bool
	Address() wgaddr.Address
	LastActivities() map[string]monotime.Time
	MTU() uint16
}
