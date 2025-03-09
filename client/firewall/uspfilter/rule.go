package uspfilter

import (
	"net"
	"net/netip"

	"github.com/google/gopacket"

	firewall "github.com/netbirdio/netbird/client/firewall/manager"
)

// PeerRule to handle management of rules
type PeerRule struct {
	id         string
	ip         net.IP
	ipLayer    gopacket.LayerType
	matchByIP  bool
	protoLayer gopacket.LayerType
	sPort      *firewall.Port
	dPort      *firewall.Port
	drop       bool
	comment    string

	udpHook func([]byte) bool
}

// ID returns the rule id
func (r *PeerRule) ID() string {
	return r.id
}

type RouteRule struct {
	id          string
	sources     []netip.Prefix
	destination netip.Prefix
	proto       firewall.Protocol
	srcPort     *firewall.Port
	dstPort     *firewall.Port
	action      firewall.Action
}

// ID returns the rule id
func (r *RouteRule) ID() string {
	return r.id
}
