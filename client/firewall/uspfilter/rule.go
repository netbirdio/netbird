package uspfilter

import (
	"net/netip"

	"github.com/google/gopacket"

	firewall "github.com/netbirdio/netbird/client/firewall/manager"
)

// PeerRule to handle management of rules
type PeerRule struct {
	id         string
	mgmtId     []byte
	ip         netip.Addr
	ipLayer    gopacket.LayerType
	matchByIP  bool
	protoLayer gopacket.LayerType
	sPort      *firewall.Port
	dPort      *firewall.Port
	drop       bool

	udpHook func([]byte) bool
}

// ID returns the rule id
func (r *PeerRule) ID() string {
	return r.id
}

type RouteRule struct {
	id           string
	mgmtId       []byte
	sources      []netip.Prefix
	dstSet       firewall.Set
	destinations []netip.Prefix
	protoLayer   gopacket.LayerType
	srcPort      *firewall.Port
	dstPort      *firewall.Port
	action       firewall.Action
}

// ID returns the rule id
func (r *RouteRule) ID() string {
	return r.id
}
