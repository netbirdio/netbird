package uspfilter

import (
	"net/netip"

	"github.com/google/gopacket"

	firewall "github.com/netbirdio/netbird/client/firewall/manager"
)

// PeerRule to handle management of rules
type PeerRule struct {
	id     firewall.RuleID
	mgmtId []byte
	// sources is the canonical list of source prefixes this rule
	// matches against.
	sources []netip.Prefix
	// sourceAddrs is a fast-path membership set for host-prefix
	// sources (/32 v4, /128 v6). Populated alongside sources;
	// consulted before falling back to prefix scan.
	sourceAddrs map[netip.Addr]struct{}
	protoLayer  gopacket.LayerType
	srcPort     *firewall.Port
	dstPort     *firewall.Port
	action      firewall.Action
}

// matchesSource reports whether the given source address is covered
// by this rule's source list. Prefix containment is family-scoped, so
// a /0 source matches every address of its own family only.
func (r *PeerRule) matchesSource(src netip.Addr) bool {
	if _, ok := r.sourceAddrs[src]; ok {
		return true
	}
	for _, p := range r.sources {
		if p.Contains(src) {
			return true
		}
	}
	return false
}

// ID returns the rule id
func (r *PeerRule) ID() firewall.RuleID {
	return r.id
}

type RouteRule struct {
	id           firewall.RuleID
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
func (r *RouteRule) ID() firewall.RuleID {
	return r.id
}
