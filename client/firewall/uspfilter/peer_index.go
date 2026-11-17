package uspfilter

import (
	"net/netip"
	"slices"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	firewall "github.com/netbirdio/netbird/client/firewall/manager"
)

// peerRuleIndex is the source-side dispatcher consulted on the packet
// hot path. It splits rules into two buckets by the shape of their
// source list:
//
//   - bySource: every source is a host prefix (/32 for v4, /128 for
//     v6). Keyed by the concrete source address, so a hit guarantees
//     the source filter passes and the matcher goes straight to
//     proto/port checks. This is the common case for peer ACLs.
//   - nonHost: any source list with a prefix coarser than a host,
//     including a /0 "match any". Walked linearly with a per-rule
//     Contains() check. Expected small or empty for typical peer ACLs.
//
// Maintained incrementally by add/remove, never rebuilt.
type peerRuleIndex struct {
	bySource map[netip.Addr][]*PeerRule
	nonHost  []*PeerRule
}

func (i *peerRuleIndex) add(r *PeerRule) {
	if hasNonHostSource(r) {
		i.nonHost = append(i.nonHost, r)
		return
	}
	if i.bySource == nil {
		i.bySource = make(map[netip.Addr][]*PeerRule)
	}
	for a := range r.sourceAddrs {
		i.bySource[a] = append(i.bySource[a], r)
	}
}

func (i *peerRuleIndex) remove(r *PeerRule) {
	if hasNonHostSource(r) {
		i.nonHost = slices.DeleteFunc(i.nonHost, eqRule(r))
		return
	}
	if i.bySource == nil {
		return
	}
	for a := range r.sourceAddrs {
		entries := slices.DeleteFunc(i.bySource[a], eqRule(r))
		if len(entries) == 0 {
			delete(i.bySource, a)
		} else {
			i.bySource[a] = entries
		}
	}
}

func (i *peerRuleIndex) reset() {
	i.bySource = nil
	i.nonHost = i.nonHost[:0]
}

// match returns the first rule matching src and the decoded packet.
// Host rules are found by direct map lookup; nonHost rules run a
// per-rule source Contains() check. Containment is family-scoped, so
// a /0 source matches every address of its own family only (0.0.0.0/0
// never matches v6 sources and ::/0 never matches v4). Within either
// bucket the matcher runs the proto/port filter.
func (i *peerRuleIndex) match(src netip.Addr, d *decoder) ([]byte, bool, bool) {
	payloadLayer := d.decoded[1]

	for _, rule := range i.bySource[src] {
		if id, drop, ok := matchProto(rule, d, payloadLayer); ok {
			return id, drop, true
		}
	}
	for _, rule := range i.nonHost {
		if !prefixesContain(rule.sources, src) {
			continue
		}
		if id, drop, ok := matchProto(rule, d, payloadLayer); ok {
			return id, drop, true
		}
	}
	return nil, false, false
}

func eqRule(target *PeerRule) func(*PeerRule) bool {
	return func(p *PeerRule) bool { return p == target }
}

// hasNonHostSource reports whether the rule has any source prefix
// that is not a single host address. Called only at add/remove time,
// not on the packet path.
func hasNonHostSource(r *PeerRule) bool {
	for _, p := range r.sources {
		if p.Bits() != p.Addr().BitLen() {
			return true
		}
	}
	return false
}

// matchProto applies the proto/port half of a rule against the
// decoded packet. Source matching is the caller's responsibility.
func matchProto(rule *PeerRule, d *decoder, payloadLayer gopacket.LayerType) ([]byte, bool, bool) {
	drop := rule.action == firewall.ActionDrop
	if rule.protoLayer == layerTypeAll {
		return rule.mgmtId, drop, true
	}
	if !protoLayerMatches(rule.protoLayer, payloadLayer) {
		return nil, false, false
	}
	switch payloadLayer {
	case layers.LayerTypeTCP:
		if portsMatch(rule.srcPort, uint16(d.tcp.SrcPort)) && portsMatch(rule.dstPort, uint16(d.tcp.DstPort)) {
			return rule.mgmtId, drop, true
		}
	case layers.LayerTypeUDP:
		if portsMatch(rule.srcPort, uint16(d.udp.SrcPort)) && portsMatch(rule.dstPort, uint16(d.udp.DstPort)) {
			return rule.mgmtId, drop, true
		}
	case layers.LayerTypeICMPv4, layers.LayerTypeICMPv6:
		return rule.mgmtId, drop, true
	}
	return nil, false, false
}

func prefixesContain(sources []netip.Prefix, src netip.Addr) bool {
	for _, p := range sources {
		if p.Contains(src) {
			return true
		}
	}
	return false
}
