package nmdata

import (
	"fmt"
	"net/netip"
)

// PeerNetworkRangeCheck is the slim twin of posture.PeerNetworkRangeCheck.
type PeerNetworkRangeCheck struct {
	Action string
	Ranges []netip.Prefix
}

func (p *PeerNetworkRangeCheck) check(peer *Peer) (bool, error) {
	peerPrefixes := make([]netip.Prefix, 0, len(peer.Meta.NetworkAddresses)+1)
	for _, peerNetAddr := range peer.Meta.NetworkAddresses {
		peerPrefixes = append(peerPrefixes, peerNetAddr.NetIP)
	}
	if connIP := peer.Location.ConnectionIP; len(connIP) > 0 {
		if addr, ok := netip.AddrFromSlice(connIP); ok {
			addr = addr.Unmap()
			peerPrefixes = append(peerPrefixes, netip.PrefixFrom(addr, addr.BitLen()))
		}
	}

	if len(peerPrefixes) == 0 {
		return false, fmt.Errorf("peer's does not contain peer network range addresses")
	}

	for _, peerPrefix := range peerPrefixes {
		for _, rangePrefix := range p.Ranges {
			if !prefixContains(rangePrefix, peerPrefix) {
				continue
			}
			switch p.Action {
			case checkActionDeny:
				return false, nil
			case checkActionAllow:
				return true, nil
			default:
				return false, fmt.Errorf("invalid peer network range check action: %s", p.Action)
			}
		}
	}

	if p.Action == checkActionDeny {
		return true, nil
	}
	if p.Action == checkActionAllow {
		return false, nil
	}

	return false, fmt.Errorf("invalid peer network range check action: %s", p.Action)
}

func prefixContains(outer, inner netip.Prefix) bool {
	outer = outer.Masked()
	inner = inner.Masked()
	return outer.Bits() <= inner.Bits() &&
		outer.Addr().BitLen() == inner.Addr().BitLen() &&
		outer.Contains(inner.Addr())
}
