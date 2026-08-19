package posture

import (
	"context"
	"fmt"
	"net/netip"
	"slices"

	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/shared/management/status"
)

type PeerNetworkRangeCheck struct {
	Action string
	Ranges []netip.Prefix `gorm:"serializer:json"`
}

var _ Check = (*PeerNetworkRangeCheck)(nil)

// prefixContains reports whether outer fully contains inner (equal counts as contained).
// Requires the same address family, that outer is no more specific than inner (its
// netmask is shorter or equal), and that inner's network address falls inside outer.
// This is stricter than netip.Prefix.Contains(Addr) — a peer's /24 NIC will not match a
// configured /32 rule, since the rule covers a single host but the NIC describes a whole
// subnet whose host bits are unknown.
func prefixContains(outer, inner netip.Prefix) bool {
	outer = outer.Masked()
	inner = inner.Masked()
	return outer.Bits() <= inner.Bits() &&
		outer.Addr().BitLen() == inner.Addr().BitLen() && // same family
		outer.Contains(inner.Addr())
}

// Check evaluates configured ranges against the peer's local network interface prefixes
// and its public connection IP (as a /32 or /128). A configured range matches when it
// fully contains one of those prefixes, so operators can target both private subnets
// and public CIDRs (e.g. 1.0.0.0/24, 2.2.2.2/32). Including the connection IP is what
// lets a public-range posture check work — peer.Meta.NetworkAddresses only carries
// local NIC addresses.
func (p *PeerNetworkRangeCheck) Check(ctx context.Context, peer nbpeer.Peer) (bool, error) {
	peerPrefixes := make([]netip.Prefix, 0, len(peer.Meta.NetworkAddresses)+1)
	for _, peerNetAddr := range peer.Meta.NetworkAddresses {
		peerPrefixes = append(peerPrefixes, peerNetAddr.NetIP)
	}
	// Unmap collapses 4-in-6 forms (::ffff:a.b.c.d) so an IPv4 range matches.
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
			case CheckActionDeny:
				return false, nil
			case CheckActionAllow:
				return true, nil
			default:
				return false, fmt.Errorf("invalid peer network range check action: %s", p.Action)
			}
		}
	}

	if p.Action == CheckActionDeny {
		return true, nil
	}
	if p.Action == CheckActionAllow {
		return false, nil
	}

	return false, fmt.Errorf("invalid peer network range check action: %s", p.Action)
}

func (p *PeerNetworkRangeCheck) Name() string {
	return PeerNetworkRangeCheckName
}

func (p *PeerNetworkRangeCheck) Validate() error {
	if p.Action == "" {
		return status.Errorf(status.InvalidArgument, "action for peer network range check shouldn't be empty")
	}

	allowedActions := []string{CheckActionAllow, CheckActionDeny}
	if !slices.Contains(allowedActions, p.Action) {
		return fmt.Errorf("%s action is not valid", p.Name())
	}

	if len(p.Ranges) == 0 {
		return fmt.Errorf("%s network ranges shouldn't be empty", p.Name())
	}
	return nil
}
