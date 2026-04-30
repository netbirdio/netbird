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

// Check evaluates configured ranges against the peer's local network interface IPs and
// its public connection IP. A configured range matches when it contains any of those
// addresses, so operators can target both NAT'd egress (e.g. 1.0.0.0/24) and exact hosts
// (e.g. 2.2.2.2/32). Including the connection IP is what lets a public-range posture
// check work — peer.Meta.NetworkAddresses only carries local NIC addresses.
func (p *PeerNetworkRangeCheck) Check(ctx context.Context, peer nbpeer.Peer) (bool, error) {
	peerAddrs := make([]netip.Addr, 0, len(peer.Meta.NetworkAddresses)+1)
	for _, peerNetAddr := range peer.Meta.NetworkAddresses {
		peerAddrs = append(peerAddrs, peerNetAddr.NetIP.Addr())
	}
	// Unmap collapses 4-in-6 forms (::ffff:a.b.c.d) so an IPv4 range matches.
	if connIP := peer.Location.ConnectionIP; len(connIP) > 0 {
		if addr, ok := netip.AddrFromSlice(connIP); ok {
			peerAddrs = append(peerAddrs, addr.Unmap())
		}
	}

	if len(peerAddrs) == 0 {
		return false, fmt.Errorf("peer's does not contain peer network range addresses")
	}

	for _, peerAddr := range peerAddrs {
		for _, prefix := range p.Ranges {
			if !prefix.Contains(peerAddr) {
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
