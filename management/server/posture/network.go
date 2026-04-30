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

// Check evaluates configured ranges against the peer's local network interfaces and its
// public connection IP (as a /32 or /128). Including the connection IP lets operators
// match peers by their NAT'd public address — local NICs alone never expose that.
func (p *PeerNetworkRangeCheck) Check(ctx context.Context, peer nbpeer.Peer) (bool, error) {
	peerMaskedPrefixes := make([]netip.Prefix, 0, len(peer.Meta.NetworkAddresses)+1)
	for _, peerNetAddr := range peer.Meta.NetworkAddresses {
		peerMaskedPrefixes = append(peerMaskedPrefixes, peerNetAddr.NetIP.Masked())
	}
	// Include the peer's public connection IP as a host prefix (/32 or /128) so operators
	// can match on the NAT'd egress IP — peer.Meta.NetworkAddresses only carries local NICs.
	// Unmap collapses 4-in-6 forms (::ffff:a.b.c.d) so an IPv4 prefix matches.
	if connIP := peer.Location.ConnectionIP; len(connIP) > 0 {
		if addr, ok := netip.AddrFromSlice(connIP); ok {
			addr = addr.Unmap()
			peerMaskedPrefixes = append(peerMaskedPrefixes, netip.PrefixFrom(addr, addr.BitLen()))
		}
	}

	if len(peerMaskedPrefixes) == 0 {
		return false, fmt.Errorf("peer's does not contain peer network range addresses")
	}

	maskedPrefixes := make([]netip.Prefix, 0, len(p.Ranges))
	for _, prefix := range p.Ranges {
		maskedPrefixes = append(maskedPrefixes, prefix.Masked())
	}

	for _, peerMaskedPrefix := range peerMaskedPrefixes {
		if slices.Contains(maskedPrefixes, peerMaskedPrefix) {
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
