package posture

import (
	"fmt"
	"net/netip"
	"slices"

	nbpeer "github.com/netbirdio/netbird/management/server/peer"
)

type PeerNetworkRangeCheck struct {
	Action string
	Ranges []netip.Prefix `gorm:"serializer:json"`
}

var _ Check = (*PeerNetworkRangeCheck)(nil)

func (p *PeerNetworkRangeCheck) Check(peer nbpeer.Peer) (bool, error) {
	if len(peer.Meta.NetworkAddresses) == 0 {
		return false, fmt.Errorf("peer's does not contain peer network range addresses")
	}

	maskedPrefixes := make([]netip.Prefix, 0, len(p.Ranges))
	for _, prefix := range p.Ranges {
		maskedPrefixes = append(maskedPrefixes, prefix.Masked())
	}

	for _, peerNetAddr := range peer.Meta.NetworkAddresses {
		peerMaskedPrefix := peerNetAddr.NetIP.Masked()
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
