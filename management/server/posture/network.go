package posture

import (
	"fmt"
	"net/netip"
	"slices"

	nbpeer "github.com/netbirdio/netbird/management/server/peer"
)

type PrivateNetworkCheck struct {
	Action string
	Ranges []netip.Prefix
}

var _ Check = (*PrivateNetworkCheck)(nil)

func (p *PrivateNetworkCheck) Check(peer nbpeer.Peer) (bool, error) {
	if len(peer.Meta.NetworkAddresses) == 0 {
		return false, fmt.Errorf("peer's does not contain private network addresses")
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
				return false, fmt.Errorf("invalid private network check action: %s", p.Action)
			}
		}
	}

	if p.Action == CheckActionDeny {
		return true, nil
	}
	if p.Action == CheckActionAllow {
		return false, nil
	}

	return false, fmt.Errorf("invalid private network check action: %s", p.Action)
}

func (p *PrivateNetworkCheck) Name() string {
	return PrivateNetworkCheckName
}
