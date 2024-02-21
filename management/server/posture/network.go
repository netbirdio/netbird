package posture

import (
	"fmt"
	"net/netip"

	nbpeer "github.com/netbirdio/netbird/management/server/peer"
)

type PrivateNetworkCheck struct {
	Action   string
	Prefixes []netip.Prefix
}

var _ Check = (*PrivateNetworkCheck)(nil)

func (p *PrivateNetworkCheck) Check(peer nbpeer.Peer) (bool, error) {
	for _, prefix := range p.Prefixes {
		for _, peerNetAddr := range peer.Meta.NetworkAddresses {
			if prefix.Masked() == peerNetAddr.NetIP.Masked() {
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
	}

	if p.Action == CheckActionDeny {
		return true, nil
	}
	if p.Action == CheckActionAllow {
		return false, nil
	}

	return false, fmt.Errorf("invalid private network action: %s", p.Action)
}

func (p *PrivateNetworkCheck) Name() string {
	return PrivateNetworkCheckName
}
