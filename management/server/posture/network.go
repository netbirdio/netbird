package posture

import (
	"net/netip"

	nbpeer "github.com/netbirdio/netbird/management/server/peer"
)

type PrivateNetworkCheck struct {
	Action   string
	Prefixes []netip.Prefix
}

var _ Check = (*PrivateNetworkCheck)(nil)

func (p *PrivateNetworkCheck) Check(peer nbpeer.Peer) (bool, error) {
	return false, nil
}

func (p *PrivateNetworkCheck) Name() string {
	return PrivateNetworkCheckName
}
