package types

import (
	peerTypes "github.com/netbirdio/netbird/management/refactor/resources/peers/types"
	policyTypes "github.com/netbirdio/netbird/management/refactor/resources/policies/types"
	routeTypes "github.com/netbirdio/netbird/management/refactor/resources/routes/types"

	nbdns "github.com/netbirdio/netbird/dns"
)

type NetworkMap struct {
	Peers         []*peerTypes.Peer
	Network       *Network
	Routes        []*routeTypes.Route
	DNSConfig     nbdns.Config
	OfflinePeers  []*peerTypes.Peer
	FirewallRules []*policyTypes.FirewallRule
}
