package mesh

import (
	nbdns "github.com/netbirdio/netbird/dns"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
)

type NetworkMap struct {
	Peers         []*nbpeer.Peer
	Network       *Network
	Routes        []*route.Route
	DNSConfig     nbdns.Config
	OfflinePeers  []*nbpeer.Peer
	FirewallRules []*FirewallRule
}
