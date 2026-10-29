package types

import (
	nbdns "github.com/netbirdio/netbird/dns"
	"github.com/netbirdio/netbird/shared/management/networkmap/nmdata"
)

const (
	// AllowedIPsFormat generates Wireguard AllowedIPs format (e.g. 100.64.30.1/32)
	AllowedIPsFormat = "%s/32"
	// AllowedIPsV6Format generates AllowedIPs format for v6 (e.g. fd12:3456:7890::1/128)
	AllowedIPsV6Format = "%s/128"
)

type NetworkMap struct {
	Peers               []*nmdata.Peer
	Network             *nmdata.Network
	Routes              []*nmdata.Route
	DNSConfig           nbdns.Config
	OfflinePeers        []*nmdata.Peer
	FirewallRules       []*FirewallRule
	RoutesFirewallRules []*RouteFirewallRule
	AuthorizedUsers     map[string]map[string]struct{}
	EnableSSH           bool
	// ForceRoutingPeerDNSResolution forces the peer to run/use routing-peer DNS
	// resolution regardless of the account-global setting, for reverse-proxy
	// domain targets.
	ForceRoutingPeerDNSResolution bool
}
