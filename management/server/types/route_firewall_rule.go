package types

import (
	"github.com/netbirdio/netbird/management/domain"
)

// RouteFirewallRule a firewall rule applicable for a routed network.
type RouteFirewallRule struct {
	// SourceRanges IP ranges of the routing peers.
	SourceRanges []string

	// Action of the traffic when the rule is applicable
	Action string

	// Destination a network prefix for the routed traffic
	Destination string

	// Protocol of the traffic
	Protocol string

	// Port of the traffic
	Port uint16

	// PortRange represents the range of ports for a firewall rule
	PortRange RulePortRange

	// Domains list of network domains for the routed traffic
	Domains domain.List

	// isDynamic indicates whether the rule is for DNS routing
	IsDynamic bool
}
