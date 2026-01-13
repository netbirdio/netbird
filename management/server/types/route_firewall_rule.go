package types

import (
	"github.com/netbirdio/netbird/route"
	"github.com/netbirdio/netbird/shared/management/domain"
)

// RouteFirewallRule a firewall rule applicable for a routed network.
type RouteFirewallRule struct {
	// PolicyID is the ID of the policy this rule is derived from
	PolicyID string

	// RouteID is the ID of the route this rule belongs to.
	RouteID route.ID

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

func (r *RouteFirewallRule) Equal(other *RouteFirewallRule) bool {
	if r.Action != other.Action {
		return false
	}
	if r.Destination != other.Destination {
		return false
	}
	if r.Protocol != other.Protocol {
		return false
	}
	if r.Port != other.Port {
		return false
	}
	if !r.PortRange.Equal(&other.PortRange) {
		return false
	}
	if !r.Domains.Equal(other.Domains) {
		return false
	}
	if r.IsDynamic != other.IsDynamic {
		return false
	}
	return true
}
