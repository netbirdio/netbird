package legacynmap

import (
	types "github.com/netbirdio/netbird/management/server/types"
	sharedtypes "github.com/netbirdio/netbird/shared/management/types"
)

type (
	Account = types.Account

	DNSSettings       = types.DNSSettings
	FirewallRule      = sharedtypes.FirewallRule
	ForwardingRule    = sharedtypes.ForwardingRule
	Group             = types.Group
	Network           = types.Network
	Policy            = types.Policy
	PolicyRule        = types.PolicyRule
	Resource          = types.Resource
	RulePortRange     = sharedtypes.RulePortRange
	RouteFirewallRule = sharedtypes.RouteFirewallRule
)

const (
	FirewallRuleDirectionIN  = sharedtypes.FirewallRuleDirectionIN
	FirewallRuleDirectionOUT = sharedtypes.FirewallRuleDirectionOUT

	PolicyRuleProtocolALL        = sharedtypes.PolicyRuleProtocolALL
	PolicyRuleProtocolTCP        = sharedtypes.PolicyRuleProtocolTCP
	PolicyRuleProtocolNetbirdSSH = sharedtypes.PolicyRuleProtocolNetbirdSSH
	PolicyTrafficActionAccept    = sharedtypes.PolicyTrafficActionAccept
	ResourceTypePeer             = sharedtypes.ResourceTypePeer

	AllowedIPsFormat   = sharedtypes.AllowedIPsFormat
	AllowedIPsV6Format = sharedtypes.AllowedIPsV6Format
)
