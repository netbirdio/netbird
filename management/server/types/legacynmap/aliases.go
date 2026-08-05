//go:build nmapequiv

// Package legacynmap is a frozen copy of main's Account → NetworkMapComponents →
// NetworkMap → proto path, used only by the main-vs-branch equivalence test.
// It is build-tagged so it never compiles into production binaries, and it lives
// in its own package so it cannot reach this tree's unexported helpers — a
// divergence can therefore never be hidden by the two sides sharing code.
//
// Delete this package once the nmdata refactor is validated.
//
// Types below are aliased rather than copied because they are byte-identical
// between main and this branch. Anything that drifted is copied instead; see
// converters.go and copied_funcs.go.
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
