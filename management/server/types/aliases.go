package types

import (
	"context"
	"math/rand"
	"net"
	"net/netip"

	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	nbroute "github.com/netbirdio/netbird/route"
	sharedtypes "github.com/netbirdio/netbird/shared/management/types"
)

// Type aliases for types relocated to shared/management/types so that the
// client-side compute path can depend on them

type DNSSettings = sharedtypes.DNSSettings

type FirewallRule = sharedtypes.FirewallRule

type Group = sharedtypes.Group
type GroupPeer = sharedtypes.GroupPeer

type Network = sharedtypes.Network
type NetworkMap = sharedtypes.NetworkMap
type ForwardingRule = sharedtypes.ForwardingRule

type Policy = sharedtypes.Policy
type PolicyUpdateOperation = sharedtypes.PolicyUpdateOperation

type PolicyRule = sharedtypes.PolicyRule
type PolicyUpdateOperationType = sharedtypes.PolicyUpdateOperationType
type PolicyTrafficActionType = sharedtypes.PolicyTrafficActionType
type PolicyRuleProtocolType = sharedtypes.PolicyRuleProtocolType
type PolicyRuleDirection = sharedtypes.PolicyRuleDirection
type RulePortRange = sharedtypes.RulePortRange

type Resource = sharedtypes.Resource
type ResourceType = sharedtypes.ResourceType

type RouteFirewallRule = sharedtypes.RouteFirewallRule

type NetworkMapComponents = sharedtypes.NetworkMapComponents
type AccountSettingsInfo = sharedtypes.AccountSettingsInfo

type GroupCompact = sharedtypes.GroupCompact
type NetworkMapComponentsCompact = sharedtypes.NetworkMapComponentsCompact

type LookupMap = sharedtypes.LookupMap
type FirewallRuleContext = sharedtypes.FirewallRuleContext

const (
	GroupIssuedAPI         = sharedtypes.GroupIssuedAPI
	GroupIssuedJWT         = sharedtypes.GroupIssuedJWT
	GroupIssuedIntegration = sharedtypes.GroupIssuedIntegration
	GroupAllName           = sharedtypes.GroupAllName
)

// Function forwarders preserve types.X(...) call sites that previously
// resolved to package-local funcs. Plain forwarders (not var aliases) keep
// the symbol immutable and allow the inliner to flatten the call.

func PolicyRuleImpliesLegacySSH(rule *PolicyRule) bool {
	return sharedtypes.PolicyRuleImpliesLegacySSH(rule)
}

func ExpandPortsAndRanges(base FirewallRule, rule *PolicyRule, peer *nbpeer.Peer) []*FirewallRule {
	return sharedtypes.ExpandPortsAndRanges(base, rule, peer)
}

func AppendIPv6FirewallRule(rules []*FirewallRule, rulesExists map[string]struct{}, peer, targetPeer *nbpeer.Peer, rule *PolicyRule, rc FirewallRuleContext) []*FirewallRule {
	return sharedtypes.AppendIPv6FirewallRule(rules, rulesExists, peer, targetPeer, rule, rc)
}

func CalculateNetworkMapFromComponents(ctx context.Context, components *NetworkMapComponents) *NetworkMap {
	return sharedtypes.CalculateNetworkMapFromComponents(ctx, components)
}

func GenerateRouteFirewallRules(ctx context.Context, route *nbroute.Route, rule *PolicyRule, groupPeers []*nbpeer.Peer, direction int, includeIPv6 bool) []*RouteFirewallRule {
	return sharedtypes.GenerateRouteFirewallRules(ctx, route, rule, groupPeers, direction, includeIPv6)
}

func AllocateIPv6Subnet(r *rand.Rand) net.IPNet {
	return sharedtypes.AllocateIPv6Subnet(r)
}

func NewNetwork() *Network {
	return sharedtypes.NewNetwork()
}

func AllocatePeerIP(prefix netip.Prefix, takenIps []netip.Addr) (netip.Addr, error) {
	return sharedtypes.AllocatePeerIP(prefix, takenIps)
}

func AllocateRandomPeerIP(prefix netip.Prefix) (netip.Addr, error) {
	return sharedtypes.AllocateRandomPeerIP(prefix)
}

func AllocateRandomPeerIPv6(prefix netip.Prefix) (netip.Addr, error) {
	return sharedtypes.AllocateRandomPeerIPv6(prefix)
}

func ParseRuleString(rule string) (PolicyRuleProtocolType, RulePortRange, error) {
	return sharedtypes.ParseRuleString(rule)
}

const (
	FirewallRuleDirectionIN  = sharedtypes.FirewallRuleDirectionIN
	FirewallRuleDirectionOUT = sharedtypes.FirewallRuleDirectionOUT
)

const (
	ResourceTypePeer   = sharedtypes.ResourceTypePeer
	ResourceTypeDomain = sharedtypes.ResourceTypeDomain
	ResourceTypeHost   = sharedtypes.ResourceTypeHost
	ResourceTypeSubnet = sharedtypes.ResourceTypeSubnet
)

const (
	PolicyTrafficActionAccept = sharedtypes.PolicyTrafficActionAccept
	PolicyTrafficActionDrop   = sharedtypes.PolicyTrafficActionDrop
)

const (
	PolicyRuleProtocolALL        = sharedtypes.PolicyRuleProtocolALL
	PolicyRuleProtocolTCP        = sharedtypes.PolicyRuleProtocolTCP
	PolicyRuleProtocolUDP        = sharedtypes.PolicyRuleProtocolUDP
	PolicyRuleProtocolICMP       = sharedtypes.PolicyRuleProtocolICMP
	PolicyRuleProtocolNetbirdSSH = sharedtypes.PolicyRuleProtocolNetbirdSSH
)

const (
	PolicyRuleFlowDirect   = sharedtypes.PolicyRuleFlowDirect
	PolicyRuleFlowBidirect = sharedtypes.PolicyRuleFlowBidirect
)

const (
	DefaultRuleName          = sharedtypes.DefaultRuleName
	DefaultRuleDescription   = sharedtypes.DefaultRuleDescription
	DefaultPolicyName        = sharedtypes.DefaultPolicyName
	DefaultPolicyDescription = sharedtypes.DefaultPolicyDescription
)
