package types

import (
	"context"

	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	nbroute "github.com/netbirdio/netbird/route"
	"github.com/netbirdio/netbird/shared/management/networkmap/nmdata"
	sharedtypes "github.com/netbirdio/netbird/shared/management/types"
)

// Type aliases for types relocated to shared/management/types so that the
// client-side compute path can depend on them

type FirewallRule = sharedtypes.FirewallRule

type NetworkMap = sharedtypes.NetworkMap
type ForwardingRule = sharedtypes.ForwardingRule

type PolicyTrafficActionType = sharedtypes.PolicyTrafficActionType
type PolicyRuleProtocolType = sharedtypes.PolicyRuleProtocolType
type RulePortRange = sharedtypes.RulePortRange

type ResourceType = sharedtypes.ResourceType

type RouteFirewallRule = sharedtypes.RouteFirewallRule

type NetworkMapComponents = sharedtypes.NetworkMapComponents

var EmptyNetworkMapComponents = sharedtypes.EmptyNetworkMapComponents

type AccountSettingsInfo = sharedtypes.AccountSettingsInfo

type GroupCompact = sharedtypes.GroupCompact
type NetworkMapComponentsCompact = sharedtypes.NetworkMapComponentsCompact

type LookupMap = sharedtypes.LookupMap
type FirewallRuleContext = sharedtypes.FirewallRuleContext

type PeerConnResolveState = sharedtypes.PeerConnResolveState
type RuleAuthCallbacks = sharedtypes.RuleAuthCallbacks
type VNCSessionPubKey = sharedtypes.VNCSessionPubKey

// Function forwarders preserve types.X(...) call sites that previously
// resolved to package-local funcs. Plain forwarders (not var aliases) keep
// the symbol immutable and allow the inliner to flatten the call.

func ParseRuleString(rule string) (PolicyRuleProtocolType, RulePortRange, error) {
	return sharedtypes.ParseRuleString(rule)
}

func PolicyRuleImpliesLegacySSH(rule *PolicyRule) bool {
	return nmdata.PolicyRuleImpliesLegacySSH(twinRule(rule))
}

func NewPeerConnResolveState() *PeerConnResolveState {
	return sharedtypes.NewPeerConnResolveState()
}

// ApplyResolvedRuleToState forwards to the twin-typed helper while keeping the
// real rule on the way back out to generateResources, which the legacy Account
// calc still drives with real types.
func ApplyResolvedRuleToState(rule *PolicyRule, sourcePeers, destPeers []*nbpeer.Peer, peerInSources, peerInDestinations, targetPeerSSHEnabled bool, generateResources func(*PolicyRule, []*nbpeer.Peer, int), cb RuleAuthCallbacks, state *PeerConnResolveState) {
	emit := func(_ *nmdata.PolicyRule, peers []*nbpeer.Peer, direction int) {
		generateResources(rule, peers, direction)
	}
	sharedtypes.ApplyResolvedRuleToState(twinRule(rule), sourcePeers, destPeers, peerInSources, peerInDestinations, targetPeerSSHEnabled, emit, cb, state)
}

func MergeAuthorizedGroupUsers(ctx context.Context, authorizedGroups map[string][]string, groupIDToUserIDs map[string][]string, target map[string]map[string]struct{}) {
	sharedtypes.MergeAuthorizedGroupUsers(ctx, authorizedGroups, groupIDToUserIDs, target)
}

func EnsureWildcardUser(target map[string]map[string]struct{}, authorizedUser string) {
	sharedtypes.EnsureWildcardUser(target, authorizedUser)
}

func MergeWildcardUsers(dst map[string]map[string]struct{}, users map[string]struct{}) {
	sharedtypes.MergeWildcardUsers(dst, users)
}

// NormalizePolicyRuleProtocol is the real-typed sibling of the twin helper in
// shared types: it maps the NetBird virtual protocols to the wire protocol and
// scopes a portless netbird-vnc rule to the embedded VNC port.
func NormalizePolicyRuleProtocol(rule *PolicyRule) (*PolicyRule, PolicyRuleProtocolType) {
	protocol := sharedtypes.WirePolicyRuleProtocol(rule.Protocol)
	if rule.Protocol != PolicyRuleProtocolNetbirdVNC || len(rule.Ports) > 0 || len(rule.PortRanges) > 0 {
		return rule, protocol
	}
	scoped := *rule
	scoped.Ports = sharedtypes.VNCScopedPorts()
	return &scoped, protocol
}

// ExpandPortsAndRanges / AppendIPv6FirewallRule / GenerateRouteFirewallRules
// forward to the shared twin-typed helpers, converting the real types the
// legacy Account calc still uses to nmdata twins at this boundary.

func ExpandPortsAndRanges(base FirewallRule, rule *PolicyRule, peer *nbpeer.Peer) []*FirewallRule {
	return sharedtypes.ExpandPortsAndRanges(base, twinRule(rule), twinPeer(peer))
}

func AppendIPv6FirewallRule(rules []*FirewallRule, rulesExists map[string]struct{}, peer, targetPeer *nbpeer.Peer, rule *PolicyRule, rc FirewallRuleContext) []*FirewallRule {
	return sharedtypes.AppendIPv6FirewallRule(rules, rulesExists, twinPeer(peer), twinPeer(targetPeer), twinRule(rule), rc)
}

func CalculateNetworkMapFromComponents(ctx context.Context, components *NetworkMapComponents) *NetworkMap {
	return sharedtypes.CalculateNetworkMapFromComponents(ctx, components)
}

func GenerateRouteFirewallRules(ctx context.Context, route *nbroute.Route, rule *PolicyRule, groupPeers []*nbpeer.Peer, direction int, includeIPv6 bool) []*RouteFirewallRule {
	return sharedtypes.GenerateRouteFirewallRules(ctx, twinRoute(route), twinRule(rule), TwinPeers(groupPeers), direction, includeIPv6)
}

const (
	FirewallRuleDirectionIN  = sharedtypes.FirewallRuleDirectionIN
	FirewallRuleDirectionOUT = sharedtypes.FirewallRuleDirectionOUT
)

const (
	AllowedIPsFormat   = sharedtypes.AllowedIPsFormat
	AllowedIPsV6Format = sharedtypes.AllowedIPsV6Format
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
	PolicyRuleProtocolNetbirdVNC = sharedtypes.PolicyRuleProtocolNetbirdVNC
)
