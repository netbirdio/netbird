package grpc

import (
	"context"

	integrationsConfig "github.com/netbirdio/management-integrations/integrations/config"

	"github.com/netbirdio/netbird/client/ssh/auth"
	nbconfig "github.com/netbirdio/netbird/management/internals/server/config"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/posture"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/networkmap"
	"github.com/netbirdio/netbird/shared/management/proto"
)

// ToComponentSyncResponse builds a SyncResponse carrying the compact
// NetworkMapEnvelope for capability-aware peers. The legacy proto.NetworkMap
// field is intentionally left empty — capable peers ignore it and the
// envelope alone is the authoritative wire shape.
//
// PeerConfig is computed once server-side using the receiving peer's own
// account-level network metadata. EnableSSH inside PeerConfig is left at
// peer.SSHEnabled (the peer's local setting); account-policy-driven SSH is
// computed by the client from the envelope's GroupIDToUserIDs / AllowedUserIDs
// inside Calculate(), so the SshConfig.SshEnabled bit may flip true on the
// client even though the server-side PeerConfig reports false.
func ToComponentSyncResponse(
	ctx context.Context,
	config *nbconfig.Config,
	httpConfig *nbconfig.HttpServerConfig,
	deviceFlowConfig *nbconfig.DeviceAuthorizationFlow,
	peer *nbpeer.Peer,
	turnCredentials *Token,
	relayCredentials *Token,
	components *types.NetworkMapComponents,
	proxyPatch *types.NetworkMap,
	dnsName string,
	checks []*posture.Checks,
	settings *types.Settings,
	extraSettings *types.ExtraSettings,
	peerGroups []string,
	dnsFwdPort int64,
) *proto.SyncResponse {
	network := networkOrZero(components)
	enableSSH := computeSSHEnabledForPeer(components, peer)
	peerConfig := toPeerConfig(peer, network, dnsName, settings, httpConfig, deviceFlowConfig, enableSSH)

	includeIPv6 := peer.SupportsIPv6() && peer.IPv6.IsValid()
	useSourcePrefixes := peer.SupportsSourcePrefixes()

	userIDClaim := auth.DefaultUserIDClaim
	if httpConfig != nil && httpConfig.AuthUserIDClaim != "" {
		userIDClaim = httpConfig.AuthUserIDClaim
	}

	envelope := EncodeNetworkMapEnvelope(ComponentsEnvelopeInput{
		Components:       components,
		PeerConfig:       peerConfig,
		DNSDomain:        dnsName,
		DNSForwarderPort: dnsFwdPort,
		UserIDClaim:      userIDClaim,
		ProxyPatch:       toProxyPatch(proxyPatch, dnsName, includeIPv6, useSourcePrefixes),
	})

	resp := &proto.SyncResponse{
		PeerConfig:         peerConfig,
		NetworkMapEnvelope: envelope,
		Checks:             toProtocolChecks(ctx, checks),
	}

	nbConfig := toNetbirdConfig(config, turnCredentials, relayCredentials, extraSettings, settings)
	resp.NetbirdConfig = integrationsConfig.ExtendNetBirdConfig(peer.ID, peerGroups, nbConfig, extraSettings)

	return resp
}

// networkOrZero returns components.Network or a zero Network — toPeerConfig
// dereferences network.Net which would panic on nil.
func networkOrZero(c *types.NetworkMapComponents) *types.Network {
	if c == nil || c.Network == nil {
		return &types.Network{}
	}
	return c.Network
}

// toProxyPatch converts a proxy-injected *types.NetworkMap into the wire
// patch the components envelope ships alongside. Returns nil when there are
// no fragments to merge — proto3 omits a nil message field, so the receiver
// sees no patch and skips the merge step entirely.
//
// We reuse the legacy proto-conversion helpers (toProtocolRoutes,
// toProtocolFirewallRules, toProtocolRoutesFirewallRules,
// appendRemotePeerConfig, ForwardingRule.ToProto) because the proxy
// delivers fragments pre-expanded — there's no raw component shape to
// derive them from. Components purity isn't violated: proxy data isn't
// policy-graph-derived, it's externally injected post-Calculate, so the
// client merges it on top of its locally-computed NetworkMap.
func toProxyPatch(nm *types.NetworkMap, dnsName string, includeIPv6, useSourcePrefixes bool) *proto.ProxyPatch {
	if nm == nil {
		return nil
	}
	if len(nm.Peers) == 0 && len(nm.OfflinePeers) == 0 && len(nm.FirewallRules) == 0 &&
		len(nm.Routes) == 0 && len(nm.RoutesFirewallRules) == 0 && len(nm.ForwardingRules) == 0 {
		return nil
	}

	patch := &proto.ProxyPatch{
		Peers:              networkmap.AppendRemotePeerConfig(nil, nm.Peers, dnsName, includeIPv6),
		OfflinePeers:       networkmap.AppendRemotePeerConfig(nil, nm.OfflinePeers, dnsName, includeIPv6),
		FirewallRules:      networkmap.ToProtocolFirewallRules(nm.FirewallRules, includeIPv6, useSourcePrefixes),
		Routes:             networkmap.ToProtocolRoutes(nm.Routes),
		RouteFirewallRules: networkmap.ToProtocolRoutesFirewallRules(nm.RoutesFirewallRules),
	}
	if len(nm.ForwardingRules) > 0 {
		patch.ForwardingRules = make([]*proto.ForwardingRule, 0, len(nm.ForwardingRules))
		for _, r := range nm.ForwardingRules {
			patch.ForwardingRules = append(patch.ForwardingRules, r.ToProto())
		}
	}
	return patch
}

// computeSSHEnabledForPeer mirrors the SSH-server-activation bit that
// Calculate() folds into NetworkMap.EnableSSH. Components-format peers
// receive a freshly-computed PeerConfig.SshConfig.SshEnabled at sync time;
// without this helper the field would be incorrectly false for any peer
// that's the destination of an SSH-enabling policy without having
// peer.SSHEnabled set locally.
//
// Mirrors the two activation paths Calculate() uses:
//  1. Explicit: rule.Protocol == NetbirdSSH and peer is in the rule's
//     destinations.
//  2. Legacy implicit: rule covers TCP/22 or TCP/22022 (or ALL), peer is in
//     destinations, AND the peer has SSHEnabled set locally — this is the
//     "allow-all/TCP-22 implies SSH activation for SSH-capable peers" path.
//
// The full SSH AuthorizedUsers map is still produced by the client when it
// runs Calculate() over the envelope.
func computeSSHEnabledForPeer(c *types.NetworkMapComponents, peer *nbpeer.Peer) bool {
	if c == nil || peer == nil {
		return false
	}
	// Mirror Calculate's `getAllPeersFromGroups` invariant: target peer must
	// exist in c.Peers, otherwise no rule applies to it.
	if _, ok := c.Peers[peer.ID]; !ok {
		return false
	}
	for _, policy := range c.Policies {
		if policy == nil || !policy.Enabled {
			continue
		}
		for _, rule := range policy.Rules {
			if ruleEnablesSSHForPeer(c, rule, peer) {
				return true
			}
		}
	}
	return false
}

// ruleEnablesSSHForPeer returns true when rule is active, targets peer, and
// either explicitly authorises SSH or covers the legacy TCP/22 path while the
// peer itself has SSH enabled locally.
func ruleEnablesSSHForPeer(c *types.NetworkMapComponents, rule *types.PolicyRule, peer *nbpeer.Peer) bool {
	if rule == nil || !rule.Enabled {
		return false
	}
	if !peerInDestinations(c, rule, peer.ID) {
		return false
	}
	if rule.Protocol == types.PolicyRuleProtocolNetbirdSSH {
		return true
	}
	return peer.SSHEnabled && types.PolicyRuleImpliesLegacySSH(rule)
}

// peerInDestinations reports whether peerID is in any of rule.Destinations'
// groups (or matches DestinationResource if it's a peer-typed resource —
// for non-peer types Calculate falls through to group lookup, so we mirror
// that exactly to avoid silent divergence).
func peerInDestinations(c *types.NetworkMapComponents, rule *types.PolicyRule, peerID string) bool {
	if rule.DestinationResource.Type == types.ResourceTypePeer && rule.DestinationResource.ID != "" {
		return rule.DestinationResource.ID == peerID
	}
	for _, groupID := range rule.Destinations {
		if c.IsPeerInGroup(peerID, groupID) {
			return true
		}
	}
	return false
}
