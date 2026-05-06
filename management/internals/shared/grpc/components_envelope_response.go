package grpc

import (
	"context"

	integrationsConfig "github.com/netbirdio/management-integrations/integrations/config"

	nbconfig "github.com/netbirdio/netbird/management/internals/server/config"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/posture"
	"github.com/netbirdio/netbird/management/server/types"
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
	enableSSH := computeSSHEnabledForPeer(components, peer.ID)
	peerConfig := toPeerConfig(peer, network, dnsName, settings, httpConfig, deviceFlowConfig, enableSSH)

	includeIPv6 := peer.SupportsIPv6() && peer.IPv6.IsValid()
	useSourcePrefixes := peer.SupportsSourcePrefixes()

	envelope := EncodeNetworkMapEnvelope(ComponentsEnvelopeInput{
		Components:       components,
		PeerConfig:       peerConfig,
		DNSDomain:        dnsName,
		DNSForwarderPort: dnsFwdPort,
		ProxyPatch:       toProxyPatch(proxyPatch, dnsName, includeIPv6, useSourcePrefixes),
	})

	resp := &proto.SyncResponse{
		PeerConfig:         peerConfig,
		NetworkMapEnvelope: envelope,
		Checks:             toProtocolChecks(ctx, checks),
	}

	nbConfig := toNetbirdConfig(config, turnCredentials, relayCredentials, extraSettings)
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
		Peers:               appendRemotePeerConfig(nil, nm.Peers, dnsName, includeIPv6),
		OfflinePeers:        appendRemotePeerConfig(nil, nm.OfflinePeers, dnsName, includeIPv6),
		FirewallRules:       toProtocolFirewallRules(nm.FirewallRules, includeIPv6, useSourcePrefixes),
		Routes:              toProtocolRoutes(nm.Routes),
		RouteFirewallRules:  toProtocolRoutesFirewallRules(nm.RoutesFirewallRules),
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
// Cheaper than running Calculate() because we ignore peer-pair expansion —
// only the "any matched policy with NetbirdSSH protocol" check is needed.
// The full SSH AuthorizedUsers map is still produced by the client when it
// runs Calculate() over the envelope.
func computeSSHEnabledForPeer(c *types.NetworkMapComponents, peerID string) bool {
	if c == nil {
		return false
	}
	for _, policy := range c.Policies {
		if policy == nil || !policy.Enabled {
			continue
		}
		for _, rule := range policy.Rules {
			if rule == nil || !rule.Enabled {
				continue
			}
			if rule.Protocol != types.PolicyRuleProtocolNetbirdSSH {
				continue
			}
			if peerInDestinations(c, rule, peerID) {
				return true
			}
		}
	}
	return false
}

// peerInDestinations reports whether peerID is in any of rule.Destinations'
// groups (or matches DestinationResource if used).
func peerInDestinations(c *types.NetworkMapComponents, rule *types.PolicyRule, peerID string) bool {
	if rule.DestinationResource.ID != "" {
		return rule.DestinationResource.ID == peerID
	}
	for _, groupID := range rule.Destinations {
		if c.IsPeerInGroup(peerID, groupID) {
			return true
		}
	}
	return false
}
