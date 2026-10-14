package grpc

import (
	"context"

	integrationsConfig "github.com/netbirdio/management-integrations/integrations/config"

	"github.com/netbirdio/netbird/client/ssh/auth"
	nbconfig "github.com/netbirdio/netbird/management/internals/server/config"
	"github.com/netbirdio/netbird/management/server/types"
	sharedgrpc "github.com/netbirdio/netbird/shared/management/grpc"
	"github.com/netbirdio/netbird/shared/management/networkmap"
	nmdata "github.com/netbirdio/netbird/shared/management/networkmap/nmdata"
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
	peer *nmdata.Peer,
	turnCredentials *Token,
	relayCredentials *Token,
	components *types.NetworkMapComponents,
	proxyPatch *types.NetworkMap,
	dnsName string,
	checks []*nmdata.PostureChecks,
	settings *nmdata.AccountSettingsInfo,
	extraSettings *types.ExtraSettings,
	peerGroups []string,
	dnsFwdPort int64,
) *proto.SyncResponse {
	//
	// 'component' parameter is expected to never be nil
	// 'peer' parameter is expected to never be nil
	//
	// TODO (dmitri) consider using invariants?
	//
	enableSSH := components.PeerSSHEnabled(peer)
	peerConfig := toPeerConfig(peer, components.Network, dnsName, settings, httpConfig, deviceFlowConfig, enableSSH, components.ForceRoutingPeerDNSResolution)

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
		ProxyPatch:       toProxyPatch(proxyPatch, dnsName, includeIPv6, useSourcePrefixes, peer.ProxyMeta.Embedded),
	})

	resp := &proto.SyncResponse{
		PeerConfig:         peerConfig,
		NetworkMapEnvelope: envelope,
		Checks:             toProtocolChecks(ctx, checks),
		Version:            int32(sharedgrpc.ComponentNetworkMap),
	}

	nbConfig := toNetbirdConfig(config, turnCredentials, relayCredentials, extraSettings, settings)
	resp.NetbirdConfig = integrationsConfig.ExtendNetBirdConfig(peer.ID, peerGroups, nbConfig, extraSettings)

	// settings == nil → field stays nil → "no info in this snapshot", client
	// preserves the deadline it already had. settings non-nil → emit either a
	// valid deadline or the explicit-zero "disabled" sentinel via
	// encodeSessionExpiresAt.
	if settings != nil {
		resp.SessionExpiresAt = encodeSessionExpiresAt(
			peer.SessionExpiresAt(settings.PeerLoginExpirationEnabled, settings.PeerLoginExpiration),
		)
	}

	return resp
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
func toProxyPatch(nm *types.NetworkMap, dnsName string, includeIPv6, useSourcePrefixes, localIsProxy bool) *proto.ProxyPatch {
	if nm == nil {
		return nil
	}
	if len(nm.Peers) == 0 && len(nm.OfflinePeers) == 0 && len(nm.FirewallRules) == 0 &&
		len(nm.Routes) == 0 && len(nm.RoutesFirewallRules) == 0 && len(nm.ForwardingRules) == 0 {
		return nil
	}

	patch := &proto.ProxyPatch{
		Peers:              networkmap.AppendRemotePeerConfig(nil, nm.Peers, dnsName, includeIPv6, localIsProxy),
		OfflinePeers:       networkmap.AppendRemotePeerConfig(nil, nm.OfflinePeers, dnsName, includeIPv6, localIsProxy),
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
