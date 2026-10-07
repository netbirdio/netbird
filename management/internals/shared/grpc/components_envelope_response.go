package grpc

import (
	"context"

	integrationsConfig "github.com/netbirdio/management-integrations/integrations/config"

	"github.com/netbirdio/netbird/client/ssh/auth"
	nbconfig "github.com/netbirdio/netbird/management/internals/server/config"
	"github.com/netbirdio/netbird/management/server/types"
	sharedgrpc "github.com/netbirdio/netbird/shared/management/grpc"
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
	enableSSH := computeSSHEnabledForPeer(components, peer)
	peerConfig := toPeerConfig(peer, components.Network, dnsName, settings, httpConfig, deviceFlowConfig, enableSSH, components.ForceRoutingPeerDNSResolution)

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
func computeSSHEnabledForPeer(c *types.NetworkMapComponents, peer *nmdata.Peer) bool {
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
func ruleEnablesSSHForPeer(c *types.NetworkMapComponents, rule *nmdata.PolicyRule, peer *nmdata.Peer) bool {
	if rule == nil || !rule.Enabled {
		return false
	}
	if !peerInDestinations(c, rule, peer.ID) {
		return false
	}
	if rule.Protocol == string(types.PolicyRuleProtocolNetbirdSSH) {
		return true
	}
	return peer.SSHEnabled && nmdata.PolicyRuleImpliesLegacySSH(rule)
}

// peerInDestinations reports whether peerID is in any of rule.Destinations'
// groups (or matches DestinationResource if it's a peer-typed resource —
// for non-peer types Calculate falls through to group lookup, so we mirror
// that exactly to avoid silent divergence).
func peerInDestinations(c *types.NetworkMapComponents, rule *nmdata.PolicyRule, peerID string) bool {
	if rule.DestinationResource.Type == string(types.ResourceTypePeer) && rule.DestinationResource.ID != "" {
		return rule.DestinationResource.ID == peerID
	}
	for _, groupID := range rule.Destinations {
		if c.IsPeerInGroup(peerID, groupID) {
			return true
		}
	}
	return false
}
