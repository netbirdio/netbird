package networkmap

import (
	"context"
	"encoding/base64"
	"fmt"

	"github.com/netbirdio/netbird/shared/management/types"
	"github.com/netbirdio/netbird/shared/management/proto"
)

// EnvelopeResult is what the client engine consumes after receiving a
// component-format NetworkMap. Both fields are populated:
//
//   - NetworkMap is the *proto.NetworkMap shape the engine reads today via
//     update.GetNetworkMap() — built from the envelope's components by
//     running Calculate() locally + converting back through the shared
//     proto helpers + merging the optional ProxyPatch.
//   - Components is the *types.NetworkMapComponents the engine retains so
//     future incremental delta updates have a base to apply changes
//     against. The client keeps it under its sync lock.
type EnvelopeResult struct {
	NetworkMap *proto.NetworkMap
	Components *types.NetworkMapComponents
}

// EnvelopeToNetworkMap is the full client-side pipeline: decode the
// component envelope back to a typed NetworkMapComponents, run Calculate()
// locally to produce the typed NetworkMap, convert it to the wire form the
// engine consumes, and fold in any ProxyPatch the server attached.
//
// localPeerKey is the receiving peer's WG pub key (used to derive
// includeIPv6 / useSourcePrefixes from the receiving peer's own record in
// the components struct, mirroring legacy ToSyncResponse behaviour).
//
// dnsName is the account's DNS domain ("netbird.cloud" etc.); used when
// rebuilding the per-peer FQDNs that proto.RemotePeerConfig carries.
func EnvelopeToNetworkMap(ctx context.Context, env *proto.NetworkMapEnvelope, localPeerKey, dnsName string) (*EnvelopeResult, error) {
	components, err := DecodeEnvelope(env)
	if err != nil {
		return nil, fmt.Errorf("decode envelope: %w", err)
	}

	// Find the receiving peer in the decoded components by WG key.
	// c.Peers is keyed by canonical base64 of the raw 32-byte pub key
	// (decoder re-encodes the bytes off the wire). The caller may pass a
	// non-canonical encoding (some persisted production keys carry
	// non-zero trailing padding bits that survived a legacy import), so
	// round-trip through raw bytes once to canonicalize before lookup.
	canonicalKey := canonicalizeWgKey(localPeerKey)
	localPeer := components.Peers[canonicalKey]
	if localPeer == nil {
		return nil, fmt.Errorf("receiving peer (wg_key prefix %q) not found among %d decoded peers — components have no PeerID, Calculate would return empty", trimKey(localPeerKey), len(components.Peers))
	}
	components.PeerID = canonicalKey

	includeIPv6 := localPeer.SupportsIPv6() && localPeer.IPv6.IsValid()
	useSourcePrefixes := localPeer.SupportsSourcePrefixes()

	typedNM := components.Calculate(ctx)

	full := env.GetFull()
	dnsFwdPort := int64(0)
	if full != nil {
		dnsFwdPort = full.DnsForwarderPort
	}

	protoNM := &proto.NetworkMap{
		Serial: typedNM.Network.CurrentSerial(),
	}
	if full != nil {
		protoNM.PeerConfig = full.PeerConfig
	}
	protoNM.Routes = ToProtocolRoutes(typedNM.Routes)
	protoNM.DNSConfig = ToProtocolDNSConfig(typedNM.DNSConfig, nil, dnsFwdPort)

	remotePeers := AppendRemotePeerConfig(nil, typedNM.Peers, dnsName, includeIPv6)
	protoNM.RemotePeers = remotePeers
	protoNM.RemotePeersIsEmpty = len(remotePeers) == 0

	protoNM.OfflinePeers = AppendRemotePeerConfig(nil, typedNM.OfflinePeers, dnsName, includeIPv6)

	firewallRules := ToProtocolFirewallRules(typedNM.FirewallRules, includeIPv6, useSourcePrefixes)
	protoNM.FirewallRules = firewallRules
	protoNM.FirewallRulesIsEmpty = len(firewallRules) == 0

	routesFirewallRules := ToProtocolRoutesFirewallRules(typedNM.RoutesFirewallRules)
	protoNM.RoutesFirewallRules = routesFirewallRules
	protoNM.RoutesFirewallRulesIsEmpty = len(routesFirewallRules) == 0

	if typedNM.AuthorizedUsers != nil {
		hashedUsers, machineUsers := BuildAuthorizedUsersProto(ctx, typedNM.AuthorizedUsers)
		userIDClaim := ""
		if full != nil {
			userIDClaim = full.UserIdClaim
		}
		protoNM.SshAuth = &proto.SSHAuth{
			AuthorizedUsers: hashedUsers,
			MachineUsers:    machineUsers,
			UserIDClaim:     userIDClaim,
		}
	}

	if typedNM.ForwardingRules != nil {
		forwardingRules := make([]*proto.ForwardingRule, 0, len(typedNM.ForwardingRules))
		for _, rule := range typedNM.ForwardingRules {
			forwardingRules = append(forwardingRules, rule.ToProto())
		}
		protoNM.ForwardingRules = forwardingRules
	}

	// Merge the proxy patch the server attached. Mirrors the legacy
	// NetworkMap.Merge step that the server runs after Calculate().
	if full != nil && full.ProxyPatch != nil {
		mergeProxyPatch(protoNM, full.ProxyPatch)
	}

	return &EnvelopeResult{
		NetworkMap: protoNM,
		Components: components,
	}, nil
}

// mergeProxyPatch folds a ProxyPatch's pre-expanded fragments into the
// proto.NetworkMap that Calculate() produced. Mirrors types.NetworkMap.Merge
// — same six collections, deduplicated where the legacy merge dedupes.
func mergeProxyPatch(nm *proto.NetworkMap, patch *proto.ProxyPatch) {
	nm.RemotePeers = appendUniquePeers(nm.RemotePeers, patch.Peers)
	nm.OfflinePeers = appendUniquePeers(nm.OfflinePeers, patch.OfflinePeers)
	nm.FirewallRules = append(nm.FirewallRules, patch.FirewallRules...)
	nm.Routes = append(nm.Routes, patch.Routes...)
	nm.RoutesFirewallRules = append(nm.RoutesFirewallRules, patch.RouteFirewallRules...)
	nm.ForwardingRules = append(nm.ForwardingRules, patch.ForwardingRules...)
	if len(nm.RemotePeers) > 0 {
		nm.RemotePeersIsEmpty = false
	}
	if len(nm.FirewallRules) > 0 {
		nm.FirewallRulesIsEmpty = false
	}
	if len(nm.RoutesFirewallRules) > 0 {
		nm.RoutesFirewallRulesIsEmpty = false
	}
}

// appendUniquePeers dedupes by WgPubKey — mirrors legacy
// mergeUniquePeersByID's intent (legacy keyed off Peer.ID; in proto form the
// closest stable identifier is WgPubKey).
func appendUniquePeers(dst, extra []*proto.RemotePeerConfig) []*proto.RemotePeerConfig {
	if len(extra) == 0 {
		return dst
	}
	seen := make(map[string]struct{}, len(dst))
	for _, p := range dst {
		if p == nil {
			continue
		}
		seen[p.WgPubKey] = struct{}{}
	}
	for _, p := range extra {
		if p == nil {
			continue
		}
		if _, ok := seen[p.WgPubKey]; ok {
			continue
		}
		seen[p.WgPubKey] = struct{}{}
		dst = append(dst, p)
	}
	return dst
}

func trimKey(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}

// canonicalizeWgKey normalises a base64-encoded WireGuard public key so it
// matches the canonical encoding emitted by the envelope decoder. Returns
// the input unchanged when it does not decode to 32 raw bytes (caller will
// hit a miss in the peer map and surface the error).
func canonicalizeWgKey(s string) string {
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(raw) != 32 {
		return s
	}
	return base64.StdEncoding.EncodeToString(raw)
}

