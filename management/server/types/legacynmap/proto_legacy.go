package legacynmap

import (
	"context"
	"fmt"
	"net/netip"
	"net/url"
	"strings"

	"github.com/netbirdio/netbird/client/ssh/auth"
	nbconfig "github.com/netbirdio/netbird/management/internals/server/config"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/types"
	nbroute "github.com/netbirdio/netbird/route"
	"github.com/netbirdio/netbird/shared/management/networkmap"
	"github.com/netbirdio/netbird/shared/management/proto"
	"github.com/netbirdio/netbird/shared/netiputil"
)

func ToProtocolRoutes(routes []*nbroute.Route) []*proto.Route {
	protoRoutes := make([]*proto.Route, 0, len(routes))
	for _, r := range routes {
		protoRoutes = append(protoRoutes, ToProtocolRoute(r))
	}
	return protoRoutes
}

func ToProtocolRoute(route *nbroute.Route) *proto.Route {
	return &proto.Route{
		ID:            string(route.ID),
		NetID:         string(route.NetID),
		Network:       route.Network.String(),
		Domains:       route.Domains.ToPunycodeList(),
		NetworkType:   int64(route.NetworkType),
		Peer:          route.Peer,
		Metric:        int64(route.Metric),
		Masquerade:    route.Masquerade,
		KeepRoute:     route.KeepRoute,
		SkipAutoApply: route.SkipAutoApply,
	}
}

func AppendRemotePeerConfig(dst []*proto.RemotePeerConfig, peers []*ComponentPeer, dnsName string, includeIPv6 bool, localIsProxy bool) []*proto.RemotePeerConfig {
	for _, rPeer := range peers {
		allowedIPs := []string{rPeer.IP.String() + "/32"}
		if includeIPv6 && rPeer.IPv6.IsValid() {
			allowedIPs = append(allowedIPs, rPeer.IPv6.String()+"/128")
		}
		dst = append(dst, &proto.RemotePeerConfig{
			WgPubKey:     rPeer.Key,
			AllowedIps:   allowedIPs,
			SshConfig:    &proto.SSHConfig{SshPubKey: []byte(rPeer.SSHKey)},
			Fqdn:         rPeer.FQDN(dnsName),
			AgentVersion: rPeer.AgentVersion,
			LazyState:    lazyStateFor(localIsProxy, rPeer),
		})
	}
	return dst
}

// lazyStateFor returns the per-peer lazy override for a remote peer. Connections
// involving an ephemeral proxy peer on either endpoint default to lazy so shared
// proxy infrastructure is not kept permanently connected to every peer. All
// other peers follow the account-wide flag. A future admin-facing per-peer
// setting can return LazyStateEager here to force a peer always-active.
func lazyStateFor(localIsProxy bool, rPeer *ComponentPeer) proto.LazyState {
	if localIsProxy || rPeer.ProxyEmbedded {
		return proto.LazyState_LazyStateLazy
	}
	return proto.LazyState_LazyStateDefault
}

func buildJWTConfig(config *nbconfig.HttpServerConfig, deviceFlowConfig *nbconfig.DeviceAuthorizationFlow) *proto.JWTConfig {
	if config == nil || config.AuthAudience == "" {
		return nil
	}

	issuer := strings.TrimSpace(config.AuthIssuer)
	if issuer == "" && deviceFlowConfig != nil {
		if d := deriveIssuerFromTokenEndpoint(deviceFlowConfig.ProviderConfig.TokenEndpoint); d != "" {
			issuer = d
		}
	}
	if issuer == "" {
		return nil
	}

	keysLocation := strings.TrimSpace(config.AuthKeysLocation)
	if keysLocation == "" {
		keysLocation = strings.TrimSuffix(issuer, "/") + "/.well-known/jwks.json"
	}

	audience := config.AuthAudience
	if config.CLIAuthAudience != "" {
		audience = config.CLIAuthAudience
	}

	audiences := []string{config.AuthAudience}
	if config.CLIAuthAudience != "" && config.CLIAuthAudience != config.AuthAudience {
		audiences = append(audiences, config.CLIAuthAudience)
	}

	return &proto.JWTConfig{
		Issuer:       issuer,
		Audience:     audience, //nolint:staticcheck
		Audiences:    audiences,
		KeysLocation: keysLocation,
	}
}

func toPeerConfig(peer *nbpeer.Peer, network *Network, dnsName string, settings *types.Settings, httpConfig *nbconfig.HttpServerConfig, deviceFlowConfig *nbconfig.DeviceAuthorizationFlow, enableSSH bool, forceRoutingPeerDNS bool) *proto.PeerConfig {
	netmask, _ := network.Net.Mask.Size()
	fqdn := peer.FQDN(dnsName)

	sshConfig := &proto.SSHConfig{
		SshEnabled: peer.SSHEnabled || enableSSH,
	}

	if sshConfig.SshEnabled {
		sshConfig.JwtConfig = buildJWTConfig(httpConfig, deviceFlowConfig)
	}

	peerConfig := &proto.PeerConfig{
		Address:                         fmt.Sprintf("%s/%d", peer.IP.String(), netmask),
		SshConfig:                       sshConfig,
		Fqdn:                            fqdn,
		RoutingPeerDnsResolutionEnabled: settings.RoutingPeerDNSResolutionEnabled || peer.ProxyMeta.Embedded || forceRoutingPeerDNS,
		LazyConnectionEnabled:           settings.LazyConnectionEnabled,
		AutoUpdate: &proto.AutoUpdateSettings{
			Version:      settings.AutoUpdateVersion,
			AlwaysUpdate: settings.AutoUpdateAlways,
		},
	}

	if peer.SupportsIPv6() && peer.IPv6.IsValid() && network.NetV6.IP != nil {
		ones, _ := network.NetV6.Mask.Size()
		v6Prefix := netip.PrefixFrom(peer.IPv6.Unmap(), ones)
		if b, err := netiputil.EncodePrefix(v6Prefix); err == nil {
			peerConfig.AddressV6 = b
		}
	}

	return peerConfig
}

// ToProtoNetworkMap mirrors main's ToSyncResponse, restricted to the
// proto.NetworkMap it produces. SyncResponse-level fields (NetbirdConfig,
// Checks, the deprecated top-level RemotePeers) are omitted — they are not part
// of the equivalence surface. PeerConfig is included because proto.NetworkMap
// carries it, and it is where main's ForceRoutingPeerDNSResolution surfaces.
func ToProtoNetworkMap(
	ctx context.Context,
	peer *nbpeer.Peer,
	nm *NetworkMap,
	dnsName string,
	settings *types.Settings,
	httpConfig *nbconfig.HttpServerConfig,
	dnsCache networkmap.DNSConfigCache,
	dnsFwdPort int64,
) *proto.NetworkMap {
	includeIPv6 := peer.SupportsIPv6() && peer.IPv6.IsValid()
	useSourcePrefixes := peer.SupportsSourcePrefixes()
	localIsProxy := peer.ProxyMeta.Embedded

	peerConfig := toPeerConfig(peer, nm.Network, dnsName, settings, httpConfig, nil, nm.EnableSSH, nm.ForceRoutingPeerDNSResolution)

	pm := &proto.NetworkMap{
		Serial:     nm.Network.CurrentSerial(),
		Routes:     ToProtocolRoutes(nm.Routes),
		DNSConfig:  networkmap.ToProtocolDNSConfig(nm.DNSConfig, dnsCache, dnsFwdPort),
		PeerConfig: peerConfig,
	}

	remotePeers := make([]*proto.RemotePeerConfig, 0, len(nm.Peers)+len(nm.OfflinePeers))
	remotePeers = AppendRemotePeerConfig(remotePeers, nm.Peers, dnsName, includeIPv6, localIsProxy)
	pm.RemotePeers = remotePeers
	pm.RemotePeersIsEmpty = len(remotePeers) == 0

	pm.OfflinePeers = AppendRemotePeerConfig(nil, nm.OfflinePeers, dnsName, includeIPv6, localIsProxy)

	firewallRules := networkmap.ToProtocolFirewallRules(nm.FirewallRules, includeIPv6, useSourcePrefixes)
	pm.FirewallRules = firewallRules
	pm.FirewallRulesIsEmpty = len(firewallRules) == 0

	routesFirewallRules := networkmap.ToProtocolRoutesFirewallRules(nm.RoutesFirewallRules)
	pm.RoutesFirewallRules = routesFirewallRules
	pm.RoutesFirewallRulesIsEmpty = len(routesFirewallRules) == 0

	if nm.ForwardingRules != nil {
		forwardingRules := make([]*proto.ForwardingRule, 0, len(nm.ForwardingRules))
		for _, rule := range nm.ForwardingRules {
			forwardingRules = append(forwardingRules, rule.ToProto())
		}
		pm.ForwardingRules = forwardingRules
	}

	if nm.AuthorizedUsers != nil {
		hashedUsers, machineUsers := networkmap.BuildAuthorizedUsersProto(ctx, nm.AuthorizedUsers)
		userIDClaim := auth.DefaultUserIDClaim
		if httpConfig != nil && httpConfig.AuthUserIDClaim != "" {
			userIDClaim = httpConfig.AuthUserIDClaim
		}
		pm.SshAuth = &proto.SSHAuth{AuthorizedUsers: hashedUsers, MachineUsers: machineUsers, UserIDClaim: userIDClaim}
	}

	return pm
}

func deriveIssuerFromTokenEndpoint(tokenEndpoint string) string {
	if tokenEndpoint == "" {
		return ""
	}

	u, err := url.Parse(tokenEndpoint)
	if err != nil {
		return ""
	}

	return fmt.Sprintf("%s://%s/", u.Scheme, u.Host)
}
