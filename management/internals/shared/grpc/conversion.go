package grpc

import (
	"context"
	"fmt"
	"net/netip"
	"net/url"
	"strings"

	integrationsConfig "github.com/netbirdio/management-integrations/integrations/config"

	"github.com/netbirdio/netbird/client/ssh/auth"

	"github.com/netbirdio/netbird/management/internals/controllers/network_map/controller/cache"
	nbconfig "github.com/netbirdio/netbird/management/internals/server/config"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/posture"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/networkmap"
	"github.com/netbirdio/netbird/shared/management/proto"
	"github.com/netbirdio/netbird/shared/netiputil"
)

func toNetbirdConfig(config *nbconfig.Config, turnCredentials *Token, relayToken *Token, extraSettings *types.ExtraSettings) *proto.NetbirdConfig {
	if config == nil {
		return nil
	}

	var stuns []*proto.HostConfig
	for _, stun := range config.Stuns {
		stuns = append(stuns, &proto.HostConfig{
			Uri:      stun.URI,
			Protocol: ToResponseProto(stun.Proto),
		})
	}

	var turns []*proto.ProtectedHostConfig
	if config.TURNConfig != nil {
		for _, turn := range config.TURNConfig.Turns {
			var username string
			var password string
			if turnCredentials != nil {
				username = turnCredentials.Payload
				password = turnCredentials.Signature
			} else {
				username = turn.Username
				password = turn.Password
			}
			turns = append(turns, &proto.ProtectedHostConfig{
				HostConfig: &proto.HostConfig{
					Uri:      turn.URI,
					Protocol: ToResponseProto(turn.Proto),
				},
				User:     username,
				Password: password,
			})
		}
	}

	var relayCfg *proto.RelayConfig
	if config.Relay != nil && len(config.Relay.Addresses) > 0 {
		relayCfg = &proto.RelayConfig{
			Urls: config.Relay.Addresses,
		}

		if relayToken != nil {
			relayCfg.TokenPayload = relayToken.Payload
			relayCfg.TokenSignature = relayToken.Signature
		}
	}

	var signalCfg *proto.HostConfig
	if config.Signal != nil {
		signalCfg = &proto.HostConfig{
			Uri:      config.Signal.URI,
			Protocol: ToResponseProto(config.Signal.Proto),
		}
	}

	nbConfig := &proto.NetbirdConfig{
		Stuns:  stuns,
		Turns:  turns,
		Signal: signalCfg,
		Relay:  relayCfg,
	}

	return nbConfig
}

func toPeerConfig(peer *nbpeer.Peer, network *types.Network, dnsName string, settings *types.Settings, httpConfig *nbconfig.HttpServerConfig, deviceFlowConfig *nbconfig.DeviceAuthorizationFlow, enableSSH bool) *proto.PeerConfig {
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
		RoutingPeerDnsResolutionEnabled: settings.RoutingPeerDNSResolutionEnabled,
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

func ToSyncResponse(ctx context.Context, config *nbconfig.Config, httpConfig *nbconfig.HttpServerConfig, deviceFlowConfig *nbconfig.DeviceAuthorizationFlow, peer *nbpeer.Peer, turnCredentials *Token, relayCredentials *Token, networkMap *types.NetworkMap, dnsName string, checks []*posture.Checks, dnsCache *cache.DNSConfigCache, settings *types.Settings, extraSettings *types.ExtraSettings, peerGroups []string, dnsFwdPort int64) *proto.SyncResponse {
	// IPv6 data in AllowedIPs and SourcePrefixes wildcard expansion depends on
	// whether the target peer supports IPv6. Routes and firewall rules are already
	// filtered at the source (network map builder).
	includeIPv6 := peer.SupportsIPv6() && peer.IPv6.IsValid()
	useSourcePrefixes := peer.SupportsSourcePrefixes()

	response := &proto.SyncResponse{
		PeerConfig: toPeerConfig(peer, networkMap.Network, dnsName, settings, httpConfig, deviceFlowConfig, networkMap.EnableSSH),
		NetworkMap: &proto.NetworkMap{
			Serial:     networkMap.Network.CurrentSerial(),
			Routes:     networkmap.ToProtocolRoutes(networkMap.Routes),
			DNSConfig:  networkmap.ToProtocolDNSConfig(networkMap.DNSConfig, dnsCache, dnsFwdPort),
			PeerConfig: toPeerConfig(peer, networkMap.Network, dnsName, settings, httpConfig, deviceFlowConfig, networkMap.EnableSSH),
		},
		Checks: toProtocolChecks(ctx, checks),
	}

	nbConfig := toNetbirdConfig(config, turnCredentials, relayCredentials, extraSettings)
	extendedConfig := integrationsConfig.ExtendNetBirdConfig(peer.ID, peerGroups, nbConfig, extraSettings)
	response.NetbirdConfig = extendedConfig

	response.NetworkMap.PeerConfig = response.PeerConfig

	remotePeers := make([]*proto.RemotePeerConfig, 0, len(networkMap.Peers)+len(networkMap.OfflinePeers))
	remotePeers = networkmap.AppendRemotePeerConfig(remotePeers, networkMap.Peers, dnsName, includeIPv6)
	response.RemotePeers = remotePeers
	response.NetworkMap.RemotePeers = remotePeers
	response.RemotePeersIsEmpty = len(remotePeers) == 0
	response.NetworkMap.RemotePeersIsEmpty = response.RemotePeersIsEmpty

	response.NetworkMap.OfflinePeers = networkmap.AppendRemotePeerConfig(nil, networkMap.OfflinePeers, dnsName, includeIPv6)

	firewallRules := networkmap.ToProtocolFirewallRules(networkMap.FirewallRules, includeIPv6, useSourcePrefixes)
	response.NetworkMap.FirewallRules = firewallRules
	response.NetworkMap.FirewallRulesIsEmpty = len(firewallRules) == 0

	routesFirewallRules := networkmap.ToProtocolRoutesFirewallRules(networkMap.RoutesFirewallRules)
	response.NetworkMap.RoutesFirewallRules = routesFirewallRules
	response.NetworkMap.RoutesFirewallRulesIsEmpty = len(routesFirewallRules) == 0

	if networkMap.ForwardingRules != nil {
		forwardingRules := make([]*proto.ForwardingRule, 0, len(networkMap.ForwardingRules))
		for _, rule := range networkMap.ForwardingRules {
			forwardingRules = append(forwardingRules, rule.ToProto())
		}
		response.NetworkMap.ForwardingRules = forwardingRules
	}

	if networkMap.AuthorizedUsers != nil {
		hashedUsers, machineUsers := networkmap.BuildAuthorizedUsersProto(ctx, networkMap.AuthorizedUsers)
		userIDClaim := auth.DefaultUserIDClaim
		if httpConfig != nil && httpConfig.AuthUserIDClaim != "" {
			userIDClaim = httpConfig.AuthUserIDClaim
		}
		response.NetworkMap.SshAuth = &proto.SSHAuth{AuthorizedUsers: hashedUsers, MachineUsers: machineUsers, UserIDClaim: userIDClaim}
	}

	return response
}

func ToResponseProto(configProto nbconfig.Protocol) proto.HostConfig_Protocol {
	switch configProto {
	case nbconfig.UDP:
		return proto.HostConfig_UDP
	case nbconfig.DTLS:
		return proto.HostConfig_DTLS
	case nbconfig.HTTP:
		return proto.HostConfig_HTTP
	case nbconfig.HTTPS:
		return proto.HostConfig_HTTPS
	case nbconfig.TCP:
		return proto.HostConfig_TCP
	default:
		panic(fmt.Errorf("unexpected config protocol type %v", configProto))
	}
}

// buildJWTConfig constructs JWT configuration for SSH servers from management server config
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
		Audience:     audience,
		Audiences:    audiences,
		KeysLocation: keysLocation,
	}
}

// deriveIssuerFromTokenEndpoint extracts the issuer URL from a token endpoint
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
