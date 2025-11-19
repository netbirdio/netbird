package grpc

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	integrationsConfig "github.com/netbirdio/management-integrations/integrations/config"
	nbdns "github.com/netbirdio/netbird/dns"
	"github.com/netbirdio/netbird/management/internals/controllers/network_map/controller/cache"
	nbconfig "github.com/netbirdio/netbird/management/internals/server/config"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/posture"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/route"
	"github.com/netbirdio/netbird/shared/management/proto"
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

func toPeerConfig(peer *nbpeer.Peer, network *types.Network, dnsName string, settings *types.Settings, httpConfig *nbconfig.HttpServerConfig, deviceFlowConfig *nbconfig.DeviceAuthorizationFlow) *proto.PeerConfig {
	netmask, _ := network.Net.Mask.Size()
	fqdn := peer.FQDN(dnsName)

	sshConfig := &proto.SSHConfig{
		SshEnabled: peer.SSHEnabled,
	}

	if peer.SSHEnabled {
		sshConfig.JwtConfig = buildJWTConfig(httpConfig, deviceFlowConfig)
	}

	return &proto.PeerConfig{
		Address:                         fmt.Sprintf("%s/%d", peer.IP.String(), netmask),
		SshConfig:                       sshConfig,
		Fqdn:                            fqdn,
		RoutingPeerDnsResolutionEnabled: settings.RoutingPeerDNSResolutionEnabled,
		LazyConnectionEnabled:           settings.LazyConnectionEnabled,
	}
}

func ToSyncResponse(ctx context.Context, config *nbconfig.Config, httpConfig *nbconfig.HttpServerConfig, deviceFlowConfig *nbconfig.DeviceAuthorizationFlow, peer *nbpeer.Peer, turnCredentials *Token, relayCredentials *Token, networkMap *types.NetworkMap, dnsName string, checks []*posture.Checks, dnsCache *cache.DNSConfigCache, settings *types.Settings, extraSettings *types.ExtraSettings, peerGroups []string, dnsFwdPort int64) *proto.SyncResponse {
	response := &proto.SyncResponse{
		PeerConfig: toPeerConfig(peer, networkMap.Network, dnsName, settings, httpConfig, deviceFlowConfig),
		NetworkMap: &proto.NetworkMap{
			Serial:    networkMap.Network.CurrentSerial(),
			Routes:    toProtocolRoutes(networkMap.Routes),
			DNSConfig: toProtocolDNSConfig(networkMap.DNSConfig, dnsCache, dnsFwdPort),
		},
		Checks: toProtocolChecks(ctx, checks),
	}

	nbConfig := toNetbirdConfig(config, turnCredentials, relayCredentials, extraSettings)
	extendedConfig := integrationsConfig.ExtendNetBirdConfig(peer.ID, peerGroups, nbConfig, extraSettings)
	response.NetbirdConfig = extendedConfig

	response.NetworkMap.PeerConfig = response.PeerConfig

	remotePeers := make([]*proto.RemotePeerConfig, 0, len(networkMap.Peers)+len(networkMap.OfflinePeers))
	remotePeers = appendRemotePeerConfig(remotePeers, networkMap.Peers, dnsName)
	response.RemotePeers = remotePeers
	response.NetworkMap.RemotePeers = remotePeers
	response.RemotePeersIsEmpty = len(remotePeers) == 0
	response.NetworkMap.RemotePeersIsEmpty = response.RemotePeersIsEmpty

	response.NetworkMap.OfflinePeers = appendRemotePeerConfig(nil, networkMap.OfflinePeers, dnsName)

	firewallRules := toProtocolFirewallRules(networkMap.FirewallRules)
	response.NetworkMap.FirewallRules = firewallRules
	response.NetworkMap.FirewallRulesIsEmpty = len(firewallRules) == 0

	routesFirewallRules := toProtocolRoutesFirewallRules(networkMap.RoutesFirewallRules)
	response.NetworkMap.RoutesFirewallRules = routesFirewallRules
	response.NetworkMap.RoutesFirewallRulesIsEmpty = len(routesFirewallRules) == 0

	if networkMap.ForwardingRules != nil {
		forwardingRules := make([]*proto.ForwardingRule, 0, len(networkMap.ForwardingRules))
		for _, rule := range networkMap.ForwardingRules {
			forwardingRules = append(forwardingRules, rule.ToProto())
		}
		response.NetworkMap.ForwardingRules = forwardingRules
	}

	return response
}

func appendRemotePeerConfig(dst []*proto.RemotePeerConfig, peers []*nbpeer.Peer, dnsName string) []*proto.RemotePeerConfig {
	for _, rPeer := range peers {
		dst = append(dst, &proto.RemotePeerConfig{
			WgPubKey:     rPeer.Key,
			AllowedIps:   []string{rPeer.IP.String() + "/32"},
			SshConfig:    &proto.SSHConfig{SshPubKey: []byte(rPeer.SSHKey)},
			Fqdn:         rPeer.FQDN(dnsName),
			AgentVersion: rPeer.Meta.WtVersion,
		})
	}
	return dst
}

// toProtocolDNSConfig converts nbdns.Config to proto.DNSConfig using the cache
func toProtocolDNSConfig(update nbdns.Config, cache *cache.DNSConfigCache, forwardPort int64) *proto.DNSConfig {
	protoUpdate := &proto.DNSConfig{
		ServiceEnable:    update.ServiceEnable,
		CustomZones:      make([]*proto.CustomZone, 0, len(update.CustomZones)),
		NameServerGroups: make([]*proto.NameServerGroup, 0, len(update.NameServerGroups)),
		ForwarderPort:    forwardPort,
	}

	for _, zone := range update.CustomZones {
		protoZone := convertToProtoCustomZone(zone)
		protoUpdate.CustomZones = append(protoUpdate.CustomZones, protoZone)
	}

	for _, nsGroup := range update.NameServerGroups {
		cacheKey := nsGroup.ID
		if cachedGroup, exists := cache.GetNameServerGroup(cacheKey); exists {
			protoUpdate.NameServerGroups = append(protoUpdate.NameServerGroups, cachedGroup)
		} else {
			protoGroup := convertToProtoNameServerGroup(nsGroup)
			cache.SetNameServerGroup(cacheKey, protoGroup)
			protoUpdate.NameServerGroups = append(protoUpdate.NameServerGroups, protoGroup)
		}
	}

	return protoUpdate
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

func toProtocolRoutes(routes []*route.Route) []*proto.Route {
	protoRoutes := make([]*proto.Route, 0, len(routes))
	for _, r := range routes {
		protoRoutes = append(protoRoutes, toProtocolRoute(r))
	}
	return protoRoutes
}

func toProtocolRoute(route *route.Route) *proto.Route {
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

// toProtocolFirewallRules converts the firewall rules to the protocol firewall rules.
func toProtocolFirewallRules(rules []*types.FirewallRule) []*proto.FirewallRule {
	result := make([]*proto.FirewallRule, len(rules))
	for i := range rules {
		rule := rules[i]

		fwRule := &proto.FirewallRule{
			PolicyID:  []byte(rule.PolicyID),
			PeerIP:    rule.PeerIP,
			Direction: getProtoDirection(rule.Direction),
			Action:    getProtoAction(rule.Action),
			Protocol:  getProtoProtocol(rule.Protocol),
			Port:      rule.Port,
		}

		if shouldUsePortRange(fwRule) {
			fwRule.PortInfo = rule.PortRange.ToProto()
		}

		result[i] = fwRule
	}
	return result
}

// getProtoDirection converts the direction to proto.RuleDirection.
func getProtoDirection(direction int) proto.RuleDirection {
	if direction == types.FirewallRuleDirectionOUT {
		return proto.RuleDirection_OUT
	}
	return proto.RuleDirection_IN
}

func toProtocolRoutesFirewallRules(rules []*types.RouteFirewallRule) []*proto.RouteFirewallRule {
	result := make([]*proto.RouteFirewallRule, len(rules))
	for i := range rules {
		rule := rules[i]
		result[i] = &proto.RouteFirewallRule{
			SourceRanges: rule.SourceRanges,
			Action:       getProtoAction(rule.Action),
			Destination:  rule.Destination,
			Protocol:     getProtoProtocol(rule.Protocol),
			PortInfo:     getProtoPortInfo(rule),
			IsDynamic:    rule.IsDynamic,
			Domains:      rule.Domains.ToPunycodeList(),
			PolicyID:     []byte(rule.PolicyID),
			RouteID:      string(rule.RouteID),
		}
	}

	return result
}

// getProtoAction converts the action to proto.RuleAction.
func getProtoAction(action string) proto.RuleAction {
	if action == string(types.PolicyTrafficActionDrop) {
		return proto.RuleAction_DROP
	}
	return proto.RuleAction_ACCEPT
}

// getProtoProtocol converts the protocol to proto.RuleProtocol.
func getProtoProtocol(protocol string) proto.RuleProtocol {
	switch types.PolicyRuleProtocolType(protocol) {
	case types.PolicyRuleProtocolALL:
		return proto.RuleProtocol_ALL
	case types.PolicyRuleProtocolTCP:
		return proto.RuleProtocol_TCP
	case types.PolicyRuleProtocolUDP:
		return proto.RuleProtocol_UDP
	case types.PolicyRuleProtocolICMP:
		return proto.RuleProtocol_ICMP
	default:
		return proto.RuleProtocol_UNKNOWN
	}
}

// getProtoPortInfo converts the port info to proto.PortInfo.
func getProtoPortInfo(rule *types.RouteFirewallRule) *proto.PortInfo {
	var portInfo proto.PortInfo
	if rule.Port != 0 {
		portInfo.PortSelection = &proto.PortInfo_Port{Port: uint32(rule.Port)}
	} else if portRange := rule.PortRange; portRange.Start != 0 && portRange.End != 0 {
		portInfo.PortSelection = &proto.PortInfo_Range_{
			Range: &proto.PortInfo_Range{
				Start: uint32(portRange.Start),
				End:   uint32(portRange.End),
			},
		}
	}
	return &portInfo
}

func shouldUsePortRange(rule *proto.FirewallRule) bool {
	return rule.Port == "" && (rule.Protocol == proto.RuleProtocol_UDP || rule.Protocol == proto.RuleProtocol_TCP)
}

// Helper function to convert nbdns.CustomZone to proto.CustomZone
func convertToProtoCustomZone(zone nbdns.CustomZone) *proto.CustomZone {
	protoZone := &proto.CustomZone{
		Domain:  zone.Domain,
		Records: make([]*proto.SimpleRecord, 0, len(zone.Records)),
	}
	for _, record := range zone.Records {
		protoZone.Records = append(protoZone.Records, &proto.SimpleRecord{
			Name:  record.Name,
			Type:  int64(record.Type),
			Class: record.Class,
			TTL:   int64(record.TTL),
			RData: record.RData,
		})
	}
	return protoZone
}

// Helper function to convert nbdns.NameServerGroup to proto.NameServerGroup
func convertToProtoNameServerGroup(nsGroup *nbdns.NameServerGroup) *proto.NameServerGroup {
	protoGroup := &proto.NameServerGroup{
		Primary:              nsGroup.Primary,
		Domains:              nsGroup.Domains,
		SearchDomainsEnabled: nsGroup.SearchDomainsEnabled,
		NameServers:          make([]*proto.NameServer, 0, len(nsGroup.NameServers)),
	}
	for _, ns := range nsGroup.NameServers {
		protoGroup.NameServers = append(protoGroup.NameServers, &proto.NameServer{
			IP:     ns.IP.String(),
			Port:   int64(ns.Port),
			NSType: int64(ns.NSType),
		})
	}
	return protoGroup
}

// buildJWTConfig constructs JWT configuration for SSH servers from management server config
func buildJWTConfig(config *nbconfig.HttpServerConfig, deviceFlowConfig *nbconfig.DeviceAuthorizationFlow) *proto.JWTConfig {
	if config == nil || config.AuthAudience == "" {
		return nil
	}

	issuer := strings.TrimSpace(config.AuthIssuer)
	if issuer == "" || deviceFlowConfig != nil {
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

	return &proto.JWTConfig{
		Issuer:       issuer,
		Audience:     config.AuthAudience,
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
