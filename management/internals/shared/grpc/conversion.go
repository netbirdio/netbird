package grpc

import (
	"context"
	"fmt"
	"net/url"
	"sort"
	"strings"

	log "github.com/sirupsen/logrus"
	"google.golang.org/protobuf/types/known/timestamppb"

	integrationsConfig "github.com/netbirdio/management-integrations/integrations/config"
	"github.com/netbirdio/netbird/shared/connectionmode"
	"github.com/netbirdio/netbird/client/ssh/auth"

	nbdns "github.com/netbirdio/netbird/dns"
	"github.com/netbirdio/netbird/management/internals/controllers/network_map/controller/cache"
	nbconfig "github.com/netbirdio/netbird/management/internals/server/config"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/posture"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/route"
	"github.com/netbirdio/netbird/shared/management/proto"
	"github.com/netbirdio/netbird/shared/sshauth"
)

// p2pRetryMaxDisabledSentinel is the wire-format value that signals
// "user-explicit disable backoff" (uint32-max). The 0 wire-value is
// reserved for "not set, use daemon default". Phase 3 of #5989.
const p2pRetryMaxDisabledSentinel = ^uint32(0)

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

	// Resolve the effective ConnectionMode for this peer.
	// Phase 1: account-wide settings only (per-peer / per-group resolution
	// follows in Phase 3 / issue #5990). The new ConnectionMode field wins
	// over the legacy LazyConnectionEnabled boolean. UNSPECIFIED in Settings
	// (i.e. ConnectionMode == nil) falls back to the legacy bool.
	resolvedMode := connectionmode.ResolveLegacyLazyBool(settings.LazyConnectionEnabled)
	if settings.ConnectionMode != nil {
		if m, err := connectionmode.ParseString(*settings.ConnectionMode); err == nil && m != connectionmode.ModeUnspecified {
			resolvedMode = m
		}
	}

	relayTO := uint32(0)
	if settings.RelayTimeoutSeconds != nil {
		relayTO = *settings.RelayTimeoutSeconds
	}
	p2pTO := uint32(0)
	if settings.P2pTimeoutSeconds != nil {
		p2pTO = *settings.P2pTimeoutSeconds
	}
	p2pRetryMax := uint32(0)
	if settings.P2pRetryMaxSeconds != nil {
		if *settings.P2pRetryMaxSeconds == 0 {
			p2pRetryMax = p2pRetryMaxDisabledSentinel
		} else {
			p2pRetryMax = *settings.P2pRetryMaxSeconds
		}
	}

	return &proto.PeerConfig{
		Address:                         fmt.Sprintf("%s/%d", peer.IP.String(), netmask),
		SshConfig:                       sshConfig,
		Fqdn:                            fqdn,
		RoutingPeerDnsResolutionEnabled: settings.RoutingPeerDNSResolutionEnabled,
		// Send BOTH the new enum (for new clients) and the legacy boolean
		// (for old clients). New clients prefer the explicit enum and
		// ignore the bool; old clients ignore the unknown enum field
		// (proto3 default behaviour) and fall back to the bool.
		LazyConnectionEnabled: resolvedMode.ToLazyConnectionEnabled(),
		ConnectionMode:        resolvedMode.ToProto(),
		P2PTimeoutSeconds:     p2pTO,
		P2PRetryMaxSeconds:    p2pRetryMax,
		RelayTimeoutSeconds:   relayTO,
		AutoUpdate: &proto.AutoUpdateSettings{
			Version:      settings.AutoUpdateVersion,
			AlwaysUpdate: settings.AutoUpdateAlways,
		},
	}
}

func ToSyncResponse(ctx context.Context, config *nbconfig.Config, httpConfig *nbconfig.HttpServerConfig, deviceFlowConfig *nbconfig.DeviceAuthorizationFlow, peer *nbpeer.Peer, turnCredentials *Token, relayCredentials *Token, networkMap *types.NetworkMap, dnsName string, checks []*posture.Checks, dnsCache *cache.DNSConfigCache, settings *types.Settings, extraSettings *types.ExtraSettings, peerGroups []string, dnsFwdPort int64, groupNamesByPeerID map[string][]string) *proto.SyncResponse {
	response := &proto.SyncResponse{
		PeerConfig: toPeerConfig(peer, networkMap.Network, dnsName, settings, httpConfig, deviceFlowConfig, networkMap.EnableSSH),
		NetworkMap: &proto.NetworkMap{
			Serial:     networkMap.Network.CurrentSerial(),
			Routes:     toProtocolRoutes(networkMap.Routes),
			DNSConfig:  toProtocolDNSConfig(networkMap.DNSConfig, dnsCache, dnsFwdPort),
			PeerConfig: toPeerConfig(peer, networkMap.Network, dnsName, settings, httpConfig, deviceFlowConfig, networkMap.EnableSSH),
		},
		Checks: toProtocolChecks(ctx, checks),
	}

	nbConfig := toNetbirdConfig(config, turnCredentials, relayCredentials, extraSettings)
	extendedConfig := integrationsConfig.ExtendNetBirdConfig(peer.ID, peerGroups, nbConfig, extraSettings)
	response.NetbirdConfig = extendedConfig

	response.NetworkMap.PeerConfig = response.PeerConfig

	appendCtx := AppendRemotePeerConfigContext{
		DNSDomain:          dnsName,
		Cfg:                settings,
		GroupNamesByPeerID: groupNamesByPeerID,
	}

	remotePeers := make([]*proto.RemotePeerConfig, 0, len(networkMap.Peers)+len(networkMap.OfflinePeers))
	remotePeers = appendRemotePeerConfig(remotePeers, networkMap.Peers, appendCtx)
	response.RemotePeers = remotePeers
	response.NetworkMap.RemotePeers = remotePeers
	response.RemotePeersIsEmpty = len(remotePeers) == 0
	response.NetworkMap.RemotePeersIsEmpty = response.RemotePeersIsEmpty

	response.NetworkMap.OfflinePeers = appendRemotePeerConfig(nil, networkMap.OfflinePeers, appendCtx)

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

	if networkMap.AuthorizedUsers != nil {
		hashedUsers, machineUsers := buildAuthorizedUsersProto(ctx, networkMap.AuthorizedUsers)
		userIDClaim := auth.DefaultUserIDClaim
		if httpConfig != nil && httpConfig.AuthUserIDClaim != "" {
			userIDClaim = httpConfig.AuthUserIDClaim
		}
		response.NetworkMap.SshAuth = &proto.SSHAuth{AuthorizedUsers: hashedUsers, MachineUsers: machineUsers, UserIDClaim: userIDClaim}
	}

	return response
}

func buildAuthorizedUsersProto(ctx context.Context, authorizedUsers map[string]map[string]struct{}) ([][]byte, map[string]*proto.MachineUserIndexes) {
	userIDToIndex := make(map[string]uint32)
	var hashedUsers [][]byte
	machineUsers := make(map[string]*proto.MachineUserIndexes, len(authorizedUsers))

	for machineUser, users := range authorizedUsers {
		indexes := make([]uint32, 0, len(users))
		for userID := range users {
			idx, exists := userIDToIndex[userID]
			if !exists {
				hash, err := sshauth.HashUserID(userID)
				if err != nil {
					log.WithContext(ctx).Errorf("failed to hash user id %s: %v", userID, err)
					continue
				}
				idx = uint32(len(hashedUsers))
				userIDToIndex[userID] = idx
				hashedUsers = append(hashedUsers, hash[:])
			}
			indexes = append(indexes, idx)
		}
		machineUsers[machineUser] = &proto.MachineUserIndexes{Indexes: indexes}
	}

	return hashedUsers, machineUsers
}

// AppendRemotePeerConfigContext bundles per-account settings + per-peer
// group lookups so appendRemotePeerConfig stays free of DB calls.
// Callers (in conversion.go) materialise this once per NetworkMap build.
type AppendRemotePeerConfigContext struct {
	DNSDomain string
	// Cfg is the account-wide configured mode/timeouts. Nil when unavailable.
	Cfg *types.Settings
	// GroupNamesByPeerID maps a peer ID to its sorted group-name list.
	GroupNamesByPeerID map[string][]string
}

func appendRemotePeerConfig(dst []*proto.RemotePeerConfig, peers []*nbpeer.Peer, c AppendRemotePeerConfigContext) []*proto.RemotePeerConfig {
	var cfgConnMode string
	var cfgRelayTO, cfgP2pTO, cfgP2pRetryMax uint32
	if c.Cfg != nil {
		cfgConnMode = derefStringOrEmpty(c.Cfg.ConnectionMode)
		cfgRelayTO = derefUint32OrZero(c.Cfg.RelayTimeoutSeconds)
		cfgP2pTO = derefUint32OrZero(c.Cfg.P2pTimeoutSeconds)
		cfgP2pRetryMax = derefUint32OrZero(c.Cfg.P2pRetryMaxSeconds)
	}

	for _, rPeer := range peers {
		cfg := &proto.RemotePeerConfig{
			WgPubKey:   rPeer.Key,
			AllowedIps: []string{rPeer.IP.String() + "/32"},
			SshConfig:  &proto.SSHConfig{SshPubKey: []byte(rPeer.SSHKey)},
			Fqdn:       rPeer.FQDN(c.DNSDomain),

			AgentVersion: rPeer.Meta.WtVersion,

			// Phase 3.7i: effective values from the peer's last self-report.
			EffectiveConnectionMode:   rPeer.Meta.EffectiveConnectionMode,
			EffectiveRelayTimeoutSecs: rPeer.Meta.EffectiveRelayTimeoutSecs,
			EffectiveP2PTimeoutSecs:   rPeer.Meta.EffectiveP2PTimeoutSecs,
			EffectiveP2PRetryMaxSecs:  rPeer.Meta.EffectiveP2PRetryMaxSecs,

			// Phase 3.7i: account-wide configured values from Settings.
			ConfiguredConnectionMode:   cfgConnMode,
			ConfiguredRelayTimeoutSecs: cfgRelayTO,
			ConfiguredP2PTimeoutSecs:   cfgP2pTO,
			ConfiguredP2PRetryMaxSecs:  cfgP2pRetryMax,

			// Phase 3.7i: server-knowledge fields surfaced to UIs.
			Groups: c.GroupNamesByPeerID[rPeer.ID],
		}
		// nbpeer.Peer.Status is *PeerStatus; nil-guard before accessing.
		if rPeer.Status != nil {
			if !rPeer.Status.LastSeen.IsZero() {
				cfg.LastSeenAtServer = timestamppb.New(rPeer.Status.LastSeen)
			}
			cfg.LiveOnline = rPeer.Status.Connected
		}
		// New servers always know per-peer liveness; signal that to new
		// clients so they can trust LiveOnline directly instead of
		// guessing from the LastSeenAtServer-zero heuristic. Old servers
		// leave this field at default (false) and clients fall back.
		cfg.ServerLivenessKnown = true
		dst = append(dst, cfg)
	}
	return dst
}

// derefStringOrEmpty returns the pointed-to string or "" for nil.
// Used for *string Settings fields where "" means "account hasn't
// configured a mode; UI shows it as unset".
func derefStringOrEmpty(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// derefUint32OrZero returns the pointed-to uint32 or 0 for nil.
// Used for *uint32 Settings fields where 0 means "account hasn't set
// an override; daemon falls back to its built-in default".
func derefUint32OrZero(u *uint32) uint32 {
	if u == nil {
		return 0
	}
	return *u
}

// BuildGroupNamesByPeerID constructs a peerID → sorted-group-names map
// from the account's Groups in a single pass. Callers pass this to
// ToSyncResponse so that appendRemotePeerConfig can annotate each
// RemotePeerConfig.Groups without any additional DB calls.
func BuildGroupNamesByPeerID(groups map[string]*types.Group) map[string][]string {
	result := make(map[string][]string, len(groups))
	for _, g := range groups {
		for _, peerID := range g.Peers {
			result[peerID] = append(result[peerID], g.Name)
		}
	}
	for peerID := range result {
		sort.Strings(result[peerID])
	}
	return result
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
		Domain:               zone.Domain,
		Records:              make([]*proto.SimpleRecord, 0, len(zone.Records)),
		SearchDomainDisabled: zone.SearchDomainDisabled,
		NonAuthoritative:     zone.NonAuthoritative,
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
