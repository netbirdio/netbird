// Package networkmap contains the shared NetworkMap helpers that both the
// management server and the client agent need.
//
// The proto-conversion helpers (types.NetworkMap → proto.NetworkMap) live
// here so the client can run the same conversion locally after deriving its
// NetworkMap from a NetworkMapEnvelope, without taking a dependency on the
// server-side conversion package (which pulls in cloud integrations and is
// otherwise an unwanted internal import on the client).
//
// The helpers are pure functions over inputs — no caches, no IO, no logging
// beyond a context-aware error log when an individual user-id hash fails.
package networkmap

import (
	"context"

	log "github.com/sirupsen/logrus"
	goproto "google.golang.org/protobuf/proto"

	nbdns "github.com/netbirdio/netbird/dns"
	"net/netip"

	nbroute "github.com/netbirdio/netbird/route"
	"github.com/netbirdio/netbird/shared/management/proto"
	"github.com/netbirdio/netbird/shared/management/types"
	"github.com/netbirdio/netbird/shared/netiputil"
	"github.com/netbirdio/netbird/shared/sshauth"
)

// ToProtocolRoutes converts a slice of typed routes to their proto form.
func ToProtocolRoutes(routes []*nbroute.Route) []*proto.Route {
	protoRoutes := make([]*proto.Route, 0, len(routes))
	for _, r := range routes {
		protoRoutes = append(protoRoutes, ToProtocolRoute(r))
	}
	return protoRoutes
}

// ToProtocolRoute converts one typed route to its proto form.
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

// ToProtocolFirewallRules converts the firewall rules to the protocol form.
// When useSourcePrefixes is true, the compact SourcePrefixes field is
// populated alongside the deprecated PeerIP for forward compatibility.
// Wildcard rules ("0.0.0.0") are expanded into separate v4/v6 SourcePrefixes
// when includeIPv6 is true.
func ToProtocolFirewallRules(rules []*types.FirewallRule, includeIPv6, useSourcePrefixes bool) []*proto.FirewallRule {
	result := make([]*proto.FirewallRule, 0, len(rules))
	for i := range rules {
		rule := rules[i]

		fwRule := &proto.FirewallRule{
			PolicyID:  []byte(rule.PolicyID),
			PeerIP:    rule.PeerIP, //nolint:staticcheck // populated for backward compatibility
			Direction: GetProtoDirection(rule.Direction),
			Action:    GetProtoAction(rule.Action),
			Protocol:  GetProtoProtocol(rule.Protocol),
			Port:      rule.Port,
		}

		if useSourcePrefixes && rule.PeerIP != "" {
			result = append(result, populateSourcePrefixes(fwRule, rule, includeIPv6)...)
		}

		if ShouldUsePortRange(fwRule) {
			fwRule.PortInfo = rule.PortRange.ToProto()
		}

		result = append(result, fwRule)
	}
	return result
}

// populateSourcePrefixes sets SourcePrefixes on fwRule and returns any
// additional rules needed (e.g. a v6 wildcard clone when the peer IP is
// unspecified).
func populateSourcePrefixes(fwRule *proto.FirewallRule, rule *types.FirewallRule, includeIPv6 bool) []*proto.FirewallRule {
	addr, err := netip.ParseAddr(rule.PeerIP)
	if err != nil {
		return nil
	}

	if !addr.IsUnspecified() {
		fwRule.SourcePrefixes = [][]byte{netiputil.EncodeAddr(addr.Unmap())}
		return nil
	}

	v4Wildcard, _ := netiputil.EncodePrefix(netip.PrefixFrom(netip.IPv4Unspecified(), 0))
	fwRule.SourcePrefixes = [][]byte{v4Wildcard}

	if !includeIPv6 {
		return nil
	}

	v6Rule := goproto.Clone(fwRule).(*proto.FirewallRule)
	v6Rule.PeerIP = "::" //nolint:staticcheck // populated for backward compatibility
	v6Wildcard, _ := netiputil.EncodePrefix(netip.PrefixFrom(netip.IPv6Unspecified(), 0))
	v6Rule.SourcePrefixes = [][]byte{v6Wildcard}
	if ShouldUsePortRange(v6Rule) {
		v6Rule.PortInfo = rule.PortRange.ToProto()
	}
	return []*proto.FirewallRule{v6Rule}
}

// GetProtoDirection converts the direction to proto.RuleDirection.
func GetProtoDirection(direction int) proto.RuleDirection {
	if direction == types.FirewallRuleDirectionOUT {
		return proto.RuleDirection_OUT
	}
	return proto.RuleDirection_IN
}

// GetProtoAction converts the action to proto.RuleAction.
func GetProtoAction(action string) proto.RuleAction {
	if action == string(types.PolicyTrafficActionDrop) {
		return proto.RuleAction_DROP
	}
	return proto.RuleAction_ACCEPT
}

// GetProtoProtocol converts the protocol to proto.RuleProtocol.
func GetProtoProtocol(protocol string) proto.RuleProtocol {
	switch types.PolicyRuleProtocolType(protocol) {
	case types.PolicyRuleProtocolALL:
		return proto.RuleProtocol_ALL
	case types.PolicyRuleProtocolTCP:
		return proto.RuleProtocol_TCP
	case types.PolicyRuleProtocolUDP:
		return proto.RuleProtocol_UDP
	case types.PolicyRuleProtocolICMP:
		return proto.RuleProtocol_ICMP
	case types.PolicyRuleProtocolNetbirdSSH:
		return proto.RuleProtocol_NETBIRD_SSH
	default:
		return proto.RuleProtocol_UNKNOWN
	}
}

// GetProtoPortInfo converts route-firewall-rule port info to proto.PortInfo.
func GetProtoPortInfo(rule *types.RouteFirewallRule) *proto.PortInfo {
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

// ShouldUsePortRange reports whether the firewall rule should use a port
// range rather than a single port (TCP/UDP without a single port).
func ShouldUsePortRange(rule *proto.FirewallRule) bool {
	return rule.Port == "" && (rule.Protocol == proto.RuleProtocol_UDP || rule.Protocol == proto.RuleProtocol_TCP)
}

// ToProtocolRoutesFirewallRules converts a slice of typed route-firewall
// rules to proto.
func ToProtocolRoutesFirewallRules(rules []*types.RouteFirewallRule) []*proto.RouteFirewallRule {
	result := make([]*proto.RouteFirewallRule, len(rules))
	for i := range rules {
		rule := rules[i]
		result[i] = &proto.RouteFirewallRule{
			SourceRanges: rule.SourceRanges,
			Action:       GetProtoAction(rule.Action),
			Destination:  rule.Destination,
			Protocol:     GetProtoProtocol(rule.Protocol),
			PortInfo:     GetProtoPortInfo(rule),
			IsDynamic:    rule.IsDynamic,
			Domains:      rule.Domains.ToPunycodeList(),
			PolicyID:     []byte(rule.PolicyID),
			RouteID:      string(rule.RouteID),
		}
	}
	return result
}

// ConvertToProtoCustomZone converts an nbdns.CustomZone to its proto form.
func ConvertToProtoCustomZone(zone nbdns.CustomZone) *proto.CustomZone {
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

// ConvertToProtoNameServerGroup converts a NameServerGroup to its proto form.
func ConvertToProtoNameServerGroup(nsGroup *nbdns.NameServerGroup) *proto.NameServerGroup {
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

// DNSConfigCache is the cache contract for amortising NameServerGroup
// proto-conversion across peers in the same account. Server uses a concrete
// implementation; client passes nil (no cross-peer caching needed when
// rebuilding a single NetworkMap from an envelope).
type DNSConfigCache interface {
	GetNameServerGroup(key string) (*proto.NameServerGroup, bool)
	SetNameServerGroup(key string, value *proto.NameServerGroup)
}

// ToProtocolDNSConfig converts nbdns.Config to proto.DNSConfig. If cache is
// non-nil, NameServerGroup proto values are cached by NSG.ID across calls —
// the server amortises this across peers, the client passes nil.
func ToProtocolDNSConfig(update nbdns.Config, cache DNSConfigCache, forwardPort int64) *proto.DNSConfig {
	protoUpdate := &proto.DNSConfig{
		ServiceEnable:    update.ServiceEnable,
		CustomZones:      make([]*proto.CustomZone, 0, len(update.CustomZones)),
		NameServerGroups: make([]*proto.NameServerGroup, 0, len(update.NameServerGroups)),
		ForwarderPort:    forwardPort,
	}

	for _, zone := range update.CustomZones {
		protoUpdate.CustomZones = append(protoUpdate.CustomZones, ConvertToProtoCustomZone(zone))
	}

	for _, nsGroup := range update.NameServerGroups {
		if cache != nil {
			if cachedGroup, exists := cache.GetNameServerGroup(nsGroup.ID); exists {
				protoUpdate.NameServerGroups = append(protoUpdate.NameServerGroups, cachedGroup)
				continue
			}
		}
		protoGroup := ConvertToProtoNameServerGroup(nsGroup)
		if cache != nil {
			cache.SetNameServerGroup(nsGroup.ID, protoGroup)
		}
		protoUpdate.NameServerGroups = append(protoUpdate.NameServerGroups, protoGroup)
	}

	return protoUpdate
}

// AppendRemotePeerConfig appends typed peers as proto.RemotePeerConfig
// entries to dst and returns the result.
func AppendRemotePeerConfig(dst []*proto.RemotePeerConfig, peers []*types.ComponentPeer, dnsName string, includeIPv6 bool) []*proto.RemotePeerConfig {
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
		})
	}
	return dst
}

// BuildAuthorizedUsersProto deduplicates user-IDs into a hashed list and
// builds per-machine-user index maps. Returns (hashedUsers, machineUsers).
// Errors from individual hash failures are logged via the provided context;
// they leave the offending user out of the result but don't abort the build.
func BuildAuthorizedUsersProto(ctx context.Context, authorizedUsers map[string]map[string]struct{}) ([][]byte, map[string]*proto.MachineUserIndexes) {
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
					log.WithContext(ctx).WithError(err).Error("failed to hash user id")
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
