package networkmap

import (
	"encoding/base64"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"time"

	log "github.com/sirupsen/logrus"

	nbdns "github.com/netbirdio/netbird/dns"
	resourceTypes "github.com/netbirdio/netbird/management/server/networks/resources/types"
	routerTypes "github.com/netbirdio/netbird/management/server/networks/routers/types"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	nbroute "github.com/netbirdio/netbird/route"
	"github.com/netbirdio/netbird/shared/management/domain"
	"github.com/netbirdio/netbird/shared/management/proto"
	"github.com/netbirdio/netbird/shared/management/types"
)

// DecodeEnvelope converts a NetworkMapEnvelope into a NetworkMapComponents
// the client can run Calculate() over. Every ID-reference on the wire is a
// xid from corresponding public_id field.
//
// ID scheme on the client side:
//
//	Peers              base64(wg_pub_key)          // stable across snapshots
func DecodeEnvelope(env *proto.NetworkMapEnvelope) (*types.NetworkMapComponents, error) {
	full := env.GetFull()
	if full == nil {
		return nil, fmt.Errorf("envelope has no Full payload")
	}

	c := &types.NetworkMapComponents{
		PeerID:              "", // engine fills its own peer id from PeerConfig
		Network:             decodeAccountNetwork(full.Network),
		AccountSettings:     decodeAccountSettings(full.AccountSettings),
		CustomZoneDomain:    full.CustomZoneDomain,
		Peers:               make(map[string]*nbpeer.Peer, len(full.Peers)),
		Groups:              make(map[string]*types.Group, len(full.Groups)),
		Policies:            make([]*types.Policy, 0, len(full.Policies)),
		Routes:              make([]*nbroute.Route, 0, len(full.Routes)),
		NameServerGroups:    make([]*nbdns.NameServerGroup, 0, len(full.NameserverGroups)),
		AllDNSRecords:       decodeSimpleRecords(full.AllDnsRecords),
		AccountZones:        decodeCustomZones(full.AccountZones),
		ResourcePoliciesMap: make(map[string][]*types.Policy),
		RoutersMap:          make(map[string]map[string]*routerTypes.NetworkRouter),
		NetworkResources:    make([]*resourceTypes.NetworkResource, 0, len(full.NetworkResources)),
		RouterPeers:         make(map[string]*nbpeer.Peer),
		AllowedUserIDs:      stringSliceToSet(full.AllowedUserIds),
		PostureFailedPeers:  make(map[string]map[string]struct{}, len(full.PostureFailedPeers)),
		GroupIDToUserIDs:    make(map[string][]string, len(full.GroupIdToUserIds)),
	}

	if full.DnsSettings != nil {
		c.DNSSettings = &types.DNSSettings{
			DisabledManagementGroups: full.DnsSettings.DisabledManagementGroupIds,
		}
	} else {
		c.DNSSettings = &types.DNSSettings{}
	}

	// Phase 1: peers. The envelope's peers slice is index-addressed on the
	// wire; we re-key by the peer's WireGuard public key (base64) so the
	// in-memory components struct uses a stable identifier across
	// snapshots. peerIDByIndex lets downstream phases resolve wire indexes
	// back to that key. A peer with a missing or malformed wg_pub_key is
	// skipped (and its index keeps "" so any cross-reference falls into the
	// same missing-peer branch downstream) — matches legacy behaviour, which
	// degrades gracefully rather than aborting the whole sync on a single
	// bad row.
	peerIDByIndex := make([]string, len(full.Peers))
	for idx, pc := range full.Peers {
		if pc == nil {
			log.Warnf("envelope: peers[%d] is nil, skipping", idx)
			continue
		}
		if len(pc.WgPubKey) != 32 {
			log.Warnf("envelope: peers[%d] wg_pub_key length %d (want 32), skipping", idx, len(pc.WgPubKey))
			continue
		}
		peerID := base64.StdEncoding.EncodeToString(pc.WgPubKey)
		peer := decodePeerCompact(pc, peerID, full.AgentVersions)
		c.Peers[peerID] = peer
		peerIDByIndex[idx] = peerID
	}

	// Phase 2: groups.
	for i, gc := range full.Groups {
		if gc == nil {
			return nil, fmt.Errorf("invalid envelope: groups[%d] is nil", i)
		}
		groupID := gc.Id
		peerIDs := make([]string, 0, len(gc.PeerIndexes))
		for _, idx := range gc.PeerIndexes {
			if int(idx) < len(peerIDByIndex) {
				peerIDs = append(peerIDs, peerIDByIndex[idx])
			} else {
				log.WithField("peer idx", idx).Error("unrecognized peer idx during decoding")
			}
		}
		c.Groups[groupID] = &types.Group{
			ID:       groupID,
			PublicID: gc.Id,
			Peers:    peerIDs,
		}
	}

	// Phase 3: policies (PolicyCompact = one rule per entry; current data
	// model is 1 rule per policy).
	policyByID := make(map[string]*types.Policy, len(full.Policies))
	for i, pc := range full.Policies {
		if pc == nil {
			return nil, fmt.Errorf("invalid envelope: policies[%d] is nil", i)
		}
		policy := decodePolicyCompact(pc, pc.Id, peerIDByIndex)
		c.Policies = append(c.Policies, policy)
		policyByID[pc.Id] = policy
	}

	// Phase 4: routes.
	for i, rr := range full.Routes {
		if rr == nil {
			return nil, fmt.Errorf("invalid envelope: routes[%d] is nil", i)
		}
		c.Routes = append(c.Routes, decodeRouteRaw(rr, peerIDByIndex))
	}

	// Phase 5: NSGs.
	for i, nsg := range full.NameserverGroups {
		if nsg == nil {
			return nil, fmt.Errorf("invalid envelope: nameserver_groups[%d] is nil", i)
		}
		c.NameServerGroups = append(c.NameServerGroups, decodeNameServerGroupRaw(nsg))
	}

	// Phase 6: network resources.
	for i, nr := range full.NetworkResources {
		if nr == nil {
			return nil, fmt.Errorf("invalid envelope: network_resources[%d] is nil", i)
		}
		c.NetworkResources = append(c.NetworkResources, decodeNetworkResource(nr))
	}

	// Phase 7: routers_map (outer key = network seq id, inner key = peer-id
	// reconstructed from peer_index). Synthesized network id is "net_<seq>".
	for networkID, list := range full.RoutersMap {
		inner := make(map[string]*routerTypes.NetworkRouter, len(list.Entries))
		for _, entry := range list.Entries {
			if !entry.PeerIndexSet {
				continue
			}
			if int(entry.PeerIndex) >= len(peerIDByIndex) {
				log.WithField("peer idx", entry.PeerIndex).Error("unrecognized peer id when decoding router map")
				continue
			}
			peerID := peerIDByIndex[entry.PeerIndex]
			inner[peerID] = &routerTypes.NetworkRouter{
				ID:         "",
				NetworkID:  networkID,
				PublicID:   entry.Id,
				Peer:       peerID,
				PeerGroups: entry.PeerGroupIds,
				Masquerade: entry.Masquerade,
				Metric:     int(entry.Metric),
				Enabled:    entry.Enabled,
			}
		}
		if len(inner) > 0 {
			c.RoutersMap[networkID] = inner
		}
	}

	// Phase 8: resource_policies_map
	for _, p := range c.Policies {
		rule := p.Rules[0] // there's always only one rule
		if rule.SourceResource.Type != types.ResourceTypePeer && rule.SourceResource.ID != "" {
			c.ResourcePoliciesMap[rule.SourceResource.ID] = append(c.ResourcePoliciesMap[rule.SourceResource.ID], p)
		}
		if rule.SourceResource.Type != types.ResourceTypePeer && rule.DestinationResource.Type != "" {
			c.ResourcePoliciesMap[rule.SourceResource.ID] = append(c.ResourcePoliciesMap[rule.SourceResource.ID], p)
		}
	}

	// Phase 9: group_id_to_user_ids — wire keys are seq ids, synth to strings.
	for groupId, list := range full.GroupIdToUserIds {
		c.GroupIDToUserIDs[groupId] = append([]string(nil), list.UserIds...)
	}

	// Phase 10: posture_failed_peers — wire keys are posture-check seq ids,
	// values are peer indexes that need to be turned into peer ids. PolicyRule
	// SourcePostureChecks (also synth ids) reference the same key space.
	for checkID, set := range full.PostureFailedPeers {
		failed := make(map[string]struct{}, len(set.PeerIndexes))
		for _, idx := range set.PeerIndexes {
			if int(idx) < len(peerIDByIndex) {
				failed[peerIDByIndex[idx]] = struct{}{}
			} else {
				log.WithField("peer idx", idx).Error("unrecognized peer when decoding posture failed peers")
			}
		}
		if len(failed) > 0 {
			c.PostureFailedPeers[checkID] = failed
		}
	}

	// Phase 11: router_peer_indexes — peers that act as routers. They're
	// already in c.Peers (router peers are appended to the global peers
	// list by the encoder); RouterPeers is the subset.
	for _, idx := range full.RouterPeerIndexes {
		if int(idx) < len(peerIDByIndex) {
			peerID := peerIDByIndex[idx]
			c.RouterPeers[peerID] = c.Peers[peerID]
		}
	}

	return c, nil
}

func decodeAccountNetwork(an *proto.AccountNetwork) *types.Network {
	if an == nil {
		return nil
	}
	n := &types.Network{
		Identifier: an.Identifier,
		Dns:        an.Dns,
		Serial:     an.Serial,
	}
	if an.NetCidr != "" {
		if _, ipnet, err := net.ParseCIDR(an.NetCidr); err == nil && ipnet != nil {
			n.Net = *ipnet
		}
	}
	if an.NetV6Cidr != "" {
		if _, ipnet, err := net.ParseCIDR(an.NetV6Cidr); err == nil && ipnet != nil {
			n.NetV6 = *ipnet
		}
	}
	return n
}

func decodeAccountSettings(as *proto.AccountSettingsCompact) *types.AccountSettingsInfo {
	if as == nil {
		return &types.AccountSettingsInfo{}
	}
	return &types.AccountSettingsInfo{
		PeerLoginExpirationEnabled: as.PeerLoginExpirationEnabled,
		PeerLoginExpiration:        time.Duration(as.PeerLoginExpirationNs),
	}
}

func decodePeerCompact(pc *proto.PeerCompact, peerID string, agentVersions []string) *nbpeer.Peer {
	var caps []int32
	if pc.SupportsSourcePrefixes {
		caps = append(caps, nbpeer.PeerCapabilitySourcePrefixes)
	}
	if pc.SupportsIpv6 {
		caps = append(caps, nbpeer.PeerCapabilityIPv6Overlay)
	}
	peer := &nbpeer.Peer{
		ID:                     peerID,
		Key:                    peerID,
		SSHKey:                 string(pc.SshPubKey),
		SSHEnabled:             pc.SshEnabled,
		DNSLabel:               pc.DnsLabel,
		LoginExpirationEnabled: pc.LoginExpirationEnabled,
		Meta: nbpeer.PeerSystemMeta{
			WtVersion:    pc.AgentVersion,
			Capabilities: caps,
			Flags: nbpeer.Flags{
				ServerSSHAllowed: pc.ServerSshAllowed,
			},
		},
	}
	if pc.AddedWithSsoLogin {
		// Set a non-empty UserID so (*Peer).AddedWithSSOLogin() returns true.
		// The original UserID isn't on the wire; the value is intentionally
		// visibly synthetic so any future consumer that mistakes UserID for a
		// real account user xid won't silently match (or worse, write the
		// sentinel into a downstream record).
		peer.UserID = "<env-sso>"
	}
	if pc.LastLoginUnixNano != 0 {
		t := time.Unix(0, pc.LastLoginUnixNano)
		peer.LastLogin = &t
	}
	switch len(pc.Ip) {
	case 4:
		peer.IP = netip.AddrFrom4([4]byte{pc.Ip[0], pc.Ip[1], pc.Ip[2], pc.Ip[3]})
	case 16:
		var a [16]byte
		copy(a[:], pc.Ip)
		peer.IP = netip.AddrFrom16(a)
	}
	if len(pc.Ipv6) == 16 {
		var a [16]byte
		copy(a[:], pc.Ipv6)
		peer.IPv6 = netip.AddrFrom16(a)
	}
	return peer
}

func decodePolicyCompact(pc *proto.PolicyCompact, policyID string, peerIDByIndex []string) *types.Policy {
	rule := &types.PolicyRule{
		ID:                  policyID, // 1 rule per policy → reuse synthesized id
		PolicyID:            policyID,
		Enabled:             true,
		Action:              actionFromProto(pc.Action),
		Protocol:            protocolFromProto(pc.Protocol),
		Bidirectional:       pc.Bidirectional,
		Ports:               uint32SliceToStrings(pc.Ports),
		PortRanges:          portRangesFromProto(pc.PortRanges),
		Sources:             pc.SourceGroupIds,
		Destinations:        pc.DestinationGroupIds,
		AuthorizedUser:      pc.AuthorizedUser,
		AuthorizedGroups:    authorizedGroupsFromProto(pc.AuthorizedGroups),
		SourceResource:      resourceFromProto(pc.SourceResource, peerIDByIndex),
		DestinationResource: resourceFromProto(pc.DestinationResource, peerIDByIndex),
	}
	return &types.Policy{
		ID:                  policyID,
		PublicID:            pc.Id,
		Enabled:             true,
		Rules:               []*types.PolicyRule{rule},
		SourcePostureChecks: pc.SourcePostureCheckIds,
	}
}

// resourceFromProto rebuilds types.Resource. For peer-typed resources the
// peer reference is reconstructed from the envelope's peer index — wire
// format ships no xid for peers, so we use the synthesized peer id.
func resourceFromProto(r *proto.ResourceCompact, peerIDByIndex []string) types.Resource {
	if r == nil {
		return types.Resource{}
	}

	t, ok := proto.ResourceCompactType_name[int32(r.Type)]
	if !ok || r.Type == proto.ResourceCompactType_unknown_type {
		return types.Resource{}
	}

	if r.Type == proto.ResourceCompactType_peer && int(r.GetPeerIndex()) >= len(peerIDByIndex) {
		return types.Resource{}
	}

	if r.Type == proto.ResourceCompactType_peer && int(r.GetPeerIndex()) < len(peerIDByIndex) {
		return types.Resource{
			Type: types.ResourceTypePeer,
			ID:   peerIDByIndex[int(r.GetPeerIndex())],
		}
	}

	return types.Resource{
		Type: types.ResourceType(t),
		ID:   r.GetId(),
	}
}

// authorizedGroupsFromProto inverts encodeAuthorizedGroups: the wire form
// keys by group account_seq_id, the typed PolicyRule field keys by group
// xid string. We rebuild using the same synthetic scheme the rest of the
// decoder uses ("g<seq>").
func authorizedGroupsFromProto(m map[string]*proto.UserNameList) map[string][]string {
	if len(m) == 0 {
		return nil
	}
	out := make(map[string][]string, len(m))
	for id, list := range m {
		if list == nil {
			continue
		}
		out[id] = append([]string(nil), list.Names...)
	}
	return out
}

func decodeRouteRaw(rr *proto.RouteRaw, peerIDByIndex []string) *nbroute.Route {
	r := &nbroute.Route{
		ID:                  nbroute.ID(rr.Id),
		PublicID:            rr.Id,
		NetID:               nbroute.NetID(rr.NetId),
		Description:         rr.Description,
		Domains:             domainsFromPunycode(rr.Domains),
		KeepRoute:           rr.KeepRoute,
		NetworkType:         nbroute.NetworkType(rr.NetworkType),
		Masquerade:          rr.Masquerade,
		Metric:              int(rr.Metric),
		Enabled:             rr.Enabled,
		Groups:              rr.GroupIds,
		AccessControlGroups: rr.AccessControlGroupIds,
		PeerGroups:          rr.PeerGroupIds,
		SkipAutoApply:       rr.SkipAutoApply,
	}
	if rr.NetworkCidr != "" {
		if p, err := netip.ParsePrefix(rr.NetworkCidr); err == nil {
			r.Network = p
		}
	}
	if rr.PeerIndexSet && int(rr.PeerIndex) < len(peerIDByIndex) {
		r.Peer = peerIDByIndex[rr.PeerIndex]
	}
	return r
}

func decodeNameServerGroupRaw(nsg *proto.NameServerGroupRaw) *nbdns.NameServerGroup {
	out := &nbdns.NameServerGroup{
		ID:                   nsg.Id,
		PublicID:             nsg.Id,
		Groups:               nsg.GroupIds,
		Primary:              nsg.Primary,
		Domains:              nsg.Domains,
		Enabled:              nsg.Enabled,
		SearchDomainsEnabled: nsg.SearchDomainsEnabled,
		NameServers:          make([]nbdns.NameServer, 0, len(nsg.Nameservers)),
	}
	for _, ns := range nsg.Nameservers {
		if addr, err := netip.ParseAddr(ns.IP); err == nil {
			out.NameServers = append(out.NameServers, nbdns.NameServer{
				IP:     addr,
				NSType: nbdns.NameServerType(ns.NSType),
				Port:   int(ns.Port),
			})
		}
	}
	return out
}

func decodeNetworkResource(nr *proto.NetworkResourceRaw) *resourceTypes.NetworkResource {
	out := &resourceTypes.NetworkResource{
		ID:          nr.Id,
		PublicID:    nr.Id,
		NetworkID:   nr.NetworkSeq,
		Name:        nr.Name,
		Description: nr.Description,
		Type:        resourceTypes.NetworkResourceType(nr.Type),
		Address:     nr.Address,
		Domain:      nr.DomainValue,
		Enabled:     nr.Enabled,
	}
	if nr.PrefixCidr != "" {
		if p, err := netip.ParsePrefix(nr.PrefixCidr); err == nil {
			out.Prefix = p
		}
	}
	return out
}

func decodeSimpleRecords(records []*proto.SimpleRecord) []nbdns.SimpleRecord {
	out := make([]nbdns.SimpleRecord, 0, len(records))
	for _, r := range records {
		out = append(out, nbdns.SimpleRecord{
			Name:  r.Name,
			Type:  int(r.Type),
			Class: r.Class,
			TTL:   int(r.TTL),
			RData: r.RData,
		})
	}
	return out
}

func decodeCustomZones(zones []*proto.CustomZone) []nbdns.CustomZone {
	out := make([]nbdns.CustomZone, 0, len(zones))
	for _, z := range zones {
		out = append(out, nbdns.CustomZone{
			Domain:               z.Domain,
			Records:              decodeSimpleRecords(z.Records),
			SearchDomainDisabled: z.SearchDomainDisabled,
			NonAuthoritative:     z.NonAuthoritative,
		})
	}
	return out
}

func uint32SliceToStrings(ports []uint32) []string {
	if len(ports) == 0 {
		return nil
	}
	out := make([]string, len(ports))
	for i, p := range ports {
		out[i] = strconv.FormatUint(uint64(p), 10)
	}
	return out
}

func portRangesFromProto(ranges []*proto.PortInfo_Range) []types.RulePortRange {
	if len(ranges) == 0 {
		return nil
	}
	out := make([]types.RulePortRange, 0, len(ranges))
	for _, r := range ranges {
		if r == nil || r.Start > 65535 || r.End > 65535 {
			continue
		}
		out = append(out, types.RulePortRange{
			Start: uint16(r.Start),
			End:   uint16(r.End),
		})
	}
	return out
}

func actionFromProto(a proto.RuleAction) types.PolicyTrafficActionType {
	if a == proto.RuleAction_DROP {
		return types.PolicyTrafficActionDrop
	}
	return types.PolicyTrafficActionAccept
}

func protocolFromProto(p proto.RuleProtocol) types.PolicyRuleProtocolType {
	switch p {
	case proto.RuleProtocol_TCP:
		return types.PolicyRuleProtocolTCP
	case proto.RuleProtocol_UDP:
		return types.PolicyRuleProtocolUDP
	case proto.RuleProtocol_ICMP:
		return types.PolicyRuleProtocolICMP
	case proto.RuleProtocol_ALL:
		return types.PolicyRuleProtocolALL
	case proto.RuleProtocol_NETBIRD_SSH:
		return types.PolicyRuleProtocolNetbirdSSH
	default:
		return types.PolicyRuleProtocolALL
	}
}

func stringSliceToSet(s []string) map[string]struct{} {
	if len(s) == 0 {
		return nil
	}
	out := make(map[string]struct{}, len(s))
	for _, v := range s {
		out[v] = struct{}{}
	}
	return out
}

// domainsFromPunycode is a thin wrapper that converts a punycode list back to
// the domain.List type the route.Route struct expects. It accepts the
// punycode strings as-is (no extra decoding) — symmetric with
// route.Domains.ToPunycodeList() used in the encoder.
func domainsFromPunycode(punycoded []string) domain.List {
	if len(punycoded) == 0 {
		return nil
	}
	out := make(domain.List, 0, len(punycoded))
	for _, d := range punycoded {
		out = append(out, domain.Domain(d))
	}
	return out
}
