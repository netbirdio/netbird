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
// uint32 (peer index or account_seq_id) — no xid strings travel. The decoder
// synthesises consistent string IDs from the uint32s so the reconstructed
// components struct round-trips through Calculate exactly the way the
// server-side typed components would.
//
// ID scheme on the client side:
//
//	Peers              base64(wg_pub_key)          // stable across snapshots
//	Groups             "g_<account_seq_id>"
//	Policies           "pol_<account_seq_id>"      // 1 rule per policy
//	Routes             "r_<account_seq_id>"
//	Network resources  "nres_<account_seq_id>"
//	Posture checks     "pc_<account_seq_id>"
//	Networks           "net_<account_seq_id>"
//	Nameserver groups  "nsg_<account_seq_id>"
func DecodeEnvelope(env *proto.NetworkMapEnvelope) (*types.NetworkMapComponents, error) {
	if env == nil {
		return nil, fmt.Errorf("nil envelope")
	}
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
			DisabledManagementGroups: groupIDsFromSeqs(full.DnsSettings.DisabledManagementGroupIds),
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

	// Phase 2: groups. AccountSeqID becomes both the synthesized string ID
	// and the GroupCompact.id wire value.
	for i, gc := range full.Groups {
		if gc == nil {
			return nil, fmt.Errorf("invalid envelope: groups[%d] is nil", i)
		}
		groupID := synthGroupID(gc.Id)
		peerIDs := make([]string, 0, len(gc.PeerIndexes))
		for _, idx := range gc.PeerIndexes {
			if int(idx) < len(peerIDByIndex) {
				peerIDs = append(peerIDs, peerIDByIndex[idx])
			}
		}
		c.Groups[groupID] = &types.Group{
			ID:           groupID,
			AccountSeqID: gc.Id,
			Name:         gc.Name,
			Peers:        peerIDs,
		}
	}

	// Phase 3: policies (PolicyCompact = one rule per entry; current data
	// model is 1 rule per policy). Policy.ID is synthesized from the
	// per-account seq id; proto.FirewallRule.PolicyID downstream carries
	// the same synth string (no xid on the wire).
	for i, pc := range full.Policies {
		if pc == nil {
			return nil, fmt.Errorf("invalid envelope: policies[%d] is nil", i)
		}
		policyID := synthPolicyID(pc.Id)
		c.Policies = append(c.Policies, decodePolicyCompact(pc, policyID, peerIDByIndex))
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
	for networkSeq, list := range full.RoutersMap {
		networkID := synthNetworkID(networkSeq)
		inner := make(map[string]*routerTypes.NetworkRouter, len(list.Entries))
		for _, entry := range list.Entries {
			if !entry.PeerIndexSet {
				continue
			}
			if int(entry.PeerIndex) >= len(peerIDByIndex) {
				continue
			}
			peerID := peerIDByIndex[entry.PeerIndex]
			inner[peerID] = &routerTypes.NetworkRouter{
				ID:           "",
				NetworkID:    networkID,
				AccountSeqID: entry.Id,
				Peer:         peerID,
				PeerGroups:   groupIDsFromSeqs(entry.PeerGroupIds),
				Masquerade:   entry.Masquerade,
				Metric:       int(entry.Metric),
				Enabled:      entry.Enabled,
			}
		}
		if len(inner) > 0 {
			c.RoutersMap[networkID] = inner
		}
	}

	// Phase 8: resource_policies_map (resource seq id → list of *types.Policy
	// pointers from the decoded policies slice). Resource ID is synthesized
	// the same way as in decodeNetworkResource.
	for resourceSeq, idxs := range full.ResourcePoliciesMap {
		if len(idxs.Indexes) == 0 {
			continue
		}
		resourceID := synthNetworkResourceID(resourceSeq)
		policies := make([]*types.Policy, 0, len(idxs.Indexes))
		for _, i := range idxs.Indexes {
			if int(i) < len(c.Policies) {
				policies = append(policies, c.Policies[i])
			}
		}
		if len(policies) > 0 {
			c.ResourcePoliciesMap[resourceID] = policies
		}
	}

	// Phase 9: group_id_to_user_ids — wire keys are seq ids, synth to strings.
	for groupSeq, list := range full.GroupIdToUserIds {
		c.GroupIDToUserIDs[synthGroupID(groupSeq)] = append([]string(nil), list.UserIds...)
	}

	// Phase 10: posture_failed_peers — wire keys are posture-check seq ids,
	// values are peer indexes that need to be turned into peer ids. PolicyRule
	// SourcePostureChecks (also synth ids) reference the same key space.
	for checkSeq, set := range full.PostureFailedPeers {
		checkID := synthPostureCheckID(checkSeq)
		failed := make(map[string]struct{}, len(set.PeerIndexes))
		for _, idx := range set.PeerIndexes {
			if int(idx) < len(peerIDByIndex) {
				failed[peerIDByIndex[idx]] = struct{}{}
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
			WtVersion:    lookupAgentVersion(agentVersions, pc.AgentVersionIdx),
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
		Sources:             groupIDsFromSeqs(pc.SourceGroupIds),
		Destinations:        groupIDsFromSeqs(pc.DestinationGroupIds),
		AuthorizedUser:      pc.AuthorizedUser,
		AuthorizedGroups:    authorizedGroupsFromProto(pc.AuthorizedGroups),
		SourceResource:      resourceFromProto(pc.SourceResource, peerIDByIndex),
		DestinationResource: resourceFromProto(pc.DestinationResource, peerIDByIndex),
	}
	return &types.Policy{
		ID:                  policyID,
		AccountSeqID:        pc.Id,
		Enabled:             true,
		Rules:               []*types.PolicyRule{rule},
		SourcePostureChecks: postureCheckIDsFromSeqs(pc.SourcePostureCheckSeqIds),
	}
}

// resourceFromProto rebuilds types.Resource. For peer-typed resources the
// peer reference is reconstructed from the envelope's peer index — wire
// format ships no xid for peers, so we use the synthesized peer id.
func resourceFromProto(r *proto.ResourceCompact, peerIDByIndex []string) types.Resource {
	if r == nil {
		return types.Resource{}
	}
	out := types.Resource{Type: types.ResourceType(r.Type)}
	if r.PeerIndexSet && int(r.PeerIndex) < len(peerIDByIndex) {
		out.ID = peerIDByIndex[r.PeerIndex]
	}
	return out
}

// postureCheckIDsFromSeqs synths posture-check ids from per-account seq ids.
// Mirrors groupIDsFromSeqs.
func postureCheckIDsFromSeqs(seqs []uint32) []string {
	if len(seqs) == 0 {
		return nil
	}
	out := make([]string, len(seqs))
	for i, s := range seqs {
		out[i] = synthPostureCheckID(s)
	}
	return out
}

// authorizedGroupsFromProto inverts encodeAuthorizedGroups: the wire form
// keys by group account_seq_id, the typed PolicyRule field keys by group
// xid string. We rebuild using the same synthetic scheme the rest of the
// decoder uses ("g<seq>").
func authorizedGroupsFromProto(m map[uint32]*proto.UserNameList) map[string][]string {
	if len(m) == 0 {
		return nil
	}
	out := make(map[string][]string, len(m))
	for seq, list := range m {
		if list == nil {
			continue
		}
		out[synthGroupID(seq)] = append([]string(nil), list.Names...)
	}
	return out
}

func decodeRouteRaw(rr *proto.RouteRaw, peerIDByIndex []string) *nbroute.Route {
	r := &nbroute.Route{
		ID:                  nbroute.ID(synthRouteID(rr.Id)),
		AccountSeqID:        rr.Id,
		NetID:               nbroute.NetID(rr.NetId),
		Description:         rr.Description,
		Domains:             domainsFromPunycode(rr.Domains),
		KeepRoute:           rr.KeepRoute,
		NetworkType:         nbroute.NetworkType(rr.NetworkType),
		Masquerade:          rr.Masquerade,
		Metric:              int(rr.Metric),
		Enabled:             rr.Enabled,
		Groups:              groupIDsFromSeqs(rr.GroupIds),
		AccessControlGroups: groupIDsFromSeqs(rr.AccessControlGroupIds),
		PeerGroups:          groupIDsFromSeqs(rr.PeerGroupIds),
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
		ID:                   synthNameServerGroupID(nsg.Id),
		AccountSeqID:         nsg.Id,
		Name:                 nsg.Name,
		Description:          nsg.Description,
		Groups:               groupIDsFromSeqs(nsg.GroupIds),
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
		ID:           synthNetworkResourceID(nr.Id),
		AccountSeqID: nr.Id,
		NetworkID:    synthNetworkID(nr.NetworkSeq),
		Name:         nr.Name,
		Description:  nr.Description,
		Type:         resourceTypes.NetworkResourceType(nr.Type),
		Address:      nr.Address,
		Domain:       nr.DomainValue,
		Enabled:      nr.Enabled,
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

// Synthetic ID generators — deterministic given the same wire input.
// Underscore-separated ("p_<n>", "pol_<n>", ...) so they're visually
// distinct in operator logs. fmt.Sprintf would dominate the decode hot path
// on large accounts (a 10k-peer envelope produces ~50k synth calls); the
// strconv.AppendUint builder keeps it allocation-light.
func synthID(prefix string, n uint32) string {
	buf := make([]byte, 0, len(prefix)+10)
	buf = append(buf, prefix...)
	buf = strconv.AppendUint(buf, uint64(n), 10)
	return string(buf)
}

func synthGroupID(seq uint32) string           { return synthID("g_", seq) }
func synthPolicyID(seq uint32) string          { return synthID("pol_", seq) }
func synthRouteID(seq uint32) string           { return synthID("r_", seq) }
func synthNetworkResourceID(seq uint32) string { return synthID("nres_", seq) }
func synthPostureCheckID(seq uint32) string    { return synthID("pc_", seq) }
func synthNetworkID(seq uint32) string         { return synthID("net_", seq) }
func synthNameServerGroupID(seq uint32) string { return synthID("nsg_", seq) }

func groupIDsFromSeqs(seqs []uint32) []string {
	if len(seqs) == 0 {
		return nil
	}
	out := make([]string, len(seqs))
	for i, s := range seqs {
		out[i] = synthGroupID(s)
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

func lookupAgentVersion(table []string, idx uint32) string {
	if int(idx) < len(table) {
		return table[idx]
	}
	return ""
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
