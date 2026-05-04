package grpc

import (
	"encoding/base64"
	"strconv"

	nbdns "github.com/netbirdio/netbird/dns"
	resourceTypes "github.com/netbirdio/netbird/management/server/networks/resources/types"
	routerTypes "github.com/netbirdio/netbird/management/server/networks/routers/types"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/types"
	nbroute "github.com/netbirdio/netbird/route"
	"github.com/netbirdio/netbird/shared/management/proto"
)

// wgKeyRawLen is the raw byte length of a WireGuard public key.
const wgKeyRawLen = 32

// ComponentsEnvelopeInput bundles the data the component-format encoder needs.
// In Step 2 the envelope is fully self-contained — every field needed by the
// client's local Calculate() comes from the components struct itself. The
// only externally-supplied data is the receiving peer's PeerConfig (which is
// computed alongside the components in the network_map controller and reused
// from the legacy proto path) and the dns_domain string.
type ComponentsEnvelopeInput struct {
	Components *types.NetworkMapComponents
	PeerConfig *proto.PeerConfig
	DNSDomain  string
}

// EncodeNetworkMapEnvelope converts NetworkMapComponents into the component
// wire envelope. The encoder is intentionally non-deterministic: it iterates
// Go maps in their native (random) order. Indexes inside the envelope
// (peer_indexes, source_group_ids, agent_version_idx, router_peer_indexes)
// are self-consistent within a single encode, so the decoder reconstructs
// the same typed objects regardless of emit order. Tests that need to
// compare envelopes do so semantically via proto round-trip + canonicalize,
// not byte-equal.
//
// Callers must NOT concatenate or merge envelopes from different encodes —
// index spaces are local to a single envelope. Delta sync (Step 3+) will
// use a different shape for the same reason.
func EncodeNetworkMapEnvelope(in ComponentsEnvelopeInput) *proto.NetworkMapEnvelope {
	c := in.Components

	// Phase 1: build dedup tables. Every routing peer (in c.RouterPeers) and
	// every regular peer (in c.Peers) must be indexed before any encoder
	// looks up indexes via e.peerOrder — otherwise routes / routers_map for
	// peers that exist only in c.RouterPeers would silently lose their
	// peer_index reference.
	enc := newComponentEncoder(c)
	enc.indexAllPeers()
	routerIdxs := enc.indexRouterPeers(c.RouterPeers)

	// Phase 2: gather every policy that any consumer references (peer-pair
	// policies + resource-only policies) so encodeResourcePoliciesMap can
	// translate every *Policy pointer to a wire index.
	allPolicies := unionPolicies(c.Policies, c.ResourcePoliciesMap)
	policies, policyToIdxs := enc.encodePolicies(allPolicies)

	// Phase 3: emit. Order of struct field expressions no longer matters:
	// every encoder either reads from the dedup tables or works on
	// independent input.
	full := &proto.NetworkMapComponentsFull{
		Serial:              networkSerial(c.Network),
		PeerConfig:          in.PeerConfig,
		Network:             toAccountNetwork(c.Network),
		AccountSettings:     toAccountSettingsCompact(c.AccountSettings),
		DnsSettings:         enc.encodeDNSSettings(c.DNSSettings),
		DnsDomain:           in.DNSDomain,
		CustomZoneDomain:    c.CustomZoneDomain,
		AgentVersions:       enc.agentVersions,
		Peers:               enc.peers,
		RouterPeerIndexes:   routerIdxs,
		Policies:            policies,
		Groups:              enc.encodeGroups(),
		Routes:              enc.encodeRoutes(c.Routes),
		NameserverGroups:    enc.encodeNameServerGroups(c.NameServerGroups),
		AllDnsRecords:       encodeSimpleRecords(c.AllDNSRecords),
		AccountZones:        encodeCustomZones(c.AccountZones),
		NetworkResources:    encodeNetworkResources(c.NetworkResources),
		RoutersMap:          enc.encodeRoutersMap(c.RoutersMap),
		ResourcePoliciesMap: encodeResourcePoliciesMap(c.ResourcePoliciesMap, policyToIdxs),
		GroupIdToUserIds:    enc.encodeGroupIDToUserIDs(c.GroupIDToUserIDs),
		AllowedUserIds:      stringSetToSlice(c.AllowedUserIDs),
		PostureFailedPeers:  enc.encodePostureFailedPeers(c.PostureFailedPeers),
	}

	return &proto.NetworkMapEnvelope{
		Payload: &proto.NetworkMapEnvelope_Full{Full: full},
	}
}

// networkSerial returns c.Network.CurrentSerial() with a nil guard. The
// production path always populates c.Network (account_components.go:86), but
// the encoder is exported and a hand-built components struct may omit it.
func networkSerial(n *types.Network) uint64 {
	if n == nil {
		return 0
	}
	return n.CurrentSerial()
}

type componentEncoder struct {
	components *types.NetworkMapComponents

	peerOrder map[string]uint32
	peers     []*proto.PeerCompact

	agentVersionOrder map[string]uint32
	agentVersions     []string
}

func newComponentEncoder(c *types.NetworkMapComponents) *componentEncoder {
	return &componentEncoder{
		components:        c,
		peerOrder:         make(map[string]uint32, len(c.Peers)),
		peers:             make([]*proto.PeerCompact, 0, len(c.Peers)),
		agentVersionOrder: map[string]uint32{"": 0},
		agentVersions:     []string{""},
	}
}

func (e *componentEncoder) indexAllPeers() {
	for _, p := range e.components.Peers {
		if p == nil {
			continue
		}
		e.appendPeer(p)
	}
}

func (e *componentEncoder) appendPeer(p *nbpeer.Peer) uint32 {
	if idx, ok := e.peerOrder[p.ID]; ok {
		return idx
	}
	idx := uint32(len(e.peers))
	e.peerOrder[p.ID] = idx
	e.peers = append(e.peers, toPeerCompact(p, e.agentVersionIndex(p.Meta.WtVersion)))
	return idx
}

func (e *componentEncoder) agentVersionIndex(v string) uint32 {
	if idx, ok := e.agentVersionOrder[v]; ok {
		return idx
	}
	idx := uint32(len(e.agentVersions))
	e.agentVersionOrder[v] = idx
	e.agentVersions = append(e.agentVersions, v)
	return idx
}

// indexRouterPeers ensures every router peer is in the peer dedup table
// (c.RouterPeers may contain peers not in c.Peers when validation rules drop
// them) and returns their wire indexes for the RouterPeerIndexes field. Must
// run before any encoder that resolves peer ids via e.peerOrder.
func (e *componentEncoder) indexRouterPeers(routers map[string]*nbpeer.Peer) []uint32 {
	if len(routers) == 0 {
		return nil
	}
	out := make([]uint32, 0, len(routers))
	for _, p := range routers {
		if p == nil {
			continue
		}
		out = append(out, e.appendPeer(p))
	}
	return out
}

func (e *componentEncoder) encodeGroups() []*proto.GroupCompact {
	if len(e.components.Groups) == 0 {
		return nil
	}

	out := make([]*proto.GroupCompact, 0, len(e.components.Groups))
	for _, g := range e.components.Groups {
		if !g.HasSeqID() {
			continue
		}
		peerIdxs := make([]uint32, 0, len(g.Peers))
		for _, peerID := range g.Peers {
			if idx, ok := e.peerOrder[peerID]; ok {
				peerIdxs = append(peerIdxs, idx)
			}
		}
		out = append(out, &proto.GroupCompact{
			Id:          g.AccountSeqID,
			Name:        g.Name,
			PeerIndexes: peerIdxs,
		})
	}
	return out
}

// encodePolicies flattens Policy{Rules} → []PolicyCompact. Returns the wire
// list and a map from policy pointer to the indexes of its emitted rules in
// that list — used by encodeResourcePoliciesMap to translate
// ResourcePoliciesMap[resourceID][]*Policy into wire-side indexes.
func (e *componentEncoder) encodePolicies(policies []*types.Policy) ([]*proto.PolicyCompact, map[*types.Policy][]uint32) {
	if len(policies) == 0 {
		return nil, nil
	}

	out := make([]*proto.PolicyCompact, 0, len(policies))
	idxByPolicy := make(map[*types.Policy][]uint32, len(policies))

	for _, pol := range policies {
		if !pol.HasSeqID() || !pol.Enabled {
			continue
		}
		for _, r := range pol.Rules {
			if r == nil || !r.Enabled {
				continue
			}
			pc := &proto.PolicyCompact{
				Id:                  pol.AccountSeqID,
				Action:              getProtoAction(string(r.Action)),
				Protocol:            getProtoProtocol(string(r.Protocol)),
				Bidirectional:       r.Bidirectional,
				Ports:               portsToUint32(r.Ports),
				PortRanges:          portRangesToProto(r.PortRanges),
				SourceGroupIds:      make([]uint32, 0, len(r.Sources)),
				DestinationGroupIds: make([]uint32, 0, len(r.Destinations)),
			}
			for _, gid := range r.Sources {
				if seq, ok := e.groupSeq(gid); ok {
					pc.SourceGroupIds = append(pc.SourceGroupIds, seq)
				}
			}
			for _, gid := range r.Destinations {
				if seq, ok := e.groupSeq(gid); ok {
					pc.DestinationGroupIds = append(pc.DestinationGroupIds, seq)
				}
			}
			idxByPolicy[pol] = append(idxByPolicy[pol], uint32(len(out)))
			out = append(out, pc)
		}
	}
	return out, idxByPolicy
}

// unionPolicies merges c.Policies with every policy referenced by
// c.ResourcePoliciesMap, deduplicating by pointer identity. Resource-only
// policies (relevant to a NetworkResource but not to peer-pair traffic)
// only live in ResourcePoliciesMap; without this union step they'd be lost
// from the wire and the client's resource-policy lookup would come back
// empty.
func unionPolicies(policies []*types.Policy, resourcePolicies map[string][]*types.Policy) []*types.Policy {
	seen := make(map[*types.Policy]struct{}, len(policies))
	out := make([]*types.Policy, 0, len(policies))
	for _, p := range policies {
		if p == nil {
			continue
		}
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	for _, list := range resourcePolicies {
		for _, p := range list {
			if p == nil {
				continue
			}
			if _, ok := seen[p]; ok {
				continue
			}
			seen[p] = struct{}{}
			out = append(out, p)
		}
	}
	return out
}

func (e *componentEncoder) groupSeq(groupID string) (uint32, bool) {
	g, ok := e.components.Groups[groupID]
	if !ok || !g.HasSeqID() {
		return 0, false
	}
	return g.AccountSeqID, true
}

func (e *componentEncoder) encodeDNSSettings(s *types.DNSSettings) *proto.DNSSettingsCompact {
	if s == nil || len(s.DisabledManagementGroups) == 0 {
		return nil
	}
	out := &proto.DNSSettingsCompact{
		DisabledManagementGroupIds: make([]uint32, 0, len(s.DisabledManagementGroups)),
	}
	for _, gid := range s.DisabledManagementGroups {
		if seq, ok := e.groupSeq(gid); ok {
			out.DisabledManagementGroupIds = append(out.DisabledManagementGroupIds, seq)
		}
	}
	return out
}

func (e *componentEncoder) encodeRoutes(routes []*nbroute.Route) []*proto.RouteRaw {
	if len(routes) == 0 {
		return nil
	}
	out := make([]*proto.RouteRaw, 0, len(routes))
	for _, r := range routes {
		if r == nil {
			continue
		}
		rr := &proto.RouteRaw{
			Id:                    r.AccountSeqID,
			NetId:                 string(r.NetID),
			Description:           r.Description,
			KeepRoute:             r.KeepRoute,
			NetworkType:           int32(r.NetworkType),
			Masquerade:            r.Masquerade,
			Metric:                int32(r.Metric),
			Enabled:               r.Enabled,
			SkipAutoApply:         r.SkipAutoApply,
			Domains:               r.Domains.ToPunycodeList(),
			GroupIds:              e.groupIDsToSeq(r.Groups),
			AccessControlGroupIds: e.groupIDsToSeq(r.AccessControlGroups),
			PeerGroupIds:          e.groupIDsToSeq(r.PeerGroups),
		}
		if r.Network.IsValid() {
			rr.NetworkCidr = r.Network.String()
		}
		if r.Peer != "" {
			if idx, ok := e.peerOrder[r.Peer]; ok {
				rr.PeerIndexSet = true
				rr.PeerIndex = idx
			}
		}
		out = append(out, rr)
	}
	return out
}

func (e *componentEncoder) groupIDsToSeq(groupIDs []string) []uint32 {
	if len(groupIDs) == 0 {
		return nil
	}
	out := make([]uint32, 0, len(groupIDs))
	for _, gid := range groupIDs {
		if seq, ok := e.groupSeq(gid); ok {
			out = append(out, seq)
		}
	}
	return out
}

func (e *componentEncoder) encodeNameServerGroups(nsgs []*nbdns.NameServerGroup) []*proto.NameServerGroupRaw {
	if len(nsgs) == 0 {
		return nil
	}
	out := make([]*proto.NameServerGroupRaw, 0, len(nsgs))
	for _, nsg := range nsgs {
		if nsg == nil {
			continue
		}
		entry := &proto.NameServerGroupRaw{
			Id:                   nsg.AccountSeqID,
			Name:                 nsg.Name,
			Description:          nsg.Description,
			Nameservers:          encodeNameServers(nsg.NameServers),
			GroupIds:             e.groupIDsToSeq(nsg.Groups),
			Primary:              nsg.Primary,
			Domains:              nsg.Domains,
			Enabled:              nsg.Enabled,
			SearchDomainsEnabled: nsg.SearchDomainsEnabled,
		}
		out = append(out, entry)
	}
	return out
}

func encodeNameServers(servers []nbdns.NameServer) []*proto.NameServer {
	if len(servers) == 0 {
		return nil
	}
	out := make([]*proto.NameServer, 0, len(servers))
	for _, s := range servers {
		out = append(out, &proto.NameServer{
			IP:     s.IP.String(),
			NSType: int64(s.NSType),
			Port:   int64(s.Port),
		})
	}
	return out
}

func encodeSimpleRecords(records []nbdns.SimpleRecord) []*proto.SimpleRecord {
	if len(records) == 0 {
		return nil
	}
	out := make([]*proto.SimpleRecord, 0, len(records))
	for _, r := range records {
		out = append(out, &proto.SimpleRecord{
			Name:  r.Name,
			Type:  int64(r.Type),
			Class: r.Class,
			TTL:   int64(r.TTL),
			RData: r.RData,
		})
	}
	return out
}

func encodeCustomZones(zones []nbdns.CustomZone) []*proto.CustomZone {
	if len(zones) == 0 {
		return nil
	}
	out := make([]*proto.CustomZone, 0, len(zones))
	for _, z := range zones {
		out = append(out, &proto.CustomZone{
			Domain:               z.Domain,
			Records:              encodeSimpleRecords(z.Records),
			SearchDomainDisabled: z.SearchDomainDisabled,
			NonAuthoritative:     z.NonAuthoritative,
		})
	}
	return out
}

func encodeNetworkResources(resources []*resourceTypes.NetworkResource) []*proto.NetworkResourceRaw {
	if len(resources) == 0 {
		return nil
	}
	out := make([]*proto.NetworkResourceRaw, 0, len(resources))
	for _, r := range resources {
		if r == nil {
			continue
		}
		entry := &proto.NetworkResourceRaw{
			Id:          r.AccountSeqID,
			NetworkId:   r.NetworkID,
			Name:        r.Name,
			Description: r.Description,
			Type:        string(r.Type),
			Address:     r.Address,
			DomainValue: r.Domain,
			Enabled:     r.Enabled,
		}
		if r.Prefix.IsValid() {
			entry.PrefixCidr = r.Prefix.String()
		}
		out = append(out, entry)
	}
	return out
}

func (e *componentEncoder) encodeRoutersMap(routersMap map[string]map[string]*routerTypes.NetworkRouter) map[string]*proto.NetworkRouterList {
	if len(routersMap) == 0 {
		return nil
	}
	out := make(map[string]*proto.NetworkRouterList, len(routersMap))
	for networkID, routers := range routersMap {
		if len(routers) == 0 {
			continue
		}
		entries := make([]*proto.NetworkRouterEntry, 0, len(routers))
		for peerID, r := range routers {
			if r == nil {
				continue
			}
			entry := &proto.NetworkRouterEntry{
				Id:           r.AccountSeqID,
				PeerGroupIds: e.groupIDsToSeq(r.PeerGroups),
				Masquerade:   r.Masquerade,
				Metric:       int32(r.Metric),
				Enabled:      r.Enabled,
			}
			if idx, ok := e.peerOrder[peerID]; ok {
				entry.PeerIndexSet = true
				entry.PeerIndex = idx
			}
			entries = append(entries, entry)
		}
		out[networkID] = &proto.NetworkRouterList{Entries: entries}
	}
	return out
}

func encodeResourcePoliciesMap(rpm map[string][]*types.Policy, policyToIdxs map[*types.Policy][]uint32) map[string]*proto.PolicyIndexes {
	if len(rpm) == 0 {
		return nil
	}
	out := make(map[string]*proto.PolicyIndexes, len(rpm))
	for resourceID, policies := range rpm {
		idxs := make([]uint32, 0, len(policies)*2)
		for _, pol := range policies {
			idxs = append(idxs, policyToIdxs[pol]...)
		}
		if len(idxs) == 0 {
			continue
		}
		out[resourceID] = &proto.PolicyIndexes{Indexes: idxs}
	}
	return out
}

func (e *componentEncoder) encodeGroupIDToUserIDs(m map[string][]string) map[uint32]*proto.UserIDList {
	if len(m) == 0 {
		return nil
	}
	out := make(map[uint32]*proto.UserIDList, len(m))
	for groupID, userIDs := range m {
		seq, ok := e.groupSeq(groupID)
		if !ok || len(userIDs) == 0 {
			continue
		}
		out[seq] = &proto.UserIDList{UserIds: userIDs}
	}
	return out
}

func stringSetToSlice(s map[string]struct{}) []string {
	if len(s) == 0 {
		return nil
	}
	out := make([]string, 0, len(s))
	for k := range s {
		out = append(out, k)
	}
	return out
}

func (e *componentEncoder) encodePostureFailedPeers(m map[string]map[string]struct{}) map[string]*proto.PeerIndexSet {
	if len(m) == 0 {
		return nil
	}
	out := make(map[string]*proto.PeerIndexSet, len(m))
	for checkID, failedPeerIDs := range m {
		idxs := make([]uint32, 0, len(failedPeerIDs))
		for peerID := range failedPeerIDs {
			if idx, ok := e.peerOrder[peerID]; ok {
				idxs = append(idxs, idx)
			}
		}
		if len(idxs) == 0 {
			continue
		}
		out[checkID] = &proto.PeerIndexSet{PeerIndexes: idxs}
	}
	return out
}

// toAccountSettingsCompact always returns a non-nil message — the client
// dereferences it unconditionally during Calculate(), so a nil here would
// crash the receiver. A missing types.AccountSettingsInfo on the server
// (which shouldn't happen in production but the encoder is exported)
// degrades to login_expiration_enabled = false, which makes
// LoginExpired() return false for every peer.
func toAccountSettingsCompact(s *types.AccountSettingsInfo) *proto.AccountSettingsCompact {
	if s == nil {
		return &proto.AccountSettingsCompact{}
	}
	return &proto.AccountSettingsCompact{
		PeerLoginExpirationEnabled: s.PeerLoginExpirationEnabled,
		PeerLoginExpirationNs:      int64(s.PeerLoginExpiration),
	}
}

func toAccountNetwork(n *types.Network) *proto.AccountNetwork {
	if n == nil {
		return nil
	}
	out := &proto.AccountNetwork{
		Identifier: n.Identifier,
		NetCidr:    n.Net.String(),
		Dns:        n.Dns,
		Serial:     n.CurrentSerial(),
	}
	if len(n.NetV6.IP) > 0 {
		out.NetV6Cidr = n.NetV6.String()
	}
	return out
}

func toPeerCompact(p *nbpeer.Peer, agentVersionIdx uint32) *proto.PeerCompact {
	pc := &proto.PeerCompact{
		WgPubKey:               decodeWgKey(p.Key),
		SshPubKey:              []byte(p.SSHKey),
		DnsLabel:               p.DNSLabel,
		AgentVersionIdx:        agentVersionIdx,
		AddedWithSsoLogin:      p.UserID != "",
		LoginExpirationEnabled: p.LoginExpirationEnabled,
	}
	if p.LastLogin != nil {
		pc.LastLoginUnixNano = p.LastLogin.UnixNano()
	}
	switch {
	case !p.IP.IsValid():
		// leave Ip nil
	case p.IP.Is4() || p.IP.Is4In6():
		ip := p.IP.Unmap().As4()
		pc.Ip = ip[:]
	default:
		ip := p.IP.As16()
		pc.Ip = ip[:]
	}
	if p.IPv6.IsValid() {
		ip := p.IPv6.As16()
		pc.Ipv6 = ip[:]
	}
	return pc
}

// decodeWgKey returns the raw 32 bytes of a base64-encoded WireGuard public
// key, or nil for an empty / malformed key.
func decodeWgKey(s string) []byte {
	if s == "" {
		return nil
	}
	out := make([]byte, wgKeyRawLen)
	n, err := base64.StdEncoding.Decode(out, []byte(s))
	if err != nil || n != wgKeyRawLen {
		return nil
	}
	return out
}

func portsToUint32(ports []string) []uint32 {
	if len(ports) == 0 {
		return nil
	}
	out := make([]uint32, 0, len(ports))
	for _, p := range ports {
		v, err := strconv.ParseUint(p, 10, 16)
		if err != nil {
			continue
		}
		out = append(out, uint32(v))
	}
	return out
}

func portRangesToProto(ranges []types.RulePortRange) []*proto.PortInfo_Range {
	if len(ranges) == 0 {
		return nil
	}
	out := make([]*proto.PortInfo_Range, 0, len(ranges))
	for _, r := range ranges {
		out = append(out, &proto.PortInfo_Range{
			Start: uint32(r.Start),
			End:   uint32(r.End),
		})
	}
	return out
}
