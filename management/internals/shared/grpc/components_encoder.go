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
	"github.com/netbirdio/netbird/shared/management/networkmap"
	"github.com/netbirdio/netbird/shared/management/proto"
)

// wgKeyRawLen is the raw byte length of a WireGuard public key.
const wgKeyRawLen = 32

// ComponentsEnvelopeInput bundles the data the component-format encoder needs.
// The envelope is fully self-contained — every field needed by the client's
// local Calculate() comes from the components struct itself. The only
// externally-supplied data is the receiving peer's PeerConfig (which is
// computed alongside the components in the network_map controller and reused
// from the legacy proto path) and the dns_domain string.
type ComponentsEnvelopeInput struct {
	Components       *types.NetworkMapComponents
	PeerConfig       *proto.PeerConfig
	DNSDomain        string
	DNSForwarderPort int64
	// UserIDClaim is the OIDC claim name the client should embed in
	// SshAuth.UserIDClaim when reconstructing the NetworkMap. Empty value
	// is OK — client treats empty as "no SshAuth to build".
	UserIDClaim string
	// ProxyPatch carries pre-expanded NetworkMap fragments injected by
	// external controllers (BYOP/port-forwarding). Nil when no proxy data
	// is present; encoder skips the field in that case.
	ProxyPatch *proto.ProxyPatch
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
// index spaces are local to a single envelope.
func EncodeNetworkMapEnvelope(in ComponentsEnvelopeInput) *proto.NetworkMapEnvelope {
	c := in.Components

	// Graceful degrade when components is nil — matches the legacy path's
	// behaviour for missing/unvalidated peers (return a NetworkMap with only
	// Network populated). The receiver gets an envelope it can decode
	// without crashing; AccountSettings stays non-nil so client-side
	// dereferences are safe.
	if c == nil {
		// Match legacy missing-peer minimum: a NetworkMap with only Network
		// populated. The receiver gets enough to bootstrap (Network
		// identifier, dns_domain, account_settings) and nothing else.
		return &proto.NetworkMapEnvelope{
			Payload: &proto.NetworkMapEnvelope_Full{
				Full: &proto.NetworkMapComponentsFull{
					PeerConfig:       in.PeerConfig,
					DnsDomain:        in.DNSDomain,
					DnsForwarderPort: in.DNSForwarderPort,
					UserIdClaim:      in.UserIDClaim,
					AccountSettings:  &proto.AccountSettingsCompact{},
					ProxyPatch:       in.ProxyPatch,
				},
			},
		}
	}

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
	policies := enc.encodePolicies(allPolicies)

	// Phase 3: emit. Order of struct field expressions no longer matters:
	// every encoder either reads from the dedup tables or works on
	// independent input.
	full := &proto.NetworkMapComponentsFull{
		Serial:              networkSerial(c.Network),
		PeerConfig:          in.PeerConfig,
		Network:             toAccountNetwork(c.Network),
		AccountSettings:     toAccountSettingsCompact(c.AccountSettings),
		DnsForwarderPort:    in.DNSForwarderPort,
		UserIdClaim:         in.UserIDClaim,
		ProxyPatch:          in.ProxyPatch,
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
		NetworkResources:    enc.encodeNetworkResources(c.NetworkResources),
		RoutersMap:          enc.encodeRoutersMap(c.RoutersMap),
		ResourcePoliciesMap: enc.encodeResourcePoliciesMap(c.ResourcePoliciesMap),
		GroupIdToUserIds:    enc.encodeGroupIDToUserIDs(c.GroupIDToUserIDs),
		AllowedUserIds:      stringSetToSlice(c.AllowedUserIDs),
		PostureFailedPeers:  enc.encodePostureFailedPeers(c.PostureFailedPeers),
	}

	return &proto.NetworkMapEnvelope{
		Payload: &proto.NetworkMapEnvelope_Full{Full: full},
	}
}

// networkSerial returns c.Network.CurrentSerial() with a nil guard. The
// production path always populates c.Network, but the encoder is exported
// and a hand-built components struct may omit it.
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
		agentVersionOrder: make(map[string]uint32),
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
	e.peers = append(e.peers, toPeerCompact(p))
	return idx
}

func (e *componentEncoder) agentVersionIndex(v string) uint32 {
	if idx, ok := e.agentVersionOrder[v]; ok {
		return idx
	}
	// Lazy-initialise the table with "" at index 0 so the empty string
	// stays interchangeable with proto3's default uint32=0 — peers without
	// a WtVersion don't force the table to materialise.
	if v == "" {
		idx := uint32(len(e.agentVersions))
		if idx == 0 {
			e.agentVersions = append(e.agentVersions, "")
		}
		e.agentVersionOrder[""] = idx
		return idx
	}
	if len(e.agentVersions) == 0 {
		e.agentVersions = append(e.agentVersions, "")
		e.agentVersionOrder[""] = 0
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
func (e *componentEncoder) encodePolicies(policies []*types.Policy) []*proto.PolicyCompact {
	if len(policies) == 0 {
		return nil
	}

	out := make([]*proto.PolicyCompact, 0, len(policies))

	for _, pol := range policies {
		if !pol.HasSeqID() || !pol.Enabled {
			continue
		}
		for _, r := range pol.Rules {
			if r == nil || !r.Enabled {
				continue
			}
			out = append(out, e.encodePolicyRule(pol, r))
		}
	}
	return out
}

// encodePolicyRule maps a single PolicyRule under pol to a PolicyCompact entry.
func (e *componentEncoder) encodePolicyRule(pol *types.Policy, r *types.PolicyRule) *proto.PolicyCompact {
	return &proto.PolicyCompact{
		Id:                       pol.AccountSeqID,
		Action:                   networkmap.GetProtoAction(string(r.Action)),
		Protocol:                 networkmap.GetProtoProtocol(string(r.Protocol)),
		Bidirectional:            r.Bidirectional,
		Ports:                    portsToUint32(r.Ports),
		PortRanges:               portRangesToProto(r.PortRanges),
		SourceGroupIds:           e.groupSeqIDs(r.Sources),
		DestinationGroupIds:      e.groupSeqIDs(r.Destinations),
		AuthorizedUser:           r.AuthorizedUser,
		AuthorizedGroups:         e.encodeAuthorizedGroups(r.AuthorizedGroups),
		SourceResource:           e.resourceToProto(r.SourceResource),
		DestinationResource:      e.resourceToProto(r.DestinationResource),
		SourcePostureCheckSeqIds: e.postureCheckSeqs(pol.SourcePostureChecks),
	}
}

// groupSeqIDs maps the xid group IDs in src to their per-account seq ids,
// dropping any group that has no seq id assigned.
func (e *componentEncoder) groupSeqIDs(src []string) []int32 {
	if len(src) == 0 {
		return nil
	}
	out := make([]int32, 0, len(src))
	for _, gid := range src {
		if seq, ok := e.groupSeq(gid); ok {
			out = append(out, seq)
		}
	}
	return out
}

// unionPolicies merges c.Policies with every policy referenced by
// c.ResourcePoliciesMap, deduplicating by pointer identity. Resource-only
// policies (relevant to a NetworkResource but not to peer-pair traffic)
// only live in ResourcePoliciesMap; without this union step they'd be lost
// from the wire and the client's resource-policy lookup would come back
// empty.
func unionPolicies(policies []*types.Policy, resourcePolicies map[string][]*types.Policy) []*types.Policy {
	// Fast path: non-router peers have no resource-only policies, so the
	// "union" is identical to `policies`. Skip the dedup map allocation.
	if len(resourcePolicies) == 0 {
		return policies
	}
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

// encodeAuthorizedGroups translates rule.AuthorizedGroups (map keyed by
// group xid → local-user names) to the wire form (map keyed by group
// account_seq_id → UserNameList). Groups without a seq id are dropped —
// matches how source/destination group references handle the same case.
func (e *componentEncoder) encodeAuthorizedGroups(m map[string][]string) map[int32]*proto.UserNameList {
	if len(m) == 0 {
		return nil
	}
	out := make(map[int32]*proto.UserNameList, len(m))
	for groupID, names := range m {
		seq, ok := e.groupSeq(groupID)
		if !ok {
			continue
		}
		out[seq] = &proto.UserNameList{Names: append([]string(nil), names...)}
	}
	return out
}

func (e *componentEncoder) groupSeq(groupID string) (int32, bool) {
	g, ok := e.components.Groups[groupID]
	if !ok || !g.HasSeqID() {
		return 0, false
	}
	return g.AccountSeqID, true
}

// resourceToProto translates types.Resource for the wire. For peer-typed
// resources the peer id is converted to a peer index into the envelope's
// peers array. For other resource types only the type string is shipped
// today (Calculate's resource-typed rule path consults SourceResource only
// for "peer" — other types fall through to group-based lookup).
func (e *componentEncoder) resourceToProto(r types.Resource) *proto.ResourceCompact {
	if r.ID == "" && r.Type == "" {
		return nil
	}
	out := &proto.ResourceCompact{Type: string(r.Type)}
	if r.Type == types.ResourceTypePeer && r.ID != "" {
		if idx, ok := e.peerOrder[r.ID]; ok {
			out.PeerIndexSet = true
			out.PeerIndex = idx
		}
	}
	return out
}

// postureCheckSeqs translates a slice of posture-check xids to their
// per-account integer ids using the NetworkMapComponents.PostureCheckXIDToSeq
// lookup. Unresolvable xids are silently dropped — matches how group/peer
// references handle the same case.
func (e *componentEncoder) postureCheckSeqs(xids []string) []int32 {
	if len(xids) == 0 || len(e.components.PostureCheckXIDToSeq) == 0 {
		return nil
	}
	out := make([]int32, 0, len(xids))
	for _, xid := range xids {
		if seq, ok := e.components.PostureCheckXIDToSeq[xid]; ok {
			out = append(out, seq)
		}
	}
	return out
}

// networkSeq translates a Network xid to its per-account integer id using
// the NetworkMapComponents.NetworkXIDToSeq lookup. Returns (0,false) when
// the xid isn't known — callers decide whether to skip the parent record.
func (e *componentEncoder) networkSeq(xid string) (int32, bool) {
	if xid == "" {
		return 0, false
	}
	seq, ok := e.components.NetworkXIDToSeq[xid]
	if !ok || seq == 0 {
		return 0, false
	}
	return seq, true
}

func (e *componentEncoder) encodeDNSSettings(s *types.DNSSettings) *proto.DNSSettingsCompact {
	if s == nil || len(s.DisabledManagementGroups) == 0 {
		return nil
	}
	out := &proto.DNSSettingsCompact{
		DisabledManagementGroupIds: make([]int32, 0, len(s.DisabledManagementGroups)),
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

func (e *componentEncoder) groupIDsToSeq(groupIDs []string) []int32 {
	if len(groupIDs) == 0 {
		return nil
	}
	out := make([]int32, 0, len(groupIDs))
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

func (e *componentEncoder) encodeNetworkResources(resources []*resourceTypes.NetworkResource) []*proto.NetworkResourceRaw {
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
			Name:        r.Name,
			Description: r.Description,
			Type:        string(r.Type),
			Address:     r.Address,
			DomainValue: r.Domain,
			Enabled:     r.Enabled,
		}
		if seq, ok := e.networkSeq(r.NetworkID); ok {
			entry.NetworkSeq = seq
		}
		if r.Prefix.IsValid() {
			entry.PrefixCidr = r.Prefix.String()
		}
		out = append(out, entry)
	}
	return out
}

func (e *componentEncoder) encodeRoutersMap(routersMap map[string]map[string]*routerTypes.NetworkRouter) map[int32]*proto.NetworkRouterList {
	if len(routersMap) == 0 {
		return nil
	}
	out := make(map[int32]*proto.NetworkRouterList, len(routersMap))
	for networkXID, routers := range routersMap {
		if len(routers) == 0 {
			continue
		}
		netSeq, ok := e.networkSeq(networkXID)
		if !ok {
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
		out[netSeq] = &proto.NetworkRouterList{Entries: entries}
	}
	return out
}

func (e *componentEncoder) encodeResourcePoliciesMap(rpm map[string][]*types.Policy) map[int32]*proto.PolicyIds {
	if len(rpm) == 0 {
		return nil
	}
	// resourceXIDToSeq is local to one encode — built from components.NetworkResources
	// (small slice). Network resources without seq id are dropped, matching how
	// other components-without-seq are silently filtered.
	resourceXIDToSeq := make(map[string]int32, len(e.components.NetworkResources))
	for _, r := range e.components.NetworkResources {
		if r != nil && r.AccountSeqID != 0 {
			resourceXIDToSeq[r.ID] = r.AccountSeqID
		}
	}
	out := make(map[int32]*proto.PolicyIds, len(rpm))
	for resourceXID, policies := range rpm {
		seq, ok := resourceXIDToSeq[resourceXID]
		if !ok {
			continue
		}
		ids := make([]int32, 0, len(policies))
		for _, pol := range policies {
			ids = append(ids, pol.AccountSeqID)
		}
		if len(ids) == 0 {
			continue
		}
		out[seq] = &proto.PolicyIds{Ids: ids}
	}
	return out
}

func (e *componentEncoder) encodeGroupIDToUserIDs(m map[string][]string) map[int32]*proto.UserIDList {
	if len(m) == 0 {
		return nil
	}
	out := make(map[int32]*proto.UserIDList, len(m))
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

func (e *componentEncoder) encodePostureFailedPeers(m map[string]map[string]struct{}) map[int32]*proto.PeerIndexSet {
	if len(m) == 0 {
		return nil
	}
	out := make(map[int32]*proto.PeerIndexSet, len(m))
	for checkXID, failedPeerIDs := range m {
		seq, ok := e.components.PostureCheckXIDToSeq[checkXID]
		if !ok || seq == 0 {
			continue
		}
		idxs := make([]uint32, 0, len(failedPeerIDs))
		for peerID := range failedPeerIDs {
			if idx, ok := e.peerOrder[peerID]; ok {
				idxs = append(idxs, idx)
			}
		}
		if len(idxs) == 0 {
			continue
		}
		out[seq] = &proto.PeerIndexSet{PeerIndexes: idxs}
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

func toPeerCompact(p *nbpeer.Peer) *proto.PeerCompact {
	pc := &proto.PeerCompact{
		WgPubKey:               decodeWgKey(p.Key),
		SshPubKey:              []byte(p.SSHKey),
		DnsLabel:               p.DNSLabel,
		AgentVersion:           p.Meta.WtVersion,
		AddedWithSsoLogin:      p.UserID != "",
		LoginExpirationEnabled: p.LoginExpirationEnabled,
		SshEnabled:             p.SSHEnabled,
		SupportsIpv6:           p.SupportsIPv6(),
		SupportsSourcePrefixes: p.SupportsSourcePrefixes(),
		ServerSshAllowed:       p.Meta.Flags.ServerSSHAllowed,
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
