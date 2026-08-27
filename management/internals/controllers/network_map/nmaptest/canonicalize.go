package nmaptest

import (
	"bytes"
	"cmp"
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/netbirdio/netbird/shared/management/proto"
)

// normalizeIDSpace replaces policy and route identifiers with positional
// placeholders so a comparison can reach everything else.
//
// This exists only because the envelope round-trip currently substitutes each
// internal xid with the object's public id, which is a tracked defect and not a
// licence to differ: those identifiers reach the server again inside flow
// events, which resolve them by internal id, so the substitution silently
// breaks flow attribution for component-format peers. TestIDSpaceMatches
// asserts the equality that must eventually hold; this erasure keeps the other
// 40-odd cases reporting on semantics meanwhile. When the id space is unified,
// delete this and the calls to it — every case should still pass.
//
// Cardinality and cross-references survive the erasure: two rules under one
// policy still share a token and a route firewall rule still points at its
// route, so a path that drops a policy, merges two policies, or misattributes a
// rule to the wrong route still fails.
func normalizeIDSpace(nm *proto.NetworkMap) {
	if nm == nil {
		return
	}
	policies := newTokenizer("policy")
	routes := newTokenizer("route")

	for _, i := range orderBy(nm.Routes, routeKeyWithoutID) {
		nm.Routes[i].ID = routes.get(nm.Routes[i].ID)
	}
	for _, i := range orderBy(nm.FirewallRules, firewallKeyWithoutPolicy) {
		r := nm.FirewallRules[i]
		if len(r.PolicyID) > 0 {
			r.PolicyID = []byte(policies.get(string(r.PolicyID)))
		}
	}
	for _, i := range orderBy(nm.RoutesFirewallRules, routeFirewallKeyWithoutIDs) {
		r := nm.RoutesFirewallRules[i]
		if len(r.PolicyID) > 0 {
			r.PolicyID = []byte(policies.get(string(r.PolicyID)))
		}
		r.RouteID = routes.get(r.RouteID)
	}
}

// tokenizer maps identifiers to positional placeholders in order of first use.
type tokenizer struct {
	prefix string
	seen   map[string]string
}

func newTokenizer(prefix string) *tokenizer {
	return &tokenizer{prefix: prefix, seen: make(map[string]string)}
}

func (t *tokenizer) get(id string) string {
	if id == "" {
		return ""
	}
	if tok, ok := t.seen[id]; ok {
		return tok
	}
	tok := fmt.Sprintf("%s#%d", t.prefix, len(t.seen))
	t.seen[id] = tok
	return tok
}

// orderBy returns indices sorted by key, so placeholder numbering does not
// depend on the identifiers being erased.
func orderBy[T any](items []T, key func(T) string) []int {
	idx := make([]int, len(items))
	for i := range idx {
		idx[i] = i
	}
	sort.SliceStable(idx, func(a, b int) bool { return key(items[idx[a]]) < key(items[idx[b]]) })
	return idx
}

func routeKeyWithoutID(r *proto.Route) string {
	if r == nil {
		return ""
	}
	return fmt.Sprintf("%s|%s|%s|%d|%d|%t|%t|%v",
		r.Network, r.NetID, r.Peer, r.Metric, r.NetworkType, r.Masquerade, r.KeepRoute, r.Domains)
}

func firewallKeyWithoutPolicy(r *proto.FirewallRule) string {
	if r == nil {
		return ""
	}
	return fmt.Sprintf("%s|%d|%d|%d|%s|%s|%v",
		r.PeerIP, r.Direction, r.Action, r.Protocol, r.Port, portInfoKey(r.PortInfo), r.SourcePrefixes) //nolint:staticcheck
}

func routeFirewallKeyWithoutIDs(r *proto.RouteFirewallRule) string {
	if r == nil {
		return ""
	}
	return fmt.Sprintf("%s|%d|%d|%s|%v|%v|%t|%d",
		r.Destination, r.Protocol, r.Action, portInfoKey(r.PortInfo), r.Domains, r.SourceRanges, r.IsDynamic, r.CustomProtocol)
}

// canonicalize sorts every repeated field of the NetworkMap by a stable key.
// The producing paths iterate Go maps while building these slices, so order
// can differ between runs even when the content is identical; comparing
// without this reports noise.
func canonicalize(nm *proto.NetworkMap) {
	if nm == nil {
		return
	}
	slices.SortFunc(nm.RemotePeers, cmpRemotePeer)
	slices.SortFunc(nm.OfflinePeers, cmpRemotePeer)
	slices.SortFunc(nm.Routes, cmpRoute)
	slices.SortFunc(nm.FirewallRules, cmpFirewallRule)
	slices.SortFunc(nm.RoutesFirewallRules, cmpRouteFirewallRule)
	slices.SortFunc(nm.ForwardingRules, cmpForwardingRule)

	for _, r := range nm.FirewallRules {
		slices.SortFunc(r.SourcePrefixes, bytes.Compare)
	}
	for _, r := range nm.RoutesFirewallRules {
		slices.Sort(r.SourceRanges)
	}
	canonicalizeDNSConfig(nm.DNSConfig)
	canonicalizeSSHAuth(nm.SshAuth)
}

func canonicalizeDNSConfig(d *proto.DNSConfig) {
	if d == nil {
		return
	}
	for _, g := range d.NameServerGroups {
		if g == nil {
			continue
		}
		slices.Sort(g.Domains)
		slices.SortFunc(g.NameServers, func(a, b *proto.NameServer) int {
			if a == nil || b == nil {
				return boolCmp(a == nil, b == nil)
			}
			if c := cmp.Compare(a.IP, b.IP); c != 0 {
				return c
			}
			if c := cmp.Compare(a.Port, b.Port); c != 0 {
				return c
			}
			return cmp.Compare(a.NSType, b.NSType)
		})
	}
	slices.SortFunc(d.NameServerGroups, func(a, b *proto.NameServerGroup) int {
		return cmp.Compare(nsgKey(a), nsgKey(b))
	})
	for _, z := range d.CustomZones {
		if z == nil {
			continue
		}
		slices.SortFunc(z.Records, cmpSimpleRecord)
	}
	slices.SortFunc(d.CustomZones, func(a, b *proto.CustomZone) int {
		if a == nil || b == nil {
			return boolCmp(a == nil, b == nil)
		}
		return cmp.Compare(a.Domain, b.Domain)
	})
}

// canonicalizeSSHAuth sorts AuthorizedUsers and re-keys MachineUsers.Indexes
// against the new ordering, preserving which machine user maps to which hashes.
func canonicalizeSSHAuth(s *proto.SSHAuth) {
	if s == nil || len(s.AuthorizedUsers) == 0 {
		return
	}
	type hashed struct {
		bytes []byte
		old   uint32
	}
	entries := make([]hashed, len(s.AuthorizedUsers))
	for i, b := range s.AuthorizedUsers {
		entries[i] = hashed{bytes: b, old: uint32(i)}
	}
	slices.SortFunc(entries, func(a, b hashed) int { return bytes.Compare(a.bytes, b.bytes) })

	remap := make(map[uint32]uint32, len(entries))
	sorted := make([][]byte, len(entries))
	for newIdx, e := range entries {
		remap[e.old] = uint32(newIdx)
		sorted[newIdx] = e.bytes
	}
	s.AuthorizedUsers = sorted

	for _, mu := range s.MachineUsers {
		if mu == nil {
			continue
		}
		for i, oldIdx := range mu.Indexes {
			if newIdx, ok := remap[oldIdx]; ok {
				mu.Indexes[i] = newIdx
			}
		}
		slices.Sort(mu.Indexes)
	}
}

func boolCmp(a, b bool) int {
	if a == b {
		return 0
	}
	if a {
		return 1
	}
	return -1
}

func nsgKey(g *proto.NameServerGroup) string {
	if g == nil {
		return ""
	}
	var parts []string
	for _, ns := range g.NameServers {
		if ns == nil {
			continue
		}
		parts = append(parts, ns.IP+":"+strconv.FormatInt(ns.Port, 10)+":"+strconv.FormatInt(ns.NSType, 10))
	}
	slices.Sort(parts)
	key := strings.Join(parts, ",")
	domains := append([]string(nil), g.Domains...)
	slices.Sort(domains)
	key += "|" + strings.Join(domains, "|")
	if g.Primary {
		key += "|P"
	}
	if g.SearchDomainsEnabled {
		key += "|S"
	}
	return key
}

func cmpSimpleRecord(a, b *proto.SimpleRecord) int {
	if a == nil || b == nil {
		return boolCmp(a == nil, b == nil)
	}
	if c := cmp.Compare(a.Name, b.Name); c != 0 {
		return c
	}
	if c := cmp.Compare(a.Type, b.Type); c != 0 {
		return c
	}
	if c := cmp.Compare(a.Class, b.Class); c != 0 {
		return c
	}
	if c := cmp.Compare(a.RData, b.RData); c != 0 {
		return c
	}
	return cmp.Compare(a.TTL, b.TTL)
}

func cmpRemotePeer(a, b *proto.RemotePeerConfig) int {
	if a == nil || b == nil {
		return boolCmp(a == nil, b == nil)
	}
	return cmp.Compare(a.WgPubKey, b.WgPubKey)
}

func cmpRoute(a, b *proto.Route) int {
	if a == nil || b == nil {
		return boolCmp(a == nil, b == nil)
	}
	if c := cmp.Compare(a.ID, b.ID); c != 0 {
		return c
	}
	if c := cmp.Compare(a.NetID, b.NetID); c != 0 {
		return c
	}
	if c := cmp.Compare(a.Network, b.Network); c != 0 {
		return c
	}
	if c := cmp.Compare(a.Peer, b.Peer); c != 0 {
		return c
	}
	if c := cmp.Compare(a.Metric, b.Metric); c != 0 {
		return c
	}
	return slices.Compare(a.Domains, b.Domains)
}

func cmpFirewallRule(a, b *proto.FirewallRule) int {
	if a == nil || b == nil {
		return boolCmp(a == nil, b == nil)
	}
	if c := bytes.Compare(a.PolicyID, b.PolicyID); c != 0 {
		return c
	}
	if c := cmp.Compare(a.PeerIP, b.PeerIP); c != 0 { //nolint:staticcheck
		return c
	}
	if c := cmp.Compare(int32(a.Direction), int32(b.Direction)); c != 0 {
		return c
	}
	if c := cmp.Compare(int32(a.Action), int32(b.Action)); c != 0 {
		return c
	}
	if c := cmp.Compare(int32(a.Protocol), int32(b.Protocol)); c != 0 {
		return c
	}
	if c := cmp.Compare(a.Port, b.Port); c != 0 {
		return c
	}
	return cmp.Compare(portInfoKey(a.PortInfo), portInfoKey(b.PortInfo))
}

func cmpRouteFirewallRule(a, b *proto.RouteFirewallRule) int {
	if a == nil || b == nil {
		return boolCmp(a == nil, b == nil)
	}
	if c := bytes.Compare(a.PolicyID, b.PolicyID); c != 0 {
		return c
	}
	if c := cmp.Compare(a.RouteID, b.RouteID); c != 0 {
		return c
	}
	if c := cmp.Compare(a.Destination, b.Destination); c != 0 {
		return c
	}
	if c := cmp.Compare(int32(a.Protocol), int32(b.Protocol)); c != 0 {
		return c
	}
	if c := cmp.Compare(portInfoKey(a.PortInfo), portInfoKey(b.PortInfo)); c != 0 {
		return c
	}
	if c := cmp.Compare(int32(a.Action), int32(b.Action)); c != 0 {
		return c
	}
	if c := slices.Compare(a.Domains, b.Domains); c != 0 {
		return c
	}
	if c := slices.Compare(a.SourceRanges, b.SourceRanges); c != 0 {
		return c
	}
	if c := cmp.Compare(a.CustomProtocol, b.CustomProtocol); c != 0 {
		return c
	}
	return boolCmp(a.IsDynamic, b.IsDynamic)
}

func cmpForwardingRule(a, b *proto.ForwardingRule) int {
	if a == nil || b == nil {
		return boolCmp(a == nil, b == nil)
	}
	if c := cmp.Compare(int32(a.Protocol), int32(b.Protocol)); c != 0 {
		return c
	}
	return bytes.Compare(a.TranslatedAddress, b.TranslatedAddress)
}

func portInfoKey(pi *proto.PortInfo) string {
	if pi == nil {
		return ""
	}
	switch sel := pi.PortSelection.(type) {
	case *proto.PortInfo_Port:
		return "P" + strconv.FormatUint(uint64(sel.Port), 10)
	case *proto.PortInfo_Range_:
		if sel.Range == nil {
			return "R"
		}
		return "R" + strconv.FormatUint(uint64(sel.Range.Start), 10) + "-" + strconv.FormatUint(uint64(sel.Range.End), 10)
	}
	return ""
}
