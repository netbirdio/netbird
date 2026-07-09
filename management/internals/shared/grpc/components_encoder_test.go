package grpc

import (
	"bytes"
	"cmp"
	"net"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	goproto "google.golang.org/protobuf/proto"

	nbdns "github.com/netbirdio/netbird/dns"
	resourceTypes "github.com/netbirdio/netbird/management/server/networks/resources/types"
	routerTypes "github.com/netbirdio/netbird/management/server/networks/routers/types"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/types"
	nbroute "github.com/netbirdio/netbird/route"
	"github.com/netbirdio/netbird/shared/management/proto"
)

const testWgKeyA = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopq="
const testWgKeyB = "BBCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopq="
const testWgKeyC = "CBCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopq="

// canonicalize rewrites a NetworkMapComponentsFull in place into a canonical
// form: peers reordered by wg_pub_key, with the rest of the message rewritten
// to reference the new peer indexes. Groups, policies, and router indexes are
// also sorted. After canonicalize, two envelopes built from the same logical
// input compare byte-equal via proto.Equal.
//
// This lives on the test side — the encoder itself emits in map-iteration
// order. Test-side normalization is the contract for "two encodes are
// equivalent".
func canonicalize(full *proto.NetworkMapComponentsFull) {
	if full == nil {
		return
	}

	type peerEntry struct {
		peer   *proto.PeerCompact
		oldIdx uint32
	}
	entries := make([]peerEntry, len(full.Peers))
	for i, p := range full.Peers {
		entries[i] = peerEntry{peer: p, oldIdx: uint32(i)}
	}
	// DnsLabel is unique per peer; it tiebreaks on equal WgPubKey (e.g. both
	// nil from malformed keys, or both empty for placeholders).
	slices.SortFunc(entries, func(a, b peerEntry) int {
		if c := bytes.Compare(a.peer.WgPubKey, b.peer.WgPubKey); c != 0 {
			return c
		}
		return cmp.Compare(a.peer.DnsLabel, b.peer.DnsLabel)
	})

	remap := make(map[uint32]uint32, len(entries))
	newPeers := make([]*proto.PeerCompact, len(entries))
	for newIdx, e := range entries {
		remap[e.oldIdx] = uint32(newIdx)
		newPeers[newIdx] = e.peer
	}
	full.Peers = newPeers

	full.RouterPeerIndexes = remapAndSort(full.RouterPeerIndexes, remap)
	for _, g := range full.Groups {
		g.PeerIndexes = remapAndSort(g.PeerIndexes, remap)
	}
	slices.SortFunc(full.Groups, func(a, b *proto.GroupCompact) int { return cmp.Compare(a.Id, b.Id) })

	for _, r := range full.Routes {
		if r.PeerIndexSet {
			if newIdx, ok := remap[r.PeerIndex]; ok {
				r.PeerIndex = newIdx
			}
		}
		slices.Sort(r.GroupIds)
		slices.Sort(r.AccessControlGroupIds)
		slices.Sort(r.PeerGroupIds)
	}
	slices.SortFunc(full.Routes, func(a, b *proto.RouteRaw) int { return cmp.Compare(a.Id, b.Id) })

	for _, list := range full.RoutersMap {
		for _, entry := range list.Entries {
			if entry.PeerIndexSet {
				if newIdx, ok := remap[entry.PeerIndex]; ok {
					entry.PeerIndex = newIdx
				}
			}
			slices.Sort(entry.PeerGroupIds)
		}
		slices.SortFunc(list.Entries, func(a, b *proto.NetworkRouterEntry) int { return cmp.Compare(a.Id, b.Id) })
	}

	for _, set := range full.PostureFailedPeers {
		set.PeerIndexes = remapAndSort(set.PeerIndexes, remap)
	}

	for _, p := range full.Policies {
		slices.Sort(p.SourceGroupIds)
		slices.Sort(p.DestinationGroupIds)
	}
	// Sort policies by (Id, source_group_ids, destination_group_ids) so that
	// multiple PolicyCompact entries sharing the same Id (one per rule, when
	// a Policy has multiple rules) still get a deterministic order. After
	// sorting we remap indexes in ResourcePoliciesMap.
	policyOldOrder := make(map[*proto.PolicyCompact]uint32, len(full.Policies))
	for i, p := range full.Policies {
		policyOldOrder[p] = uint32(i)
	}
	slices.SortFunc(full.Policies, func(a, b *proto.PolicyCompact) int {
		if c := cmp.Compare(a.Id, b.Id); c != 0 {
			return c
		}
		if c := slices.Compare(a.SourceGroupIds, b.SourceGroupIds); c != 0 {
			return c
		}
		return slices.Compare(a.DestinationGroupIds, b.DestinationGroupIds)
	})
	policyRemap := make(map[uint32]uint32, len(full.Policies))
	for newIdx, p := range full.Policies {
		policyRemap[policyOldOrder[p]] = uint32(newIdx)
	}
	for _, idxs := range full.ResourcePoliciesMap {
		slices.Sort(idxs.Ids)
	}
	for _, list := range full.GroupIdToUserIds {
		slices.Sort(list.UserIds)
	}
	slices.Sort(full.AllowedUserIds)
}

func remapAndSort(idxs []uint32, remap map[uint32]uint32) []uint32 {
	out := make([]uint32, 0, len(idxs))
	for _, i := range idxs {
		if newIdx, ok := remap[i]; ok {
			out = append(out, newIdx)
		}
	}
	slices.Sort(out)
	return out
}

// envelopesEquivalent decodes both envelopes, canonicalizes them, and reports
// whether they're proto.Equal. Use instead of byte-comparing marshaled output:
// the encoder is intentionally non-deterministic.
func envelopesEquivalent(a, b *proto.NetworkMapEnvelope) bool {
	canonicalize(a.GetFull())
	canonicalize(b.GetFull())
	return goproto.Equal(a, b)
}

func newTestComponents() *types.NetworkMapComponents {
	peerA := &nbpeer.Peer{
		ID:       "peer-a",
		Key:      testWgKeyA,
		IP:       netip.AddrFrom4([4]byte{100, 64, 0, 1}),
		DNSLabel: "peera",
		SSHKey:   "ssh-a",
		Status:   &nbpeer.PeerStatus{Connected: true, LastSeen: time.Now()},
		Meta:     nbpeer.PeerSystemMeta{WtVersion: "0.40.0"},
	}
	peerB := &nbpeer.Peer{
		ID:       "peer-b",
		Key:      testWgKeyB,
		IP:       netip.AddrFrom4([4]byte{100, 64, 0, 2}),
		IPv6:     netip.AddrFrom16([16]byte{0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}),
		DNSLabel: "peerb",
		Meta:     nbpeer.PeerSystemMeta{WtVersion: "0.25.0"},
	}
	peerC := &nbpeer.Peer{
		ID:       "peer-c",
		Key:      testWgKeyC,
		IP:       netip.AddrFrom4([4]byte{100, 64, 0, 3}),
		DNSLabel: "peerc",
		Meta:     nbpeer.PeerSystemMeta{WtVersion: "0.40.0"},
	}

	return &types.NetworkMapComponents{
		PeerID: "peer-a",
		Network: &types.Network{
			Identifier: "net-test",
			Net:        net.IPNet{IP: net.IP{100, 64, 0, 0}, Mask: net.CIDRMask(10, 32)},
			Serial:     7,
		},
		AccountSettings: &types.AccountSettingsInfo{
			PeerLoginExpirationEnabled: true,
			PeerLoginExpiration:        2 * time.Hour,
		},
		Peers: map[string]*nbpeer.Peer{
			"peer-a": peerA,
			"peer-b": peerB,
			"peer-c": peerC,
		},
		Groups: map[string]*types.Group{
			"group-src": {ID: "group-src", PublicID: "1", Name: "Src", Peers: []string{"peer-a"}},
			"group-dst": {ID: "group-dst", PublicID: "2", Name: "Dst", Peers: []string{"peer-b", "peer-c"}},
		},
		Policies: []*types.Policy{
			{
				ID:       "pol-1",
				PublicID: "10",
				Enabled:  true,
				Rules: []*types.PolicyRule{{
					ID: "rule-1", Enabled: true, Action: types.PolicyTrafficActionAccept,
					Protocol: types.PolicyRuleProtocolTCP, Bidirectional: true,
					Ports:        []string{"22", "80"},
					PortRanges:   []types.RulePortRange{{Start: 8000, End: 8100}},
					Sources:      []string{"group-src"},
					Destinations: []string{"group-dst"},
				}},
			},
		},
		RouterPeers: map[string]*nbpeer.Peer{"peer-c": peerC},
	}
}

func TestEncodeNetworkMapEnvelope_Basic(t *testing.T) {
	c := newTestComponents()
	env := EncodeNetworkMapEnvelope(ComponentsEnvelopeInput{
		Components: c,
		DNSDomain:  "netbird.cloud",
	})

	require.NotNil(t, env)
	full := env.GetFull()
	require.NotNil(t, full, "envelope must contain Full payload")

	assert.EqualValues(t, 7, full.Serial)
	assert.Equal(t, "netbird.cloud", full.DnsDomain)

	require.NotNil(t, full.Network)
	assert.Equal(t, "net-test", full.Network.Identifier)
	assert.Equal(t, "100.64.0.0/10", full.Network.NetCidr)

	require.NotNil(t, full.AccountSettings)
	assert.True(t, full.AccountSettings.PeerLoginExpirationEnabled)
	assert.EqualValues(t, (2 * time.Hour).Nanoseconds(), full.AccountSettings.PeerLoginExpirationNs)

	require.Len(t, full.Peers, 3)
	byLabel := map[string]*proto.PeerCompact{}
	for _, p := range full.Peers {
		assert.Len(t, p.WgPubKey, 32, "wg key must be raw 32 bytes")
		assert.Len(t, p.Ip, 4, "ipv4 must be raw 4 bytes")
		byLabel[p.DnsLabel] = p
	}
	assert.Len(t, byLabel["peerb"].Ipv6, 16, "peer-b has ipv6 → 16 bytes")
}

func TestEncodeNetworkMapEnvelope_RepeatEncodesEquivalent(t *testing.T) {
	c := newTestComponents()

	expected := EncodeNetworkMapEnvelope(ComponentsEnvelopeInput{Components: c})

	// Hammer it 100 times — Go map iteration is randomized per call, so each
	// run produces different wire bytes, but the canonicalized form must
	// match.
	for i := 0; i < 100; i++ {
		got := EncodeNetworkMapEnvelope(ComponentsEnvelopeInput{Components: c})
		require.True(t, envelopesEquivalent(expected, got),
			"encode #%d must be semantically equivalent to first encode", i)
	}
}

func TestEncodeNetworkMapEnvelope_ConcurrentEncodesEquivalent(t *testing.T) {
	c := newTestComponents()

	expected := EncodeNetworkMapEnvelope(ComponentsEnvelopeInput{Components: c})

	const goroutines = 50
	var wg sync.WaitGroup
	wg.Add(goroutines)
	results := make([]*proto.NetworkMapEnvelope, goroutines)
	for i := 0; i < goroutines; i++ {
		i := i
		go func() {
			defer wg.Done()
			results[i] = EncodeNetworkMapEnvelope(ComponentsEnvelopeInput{Components: c})
		}()
	}
	wg.Wait()

	for i, got := range results {
		require.NotNil(t, got, "goroutine %d returned nil", i)
		require.True(t, envelopesEquivalent(expected, got),
			"goroutine %d produced inequivalent envelope", i)
	}
}

func TestEncodeNetworkMapEnvelope_GroupsByAccountPublicId(t *testing.T) {
	c := newTestComponents()

	full := EncodeNetworkMapEnvelope(ComponentsEnvelopeInput{Components: c}).GetFull()

	require.Len(t, full.Groups, 2)

	groupByID := map[string]*proto.GroupCompact{}
	for _, g := range full.Groups {
		groupByID[g.Id] = g
	}
	require.Contains(t, groupByID, "1")
	require.Contains(t, groupByID, "2")
	assert.Equal(t, "Src", groupByID["1"].Name)
	assert.Equal(t, "Dst", groupByID["2"].Name)
	assert.Len(t, groupByID["1"].PeerIndexes, 1)
	assert.Len(t, groupByID["2"].PeerIndexes, 2)
}

func TestEncodeNetworkMapEnvelope_PolicyExpansion(t *testing.T) {
	c := newTestComponents()

	full := EncodeNetworkMapEnvelope(ComponentsEnvelopeInput{Components: c}).GetFull()

	require.Len(t, full.Policies, 1)
	pc := full.Policies[0]
	assert.EqualValues(t, "10", pc.Id)
	assert.Equal(t, proto.RuleAction_ACCEPT, pc.Action)
	assert.Equal(t, proto.RuleProtocol_TCP, pc.Protocol)
	assert.True(t, pc.Bidirectional)
	assert.Equal(t, []uint32{22, 80}, pc.Ports)
	require.Len(t, pc.PortRanges, 1)
	assert.EqualValues(t, 8000, pc.PortRanges[0].Start)
	assert.EqualValues(t, 8100, pc.PortRanges[0].End)
	assert.Equal(t, []string{"1"}, pc.SourceGroupIds)
	assert.Equal(t, []string{"2"}, pc.DestinationGroupIds)
}

func TestEncodeNetworkMapEnvelope_RouterIndexes(t *testing.T) {
	c := newTestComponents()

	full := EncodeNetworkMapEnvelope(ComponentsEnvelopeInput{Components: c}).GetFull()

	require.Len(t, full.RouterPeerIndexes, 1)
	idx := full.RouterPeerIndexes[0]
	require.Less(t, int(idx), len(full.Peers))
	assert.Equal(t, "peerc", full.Peers[idx].DnsLabel)
}

func TestEncodeNetworkMapEnvelope_DisabledPolicySkipped(t *testing.T) {
	c := newTestComponents()
	c.Policies[0].Enabled = false

	full := EncodeNetworkMapEnvelope(ComponentsEnvelopeInput{Components: c}).GetFull()

	assert.Empty(t, full.Policies)
}

func TestEncodeNetworkMapEnvelope_TwoPeersSameMalformedKey(t *testing.T) {
	// Both peers have nil WgPubKey after decode; canonicalize must still
	// produce a stable order using DnsLabel as a tiebreaker, so 100 encodes
	// canonicalize identically.
	c := newTestComponents()
	c.Peers["peer-a"].Key = "garbage-a-!!!"
	c.Peers["peer-b"].Key = "garbage-b-!!!"

	expected := EncodeNetworkMapEnvelope(ComponentsEnvelopeInput{Components: c})
	for i := 0; i < 100; i++ {
		got := EncodeNetworkMapEnvelope(ComponentsEnvelopeInput{Components: c})
		require.True(t, envelopesEquivalent(expected, got),
			"encode #%d with two same-key peers must canonicalize equivalently", i)
	}
}

func TestEncodeNetworkMapEnvelope_MalformedWgKey(t *testing.T) {
	c := newTestComponents()
	c.Peers["peer-a"].Key = "not-base64-!!!"

	full := EncodeNetworkMapEnvelope(ComponentsEnvelopeInput{Components: c}).GetFull()

	require.Len(t, full.Peers, 3)

	var byLabel = map[string]*proto.PeerCompact{}
	for _, p := range full.Peers {
		byLabel[p.DnsLabel] = p
	}
	assert.Nil(t, byLabel["peera"].WgPubKey, "peer with malformed key encodes nil WgPubKey")
	assert.Len(t, byLabel["peerb"].WgPubKey, 32, "other peers retain their key")
}

func TestEncodeNetworkMapEnvelope_IPv6OnlyPeer(t *testing.T) {
	c := newTestComponents()
	v6Only := &nbpeer.Peer{
		ID:       "peer-v6",
		Key:      testWgKeyA,
		IPv6:     netip.AddrFrom16([16]byte{0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9}),
		DNSLabel: "peerv6",
		Meta:     nbpeer.PeerSystemMeta{WtVersion: "0.40.0"},
	}
	c.Peers["peer-v6"] = v6Only

	full := EncodeNetworkMapEnvelope(ComponentsEnvelopeInput{Components: c}).GetFull()

	var found *proto.PeerCompact
	for _, p := range full.Peers {
		if p.DnsLabel == "peerv6" {
			found = p
		}
	}
	require.NotNil(t, found, "ipv6-only peer must be present")
	assert.Empty(t, found.Ip, "no IPv4 address → empty Ip")
	assert.Len(t, found.Ipv6, 16)
}

func TestEncodeNetworkMapEnvelope_PeerWithoutIP(t *testing.T) {
	c := newTestComponents()
	c.Peers["peer-noip"] = &nbpeer.Peer{
		ID:       "peer-noip",
		Key:      testWgKeyA,
		DNSLabel: "peernoip",
		Meta:     nbpeer.PeerSystemMeta{WtVersion: "0.40.0"},
	}

	full := EncodeNetworkMapEnvelope(ComponentsEnvelopeInput{Components: c}).GetFull()

	var found *proto.PeerCompact
	for _, p := range full.Peers {
		if p.DnsLabel == "peernoip" {
			found = p
		}
	}
	require.NotNil(t, found)
	assert.Empty(t, found.Ip)
	assert.Empty(t, found.Ipv6)
}

func TestEncodeNetworkMapEnvelope_EmptyInput(t *testing.T) {
	c := &types.NetworkMapComponents{
		Network: &types.Network{Identifier: "x", Net: net.IPNet{IP: net.IP{100, 64, 0, 0}, Mask: net.CIDRMask(10, 32)}},
	}

	env := EncodeNetworkMapEnvelope(ComponentsEnvelopeInput{Components: c})

	full := env.GetFull()
	require.NotNil(t, full)
	assert.Empty(t, full.Peers)
	assert.Empty(t, full.Groups)
	assert.Empty(t, full.Policies)
	assert.Empty(t, full.RouterPeerIndexes)
	require.NotNil(t, full.AccountSettings, "AccountSettingsCompact must always be emitted (client dereferences it unconditionally)")
}

func TestEncodeNetworkMapEnvelope_PeerLoginExpirationFields(t *testing.T) {
	c := newTestComponents()
	now := time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC)
	c.Peers["peer-a"].UserID = "user-1"
	c.Peers["peer-a"].LoginExpirationEnabled = true
	c.Peers["peer-a"].LastLogin = &now

	full := EncodeNetworkMapEnvelope(ComponentsEnvelopeInput{Components: c}).GetFull()

	var pa *proto.PeerCompact
	for _, p := range full.Peers {
		if p.DnsLabel == "peera" {
			pa = p
		}
	}
	require.NotNil(t, pa)
	assert.True(t, pa.AddedWithSsoLogin)
	assert.True(t, pa.LoginExpirationEnabled)
	assert.Equal(t, now.UnixNano(), pa.LastLoginUnixNano)

	// peer-b has no UserID and no LastLogin → all fields zero-value.
	var pb *proto.PeerCompact
	for _, p := range full.Peers {
		if p.DnsLabel == "peerb" {
			pb = p
		}
	}
	require.NotNil(t, pb)
	assert.False(t, pb.AddedWithSsoLogin)
	assert.False(t, pb.LoginExpirationEnabled)
	assert.Zero(t, pb.LastLoginUnixNano)
}

func TestEncodeNetworkMapEnvelope_RoutesRoundTrip(t *testing.T) {
	c := newTestComponents()
	c.Routes = []*nbroute.Route{
		{
			ID:                  "route-peer",
			PublicID:            "100",
			NetID:               "net-A",
			Description:         "via peer-c",
			Network:             netip.MustParsePrefix("10.0.0.0/16"),
			Peer:                "peer-c", // peer ID, not WG key
			Groups:              []string{"group-src"},
			AccessControlGroups: []string{"group-dst"},
			Enabled:             true,
		},
		{
			ID:         "route-peergroup",
			PublicID:   "101",
			NetID:      "net-B",
			Network:    netip.MustParsePrefix("10.1.0.0/16"),
			PeerGroups: []string{"group-src", "group-dst"},
			Enabled:    true,
		},
	}

	full := EncodeNetworkMapEnvelope(ComponentsEnvelopeInput{Components: c}).GetFull()

	require.Len(t, full.Routes, 2)
	byNetID := map[string]*proto.RouteRaw{}
	for _, r := range full.Routes {
		byNetID[r.NetId] = r
	}

	r1 := byNetID["net-A"]
	require.NotNil(t, r1)
	assert.True(t, r1.PeerIndexSet, "route with peer must set peer_index_set")
	require.Less(t, int(r1.PeerIndex), len(full.Peers))
	assert.Equal(t, "peerc", full.Peers[r1.PeerIndex].DnsLabel)
	assert.Equal(t, []string{"1"}, r1.GroupIds, "group-src has AccountSeqID 1")
	assert.Equal(t, []string{"2"}, r1.AccessControlGroupIds, "group-dst has AccountSeqID 2")
	assert.Empty(t, r1.PeerGroupIds)

	r2 := byNetID["net-B"]
	require.NotNil(t, r2)
	assert.False(t, r2.PeerIndexSet, "route with peer_groups must NOT set peer_index_set")
	assert.ElementsMatch(t, []string{"1", "2"}, r2.PeerGroupIds)
}

func TestEncodeNetworkMapEnvelope_RouteWithMissingPeerLeavesIndexUnset(t *testing.T) {
	c := newTestComponents()
	c.Routes = []*nbroute.Route{{
		ID:       "route-x",
		PublicID: "100",
		Peer:     "peer-not-in-components",
		Network:  netip.MustParsePrefix("10.0.0.0/16"),
		Enabled:  true,
	}}

	full := EncodeNetworkMapEnvelope(ComponentsEnvelopeInput{Components: c}).GetFull()

	require.Len(t, full.Routes, 1)
	assert.False(t, full.Routes[0].PeerIndexSet,
		"missing peer reference must not pretend to point at peer index 0")
}

func TestEncodeNetworkMapEnvelope_ResourceOnlyPolicyShippedAndIndexed(t *testing.T) {
	c := newTestComponents()
	// Policy that exists ONLY in ResourcePoliciesMap, not in c.Policies. This
	// is the I1 case — without unionPolicies the encoder would silently
	// drop it from the wire.
	resourceOnlyPolicy := &types.Policy{
		ID: "pol-resource", PublicID: "99", Enabled: true,
		Rules: []*types.PolicyRule{{
			ID: "rule-r", Enabled: true, Action: types.PolicyTrafficActionAccept,
			Protocol:     types.PolicyRuleProtocolTCP,
			Sources:      []string{"group-src"},
			Destinations: []string{"group-dst"},
		}},
	}
	c.ResourcePoliciesMap = map[string][]*types.Policy{
		"resource-x": {c.Policies[0], resourceOnlyPolicy}, // shared + resource-only
	}
	// Resource must appear in components.NetworkResources with a seq id —
	// encoder uses that to translate the xid map key to uint32.
	c.NetworkResources = []*resourceTypes.NetworkResource{
		{ID: "resource-x", PublicID: "77", Name: "res-x", Enabled: true},
	}

	full := EncodeNetworkMapEnvelope(ComponentsEnvelopeInput{Components: c}).GetFull()

	require.Len(t, full.Policies, 2, "encoded policies must include both peer-traffic and resource-only")

	policyByID := map[string]*proto.PolicyCompact{}
	policyIds := make([]string, 0)
	for _, p := range full.Policies {
		policyByID[p.Id] = p
		policyIds = append(policyIds, p.Id)
	}
	require.Contains(t, policyByID, "10", "original peer-traffic policy id 10")
	require.Contains(t, policyByID, "99", "resource-only policy id 99")

	require.Contains(t, full.ResourcePoliciesMap, "77")
	ids := full.ResourcePoliciesMap["77"].Ids
	require.Len(t, ids, 2)
	assert.ElementsMatch(t, policyIds, ids,
		"resource policies map must reference both wire policy indexes")
}

func TestEncodeNetworkMapEnvelope_NameServerGroups(t *testing.T) {
	c := newTestComponents()
	c.NameServerGroups = []*nbdns.NameServerGroup{{
		ID: "nsg-1", PublicID: "50", Name: "Main", Description: "primary",
		NameServers: []nbdns.NameServer{{
			IP: netip.MustParseAddr("8.8.8.8"), NSType: nbdns.UDPNameServerType, Port: 53,
		}},
		Groups:  []string{"group-src", "group-not-persisted"},
		Primary: true, Enabled: true,
		Domains: []string{"corp.example"},
	}}

	full := EncodeNetworkMapEnvelope(ComponentsEnvelopeInput{Components: c}).GetFull()

	require.Len(t, full.NameserverGroups, 1)
	nsg := full.NameserverGroups[0]
	assert.EqualValues(t, "50", nsg.Id)
	assert.Equal(t, "Main", nsg.Name)
	assert.True(t, nsg.Primary)
	require.Len(t, nsg.Nameservers, 1)
	assert.Equal(t, "8.8.8.8", nsg.Nameservers[0].IP)
	assert.Equal(t, []string{"1"}, nsg.GroupIds)
}

func TestEncodeNetworkMapEnvelope_PostureFailedPeers(t *testing.T) {
	c := newTestComponents()
	c.PostureCheckXIDToPublicID = map[string]string{"check-1": "33"}
	c.PostureFailedPeers = map[string]map[string]struct{}{
		"check-1": {
			"peer-a":              {},
			"peer-b":              {},
			"peer-not-in-account": {},
		},
	}

	full := EncodeNetworkMapEnvelope(ComponentsEnvelopeInput{Components: c}).GetFull()

	require.Contains(t, full.PostureFailedPeers, "33")
	idxs := full.PostureFailedPeers["33"].PeerIndexes
	assert.Len(t, idxs, 2, "missing peer is silently dropped (filterPostureFailedPeers guarantees presence in real data)")
}

func TestEncodeNetworkMapEnvelope_RoutersMap(t *testing.T) {
	c := newTestComponents()
	c.NetworkXIDToPublicID = map[string]string{"net-1": "5"}
	c.RoutersMap = map[string]map[string]*routerTypes.NetworkRouter{
		"net-1": {
			"peer-c": {
				ID: "router-1", PublicID: "200",
				Peer: "peer-c", Masquerade: true, Metric: 10, Enabled: true,
			},
		},
	}

	full := EncodeNetworkMapEnvelope(ComponentsEnvelopeInput{Components: c}).GetFull()

	require.Contains(t, full.RoutersMap, "5")
	entries := full.RoutersMap["5"].Entries
	require.Len(t, entries, 1)
	e := entries[0]
	assert.EqualValues(t, "200", e.Id)
	assert.True(t, e.PeerIndexSet)
	require.Less(t, int(e.PeerIndex), len(full.Peers))
	assert.Equal(t, "peerc", full.Peers[e.PeerIndex].DnsLabel)
	assert.True(t, e.Masquerade)
	assert.EqualValues(t, 10, e.Metric)
	assert.True(t, e.Enabled)
}

func TestEncodeNetworkMapEnvelope_RouterPeerNotInComponentsPeers(t *testing.T) {
	// Router peer in c.RouterPeers but NOT in c.Peers (validation may have
	// filtered it). indexRouterPeers runs before encodeRoutersMap, so the
	// peer_index reference must still resolve.
	c := newTestComponents()
	delete(c.Peers, "peer-c")
	routerPeer := &nbpeer.Peer{
		ID: "peer-c", Key: testWgKeyC, IP: netip.AddrFrom4([4]byte{100, 64, 0, 3}),
		DNSLabel: "peerc", Meta: nbpeer.PeerSystemMeta{WtVersion: "0.40.0"},
	}
	c.RouterPeers = map[string]*nbpeer.Peer{"peer-c": routerPeer}
	c.NetworkXIDToPublicID = map[string]string{"net-1": "5"}
	c.RoutersMap = map[string]map[string]*routerTypes.NetworkRouter{
		"net-1": {"peer-c": {ID: "r-1", PublicID: "1", Peer: "peer-c", Enabled: true}},
	}

	full := EncodeNetworkMapEnvelope(ComponentsEnvelopeInput{Components: c}).GetFull()

	require.Contains(t, full.RoutersMap, "5")
	require.Len(t, full.RoutersMap["5"].Entries, 1)
	e := full.RoutersMap["5"].Entries[0]
	assert.True(t, e.PeerIndexSet, "router peer must be indexed even when not in c.Peers")
}

func TestEncodeNetworkMapEnvelope_GroupIDToUserIDs(t *testing.T) {
	c := newTestComponents()
	c.GroupIDToUserIDs = map[string][]string{
		"group-src":     {"user-1", "user-2"},
		"group-missing": {"user-4"}, // group not in components → drop
	}

	full := EncodeNetworkMapEnvelope(ComponentsEnvelopeInput{Components: c}).GetFull()

	require.Len(t, full.GroupIdToUserIds, 1, "only present groups survive")
	require.Contains(t, full.GroupIdToUserIds, "1")
	assert.ElementsMatch(t, []string{"user-1", "user-2"}, full.GroupIdToUserIds["1"].UserIds)
}

func TestToProxyPatch_EmptyInputReturnsNil(t *testing.T) {
	assert.Nil(t, toProxyPatch(nil, "netbird.cloud", false, false))
	assert.Nil(t, toProxyPatch(&types.NetworkMap{}, "netbird.cloud", false, false),
		"empty NetworkMap (no peers, rules, routes etc) → nil patch so proto3 omits the field")
}

func TestToProxyPatch_PopulatesAllFields(t *testing.T) {
	nm := &types.NetworkMap{
		Peers: []*nbpeer.Peer{{
			ID: "ext-peer", Key: testWgKeyA, IP: netip.AddrFrom4([4]byte{100, 64, 0, 9}),
			DNSLabel: "extpeer", Meta: nbpeer.PeerSystemMeta{WtVersion: "0.40.0"},
		}},
		FirewallRules: []*types.FirewallRule{{
			PeerIP: "100.64.0.9", Action: "accept", Direction: 0, Protocol: "tcp",
		}},
	}

	patch := toProxyPatch(nm, "netbird.cloud", false, false)

	require.NotNil(t, patch)
	assert.Len(t, patch.Peers, 1)
	assert.Len(t, patch.FirewallRules, 1)
}

// TestEncodeNetworkMapEnvelope_ProxyPatchPropagated covers the ProxyPatch
// pass-through in both encoder branches (normal path + nil-Components
// graceful-degrade). Guards against a regression that drops `ProxyPatch:`
// from one of the envelope struct literals.
func TestEncodeNetworkMapEnvelope_ProxyPatchPropagated(t *testing.T) {
	patch := &proto.ProxyPatch{
		ForwardingRules: []*proto.ForwardingRule{{
			Protocol:          proto.RuleProtocol_TCP,
			DestinationPort:   &proto.PortInfo{PortSelection: &proto.PortInfo_Port{Port: 80}},
			TranslatedAddress: net.IPv4(10, 0, 0, 1).To4(),
			TranslatedPort:    &proto.PortInfo{PortSelection: &proto.PortInfo_Port{Port: 8080}},
		}},
	}

	t.Run("normal_path", func(t *testing.T) {
		c := newTestComponents()
		full := EncodeNetworkMapEnvelope(ComponentsEnvelopeInput{
			Components: c,
			ProxyPatch: patch,
		}).GetFull()

		require.NotNil(t, full.ProxyPatch, "ProxyPatch must propagate through the normal encode path")
		assert.Len(t, full.ProxyPatch.ForwardingRules, 1)
	})

	t.Run("nil_components_graceful_degrade", func(t *testing.T) {
		full := EncodeNetworkMapEnvelope(ComponentsEnvelopeInput{
			Components: nil,
			ProxyPatch: patch,
		}).GetFull()

		require.NotNil(t, full.ProxyPatch, "ProxyPatch must propagate through the nil-Components branch too")
		assert.Len(t, full.ProxyPatch.ForwardingRules, 1)
	})
}

func TestEncodeNetworkMapEnvelope_NilComponentsGracefulDegrade(t *testing.T) {
	// nil Components → minimal envelope, no crash. Matches the legacy
	// behaviour for missing/unvalidated peers.
	env := EncodeNetworkMapEnvelope(ComponentsEnvelopeInput{
		Components: nil,
		DNSDomain:  "netbird.cloud",
	})

	require.NotNil(t, env)
	full := env.GetFull()
	require.NotNil(t, full)
	require.NotNil(t, full.AccountSettings, "AccountSettings must always be non-nil")
	assert.Equal(t, "netbird.cloud", full.DnsDomain)
	assert.Empty(t, full.Peers)
	assert.Empty(t, full.Policies)
}

func TestEncodeNetworkMapEnvelope_AccountSettingsAlwaysEmitted(t *testing.T) {
	c := &types.NetworkMapComponents{
		Network: &types.Network{Identifier: "x", Net: net.IPNet{IP: net.IP{100, 64, 0, 0}, Mask: net.CIDRMask(10, 32)}},
		// AccountSettings deliberately nil
	}

	full := EncodeNetworkMapEnvelope(ComponentsEnvelopeInput{Components: c}).GetFull()

	require.NotNil(t, full.AccountSettings, "client dereferences AccountSettings unconditionally during Calculate(); a nil here would crash the receiver")
	assert.False(t, full.AccountSettings.PeerLoginExpirationEnabled)
	assert.Zero(t, full.AccountSettings.PeerLoginExpirationNs)
}
