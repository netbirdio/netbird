package networkmap_test

import (
	"context"
	"fmt"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/shared/management/networkmap"
	"github.com/netbirdio/netbird/shared/management/networkmap/nmdata"
	nbtypes "github.com/netbirdio/netbird/shared/management/types"
)

const (
	targetID          = "peer-target"
	postureMinVersion = "0.30.0"
	passingVersion    = "1.0.0"
	failingVersion    = "0.1.0"
)

func newPeer(id string, hostNum byte) *nmdata.Peer {
	return &nmdata.Peer{
		ID:       id,
		Key:      "key-" + id,
		IP:       netip.AddrFrom4([4]byte{100, 64, 0, hostNum}),
		DNSLabel: id,
		Meta:     nmdata.PeerSystemMeta{WtVersion: passingVersion},
	}
}

func newNMD(peers ...*nmdata.Peer) *networkmap.NetworkMapData {
	nmd := &networkmap.NetworkMapData{
		Peers:           make(map[string]*nmdata.Peer),
		Groups:          make(map[string]*nmdata.Group),
		ValidatedPeers:  make(map[string]struct{}),
		Network:         &nmdata.Network{Identifier: "network-1", Serial: 7},
		AccountSettings: &nmdata.AccountSettingsInfo{},
		DNSSettings:     &nmdata.DNSSettings{},
	}
	for _, p := range peers {
		nmd.Peers[p.ID] = p
		nmd.ValidatedPeers[p.ID] = struct{}{}
	}
	return nmd
}

func addGroup(nmd *networkmap.NetworkMapData, id string, peerIDs ...string) *nmdata.Group {
	g := &nmdata.Group{ID: id, Name: id, Peers: peerIDs}
	nmd.Groups[id] = g
	return g
}

func newRule(sources, destinations []string) *nmdata.PolicyRule {
	return &nmdata.PolicyRule{
		Enabled:       true,
		Action:        string(nbtypes.PolicyTrafficActionAccept),
		Protocol:      string(nbtypes.PolicyRuleProtocolTCP),
		Bidirectional: true,
		Sources:       sources,
		Destinations:  destinations,
	}
}

func newPolicy(id string, rules ...*nmdata.PolicyRule) *nmdata.Policy {
	for i, r := range rules {
		if r.ID == "" {
			r.ID = fmt.Sprintf("%s-rule-%d", id, i)
		}
		r.PolicyID = id
	}
	return &nmdata.Policy{ID: id, Enabled: true, Rules: rules}
}

func addVersionCheck(nmd *networkmap.NetworkMapData, id, minVersion string) {
	if nmd.PostureChecks == nil {
		nmd.PostureChecks = make(map[string]*nmdata.PostureChecks)
	}
	nmd.PostureChecks[id] = &nmdata.PostureChecks{
		ID:     id,
		Checks: nmdata.ChecksDefinition{NBVersionCheck: &nmdata.NBVersionCheck{MinVersion: minVersion}},
	}
}

func compute(nmd *networkmap.NetworkMapData, peerID string) *nbtypes.NetworkMapComponents {
	return nmd.GetPeerNetworkMapComponents(peerID, nmdata.CustomZone{})
}

func peerIDSet(peers map[string]*nmdata.Peer) []string {
	ids := make([]string, 0, len(peers))
	for id := range peers {
		ids = append(ids, id)
	}
	return ids
}

func policyIDs(policies []*nmdata.Policy) []string {
	ids := make([]string, 0, len(policies))
	for _, p := range policies {
		ids = append(ids, p.ID)
	}
	return ids
}

func groupIDSet(groups map[string]*nmdata.Group) []string {
	ids := make([]string, 0, len(groups))
	for id := range groups {
		ids = append(ids, id)
	}
	return ids
}

func TestGetPeerNetworkMapComponents_UnknownPeer(t *testing.T) {
	nmd := newNMD(newPeer("peer-a", 2))

	c := compute(nmd, "missing")

	require.True(t, c.IsEmpty())
	assert.Equal(t, "missing", c.PeerID)
	assert.Same(t, nmd.Network, c.Network)
	require.Contains(t, c.Peers, "missing")
	assert.Nil(t, c.Peers["missing"])
	assert.Len(t, c.Peers, 1)
	assert.Nil(t, c.AccountSettings)
	assert.Nil(t, c.Policies)
	assert.False(t, c.ForceRoutingPeerDNSResolution)
}

func TestGetPeerNetworkMapComponents_UnvalidatedPeer(t *testing.T) {
	target := newPeer(targetID, 1)
	nmd := newNMD(target)
	delete(nmd.ValidatedPeers, targetID)

	c := compute(nmd, targetID)

	require.True(t, c.IsEmpty())
	assert.Equal(t, targetID, c.PeerID)
	assert.Same(t, target, c.Peers[targetID])
	assert.Len(t, c.Peers, 1)
	assert.Nil(t, c.AccountSettings)
	assert.Nil(t, c.Groups)
}

// The forced-DNS flag must be computed even on the empty-components early
// exits, so an unknown or unvalidated proxy routing peer still starts its DNS
// forwarder.
func TestGetPeerNetworkMapComponents_EmptyComponentsKeepForcedDNSResolution(t *testing.T) {
	build := func() *networkmap.NetworkMapData {
		nmd := newNMD(newPeer("unval-router", 1))
		delete(nmd.ValidatedPeers, "unval-router")
		nmd.NetworkResources = []*nmdata.NetworkResource{
			{ID: "res-1", NetworkID: "net-1", Type: string(nbtypes.ResourceTypeDomain), Enabled: true},
		}
		nmd.ProxyTargetedDomainResourceIDs = map[string]struct{}{"res-1": {}}
		nmd.Routers = map[string]map[string]*nmdata.NetworkRouter{"net-1": {"ghost-router": {}, "unval-router": {}}}
		return nmd
	}

	t.Run("unknown peer", func(t *testing.T) {
		c := compute(build(), "ghost-router")
		require.True(t, c.IsEmpty())
		assert.True(t, c.ForceRoutingPeerDNSResolution)
	})

	t.Run("unvalidated peer", func(t *testing.T) {
		c := compute(build(), "unval-router")
		require.True(t, c.IsEmpty())
		assert.True(t, c.ForceRoutingPeerDNSResolution)
	})
}

func TestGetPeerNetworkMapComponents_ForceRoutingPeerDNSResolution(t *testing.T) {
	forced := func(mutate func(*networkmap.NetworkMapData)) bool {
		nmd := newNMD(newPeer(targetID, 1))
		nmd.NetworkResources = []*nmdata.NetworkResource{
			{ID: "res-1", NetworkID: "net-1", Type: string(nbtypes.ResourceTypeDomain), Enabled: true},
		}
		nmd.ProxyTargetedDomainResourceIDs = map[string]struct{}{"res-1": {}}
		nmd.Routers = map[string]map[string]*nmdata.NetworkRouter{"net-1": {targetID: {}}}
		if mutate != nil {
			mutate(nmd)
		}
		return compute(nmd, targetID).ForceRoutingPeerDNSResolution
	}

	t.Run("router of targeted domain resource is forced", func(t *testing.T) {
		assert.True(t, forced(nil))
	})
	t.Run("no proxy-targeted resources", func(t *testing.T) {
		assert.False(t, forced(func(nmd *networkmap.NetworkMapData) {
			nmd.ProxyTargetedDomainResourceIDs = nil
		}))
	})
	t.Run("resource disabled", func(t *testing.T) {
		assert.False(t, forced(func(nmd *networkmap.NetworkMapData) {
			nmd.NetworkResources[0].Enabled = false
		}))
	})
	t.Run("resource not a domain", func(t *testing.T) {
		assert.False(t, forced(func(nmd *networkmap.NetworkMapData) {
			nmd.NetworkResources[0].Type = string(nbtypes.ResourceTypeHost)
		}))
	})
	t.Run("resource not targeted", func(t *testing.T) {
		assert.False(t, forced(func(nmd *networkmap.NetworkMapData) {
			nmd.ProxyTargetedDomainResourceIDs = map[string]struct{}{"res-other": {}}
		}))
	})
	t.Run("peer not a router of the resource network", func(t *testing.T) {
		assert.False(t, forced(func(nmd *networkmap.NetworkMapData) {
			nmd.Routers = map[string]map[string]*nmdata.NetworkRouter{"net-1": {"someone-else": {}}}
		}))
	})
	t.Run("nil resource entry tolerated", func(t *testing.T) {
		assert.True(t, forced(func(nmd *networkmap.NetworkMapData) {
			nmd.NetworkResources = append([]*nmdata.NetworkResource{nil}, nmd.NetworkResources...)
		}))
	})
}

func TestGetPeerNetworkMapComponents_CoreFieldsPassThrough(t *testing.T) {
	target := newPeer(targetID, 1)
	nmd := newNMD(target)
	nmd.NetworkXIDToPublicID = map[string]string{"net-xid": "net-pub"}
	nmd.PostureCheckXIDToPublicID = map[string]string{"pc-xid": "pc-pub"}

	c := nmd.GetPeerNetworkMapComponents(targetID, nmdata.CustomZone{Domain: "acme.netbird.cloud."})

	require.False(t, c.IsEmpty())
	assert.Equal(t, targetID, c.PeerID)
	assert.Same(t, nmd.Network, c.Network)
	assert.Same(t, nmd.AccountSettings, c.AccountSettings)
	assert.Same(t, nmd.DNSSettings, c.DNSSettings)
	assert.Equal(t, "acme.netbird.cloud.", c.CustomZoneDomain)
	assert.Equal(t, nmd.NetworkXIDToPublicID, c.NetworkXIDToPublicID)
	assert.Equal(t, nmd.PostureCheckXIDToPublicID, c.PostureCheckXIDToPublicID)

	assert.Equal(t, map[string]*nmdata.Peer{targetID: target}, c.Peers)
	assert.Empty(t, c.Groups)
	assert.Empty(t, c.Policies)
	assert.Empty(t, c.Routes)
	assert.Empty(t, c.NameServerGroups)
	assert.Empty(t, c.NetworkResources)
	assert.Empty(t, c.ResourcePoliciesMap)
	assert.Empty(t, c.RoutersMap)
	assert.Empty(t, c.RouterPeers)
	assert.Empty(t, c.PostureFailedPeers)
	assert.Nil(t, c.AllDNSRecords)
	assert.Empty(t, c.AccountZones)
	assert.Nil(t, c.GroupIDToUserIDs)
	assert.Nil(t, c.AllowedUserIDs)
	assert.False(t, c.ForceRoutingPeerDNSResolution)
}

func TestGetPeerNetworkMapComponents_OwnGroupsTrimmedWithoutMutatingStore(t *testing.T) {
	target := newPeer(targetID, 1)
	bystander := newPeer("peer-bystander", 2)
	nmd := newNMD(target, bystander)
	stored := addGroup(nmd, "g-mixed", targetID, bystander.ID)

	c := compute(nmd, targetID)

	require.Contains(t, c.Groups, "g-mixed")
	assert.Equal(t, []string{targetID}, c.Groups["g-mixed"].Peers)
	assert.NotSame(t, stored, c.Groups["g-mixed"])
	assert.Equal(t, []string{targetID, bystander.ID}, stored.Peers)
}

func TestGetPeerNetworkMapComponents_PolicyRelevance(t *testing.T) {
	t.Run("peer in sources pulls destination peers and groups", func(t *testing.T) {
		target := newPeer(targetID, 1)
		srcSibling := newPeer("peer-src-sibling", 2)
		dst := newPeer("peer-dst", 3)
		nmd := newNMD(target, srcSibling, dst)
		addGroup(nmd, "g-src", targetID, srcSibling.ID)
		addGroup(nmd, "g-dst", dst.ID)
		p := newPolicy("p-1", newRule([]string{"g-src"}, []string{"g-dst"}))
		nmd.Policies = []*nmdata.Policy{p}

		c := compute(nmd, targetID)

		assert.Equal(t, []string{"p-1"}, policyIDs(c.Policies))
		assert.ElementsMatch(t, []string{targetID, dst.ID}, peerIDSet(c.Peers),
			"source-side siblings must not be connected")
		assert.ElementsMatch(t, []string{"g-src", "g-dst"}, groupIDSet(c.Groups))
		assert.Equal(t, []string{targetID}, c.Groups["g-src"].Peers)
		assert.Equal(t, []string{dst.ID}, c.Groups["g-dst"].Peers)
	})

	t.Run("peer in destinations pulls source peers and groups", func(t *testing.T) {
		target := newPeer(targetID, 1)
		src := newPeer("peer-src", 2)
		nmd := newNMD(target, src)
		addGroup(nmd, "g-src", src.ID)
		addGroup(nmd, "g-dst", targetID)
		nmd.Policies = []*nmdata.Policy{newPolicy("p-1", newRule([]string{"g-src"}, []string{"g-dst"}))}

		c := compute(nmd, targetID)

		assert.Equal(t, []string{"p-1"}, policyIDs(c.Policies))
		assert.ElementsMatch(t, []string{targetID, src.ID}, peerIDSet(c.Peers))
		assert.ElementsMatch(t, []string{"g-src", "g-dst"}, groupIDSet(c.Groups))
	})

	t.Run("unrelated policy contributes nothing", func(t *testing.T) {
		target := newPeer(targetID, 1)
		a := newPeer("peer-a", 2)
		b := newPeer("peer-b", 3)
		nmd := newNMD(target, a, b)
		addGroup(nmd, "g-own", targetID)
		addGroup(nmd, "g-a", a.ID)
		addGroup(nmd, "g-b", b.ID)
		nmd.Policies = []*nmdata.Policy{newPolicy("p-1", newRule([]string{"g-a"}, []string{"g-b"}))}

		c := compute(nmd, targetID)

		assert.Empty(t, c.Policies)
		assert.ElementsMatch(t, []string{targetID}, peerIDSet(c.Peers))
		assert.ElementsMatch(t, []string{"g-own"}, groupIDSet(c.Groups))
	})

	t.Run("disabled policy ignored", func(t *testing.T) {
		target := newPeer(targetID, 1)
		src := newPeer("peer-src", 2)
		nmd := newNMD(target, src)
		addGroup(nmd, "g-src", src.ID)
		addGroup(nmd, "g-dst", targetID)
		p := newPolicy("p-1", newRule([]string{"g-src"}, []string{"g-dst"}))
		p.Enabled = false
		nmd.Policies = []*nmdata.Policy{p}

		c := compute(nmd, targetID)

		assert.Empty(t, c.Policies)
		assert.ElementsMatch(t, []string{targetID}, peerIDSet(c.Peers))
	})

	t.Run("disabled rule ignored", func(t *testing.T) {
		target := newPeer(targetID, 1)
		src := newPeer("peer-src", 2)
		nmd := newNMD(target, src)
		addGroup(nmd, "g-src", src.ID)
		addGroup(nmd, "g-dst", targetID)
		rule := newRule([]string{"g-src"}, []string{"g-dst"})
		rule.Enabled = false
		nmd.Policies = []*nmdata.Policy{newPolicy("p-1", rule)}

		c := compute(nmd, targetID)

		assert.Empty(t, c.Policies)
		assert.ElementsMatch(t, []string{targetID}, peerIDSet(c.Peers))
	})

	t.Run("peer on both sides pulls peers from both directions", func(t *testing.T) {
		target := newPeer(targetID, 1)
		x := newPeer("peer-x", 2)
		y := newPeer("peer-y", 3)
		nmd := newNMD(target, x, y)
		addGroup(nmd, "g-src", targetID, x.ID)
		addGroup(nmd, "g-dst", targetID, y.ID)
		nmd.Policies = []*nmdata.Policy{newPolicy("p-1", newRule([]string{"g-src"}, []string{"g-dst"}))}

		c := compute(nmd, targetID)

		assert.Equal(t, []string{"p-1"}, policyIDs(c.Policies))
		assert.ElementsMatch(t, []string{targetID, x.ID, y.ID}, peerIDSet(c.Peers),
			"both the source-side and destination-side counterparts must connect")
	})

	t.Run("rule referencing missing group tolerated", func(t *testing.T) {
		target := newPeer(targetID, 1)
		nmd := newNMD(target)
		addGroup(nmd, "g-dst", targetID)
		nmd.Policies = []*nmdata.Policy{newPolicy("p-1", newRule([]string{"g-ghost"}, []string{"g-dst"}))}

		c := compute(nmd, targetID)

		assert.Equal(t, []string{"p-1"}, policyIDs(c.Policies))
		assert.ElementsMatch(t, []string{targetID}, peerIDSet(c.Peers))
	})

	t.Run("nil policy and rule entries tolerated", func(t *testing.T) {
		target := newPeer(targetID, 1)
		dst := newPeer("peer-dst", 2)
		nmd := newNMD(target, dst)
		addGroup(nmd, "g-src", targetID)
		addGroup(nmd, "g-dst", dst.ID)
		p := newPolicy("p-1", newRule([]string{"g-src"}, []string{"g-dst"}))
		p.Rules = append([]*nmdata.PolicyRule{nil}, p.Rules...)
		nmd.Policies = []*nmdata.Policy{nil, p}

		c := compute(nmd, targetID)

		assert.Equal(t, []string{"p-1"}, policyIDs(c.Policies))
		assert.ElementsMatch(t, []string{targetID, dst.ID}, peerIDSet(c.Peers))
	})
}

func TestGetPeerNetworkMapComponents_PeerResourceRules(t *testing.T) {
	peerResource := func(id string) nmdata.Resource {
		return nmdata.Resource{ID: id, Type: string(nbtypes.ResourceTypePeer)}
	}

	t.Run("target as source resource", func(t *testing.T) {
		target := newPeer(targetID, 1)
		dst := newPeer("peer-dst", 2)
		nmd := newNMD(target, dst)
		addGroup(nmd, "g-dst", dst.ID)
		rule := newRule(nil, []string{"g-dst"})
		rule.SourceResource = peerResource(targetID)
		nmd.Policies = []*nmdata.Policy{newPolicy("p-1", rule)}

		c := compute(nmd, targetID)

		assert.Equal(t, []string{"p-1"}, policyIDs(c.Policies))
		assert.ElementsMatch(t, []string{targetID, dst.ID}, peerIDSet(c.Peers))
	})

	t.Run("target as destination resource", func(t *testing.T) {
		target := newPeer(targetID, 1)
		src := newPeer("peer-src", 2)
		nmd := newNMD(target, src)
		addGroup(nmd, "g-src", src.ID)
		rule := newRule([]string{"g-src"}, nil)
		rule.DestinationResource = peerResource(targetID)
		nmd.Policies = []*nmdata.Policy{newPolicy("p-1", rule)}

		c := compute(nmd, targetID)

		assert.Equal(t, []string{"p-1"}, policyIDs(c.Policies))
		assert.ElementsMatch(t, []string{targetID, src.ID}, peerIDSet(c.Peers))
	})

	t.Run("remote peer as destination resource", func(t *testing.T) {
		target := newPeer(targetID, 1)
		remote := newPeer("peer-remote", 2)
		nmd := newNMD(target, remote)
		addGroup(nmd, "g-src", targetID)
		rule := newRule([]string{"g-src"}, nil)
		rule.DestinationResource = peerResource(remote.ID)
		nmd.Policies = []*nmdata.Policy{newPolicy("p-1", rule)}

		c := compute(nmd, targetID)

		assert.Equal(t, []string{"p-1"}, policyIDs(c.Policies))
		assert.ElementsMatch(t, []string{targetID, remote.ID}, peerIDSet(c.Peers))
	})

	// A directly referenced peer is admitted like a member of a group holding only
	// that peer: the ValidatedPeers gate and the posture checks apply equally.
	t.Run("unvalidated source resource peer is excluded", func(t *testing.T) {
		target := newPeer(targetID, 1)
		unval := newPeer("peer-unval", 2)
		nmd := newNMD(target, unval)
		delete(nmd.ValidatedPeers, unval.ID)
		addGroup(nmd, "g-dst", targetID)
		rule := newRule(nil, []string{"g-dst"})
		rule.SourceResource = peerResource(unval.ID)
		nmd.Policies = []*nmdata.Policy{newPolicy("p-1", rule)}

		c := compute(nmd, targetID)

		assert.ElementsMatch(t, []string{targetID}, peerIDSet(c.Peers))
	})

	t.Run("source resource peer failing posture checks is excluded", func(t *testing.T) {
		target := newPeer(targetID, 1)
		failing := newPeer("peer-failing", 2)
		failing.Meta.WtVersion = failingVersion
		nmd := newNMD(target, failing)
		addVersionCheck(nmd, "pc-1", postureMinVersion)
		addGroup(nmd, "g-dst", targetID)
		rule := newRule(nil, []string{"g-dst"})
		rule.SourceResource = peerResource(failing.ID)
		p := newPolicy("p-1", rule)
		p.SourcePostureChecks = []string{"pc-1"}
		nmd.Policies = []*nmdata.Policy{p}

		c := compute(nmd, targetID)

		assert.ElementsMatch(t, []string{targetID}, peerIDSet(c.Peers))
		assert.Empty(t, c.PostureFailedPeers)
	})

	t.Run("direct source peer failure recorded when connected via another policy", func(t *testing.T) {
		target := newPeer(targetID, 1)
		failing := newPeer("peer-failing", 2)
		failing.Meta.WtVersion = failingVersion
		nmd := newNMD(target, failing)
		addVersionCheck(nmd, "pc-1", postureMinVersion)
		addGroup(nmd, "g-dst", targetID)
		checkedRule := newRule(nil, []string{"g-dst"})
		checkedRule.SourceResource = peerResource(failing.ID)
		checked := newPolicy("p-checked", checkedRule)
		checked.SourcePostureChecks = []string{"pc-1"}
		openRule := newRule(nil, []string{"g-dst"})
		openRule.SourceResource = peerResource(failing.ID)
		nmd.Policies = []*nmdata.Policy{checked, newPolicy("p-open", openRule)}

		c := compute(nmd, targetID)

		assert.ElementsMatch(t, []string{targetID, failing.ID}, peerIDSet(c.Peers))
		assert.Equal(t, map[string]map[string]struct{}{"pc-1": {failing.ID: {}}}, c.PostureFailedPeers)
	})

	t.Run("target as source resource failing posture checks gets no policy", func(t *testing.T) {
		target := newPeer(targetID, 1)
		target.Meta.WtVersion = failingVersion
		dst := newPeer("peer-dst", 2)
		nmd := newNMD(target, dst)
		addVersionCheck(nmd, "pc-1", postureMinVersion)
		addGroup(nmd, "g-dst", dst.ID)
		rule := newRule(nil, []string{"g-dst"})
		rule.SourceResource = peerResource(targetID)
		p := newPolicy("p-1", rule)
		p.SourcePostureChecks = []string{"pc-1"}
		nmd.Policies = []*nmdata.Policy{p}

		c := compute(nmd, targetID)

		assert.Empty(t, policyIDs(c.Policies))
		assert.ElementsMatch(t, []string{targetID}, peerIDSet(c.Peers))
	})

	t.Run("unvalidated destination resource peer is excluded", func(t *testing.T) {
		target := newPeer(targetID, 1)
		unval := newPeer("peer-unval", 2)
		nmd := newNMD(target, unval)
		delete(nmd.ValidatedPeers, unval.ID)
		addGroup(nmd, "g-src", targetID)
		rule := newRule([]string{"g-src"}, nil)
		rule.DestinationResource = peerResource(unval.ID)
		nmd.Policies = []*nmdata.Policy{newPolicy("p-1", rule)}

		c := compute(nmd, targetID)

		assert.ElementsMatch(t, []string{targetID}, peerIDSet(c.Peers))
	})

	t.Run("unrelated peer resource rule ignored", func(t *testing.T) {
		target := newPeer(targetID, 1)
		a := newPeer("peer-a", 2)
		b := newPeer("peer-b", 3)
		nmd := newNMD(target, a, b)
		rule := newRule(nil, nil)
		rule.SourceResource = peerResource(a.ID)
		rule.DestinationResource = peerResource(b.ID)
		nmd.Policies = []*nmdata.Policy{newPolicy("p-1", rule)}

		c := compute(nmd, targetID)

		assert.Empty(t, c.Policies)
		assert.ElementsMatch(t, []string{targetID}, peerIDSet(c.Peers))
	})
}

// A destination list containing a group named "All" short-circuits peer
// expansion to that group alone, dropping peers accumulated from earlier
// groups. Groups themselves are still all shipped. Mirrors legacy behavior
// that the wire encoding depends on (see
// TestEnvelopeRoundTrip_AllGroupShortCircuitParity).
func TestGetPeerNetworkMapComponents_AllGroupShortCircuit(t *testing.T) {
	target := newPeer(targetID, 1)
	first := newPeer("peer-first", 2)
	allMember := newPeer("peer-all-member", 3)
	nmd := newNMD(target, first, allMember)
	addGroup(nmd, "g-src", targetID)
	addGroup(nmd, "g-first", first.ID)
	nmd.Groups["g-all"] = &nmdata.Group{ID: "g-all", Name: nmdata.GroupAllName, Peers: []string{targetID, allMember.ID}}
	nmd.Policies = []*nmdata.Policy{newPolicy("p-1", newRule([]string{"g-src"}, []string{"g-first", "g-all"}))}

	c := compute(nmd, targetID)

	assert.ElementsMatch(t, []string{targetID, allMember.ID}, peerIDSet(c.Peers),
		"peers from groups before the All group must be dropped by the short-circuit")
	assert.ElementsMatch(t, []string{"g-src", "g-first", "g-all"}, groupIDSet(c.Groups))
	assert.Empty(t, c.Groups["g-first"].Peers)
}

func TestGetPeerNetworkMapComponents_UnvalidatedPolicyPeersExcluded(t *testing.T) {
	target := newPeer(targetID, 1)
	srcOK := newPeer("peer-src-ok", 2)
	srcUnval := newPeer("peer-src-unval", 3)
	nmd := newNMD(target, srcOK, srcUnval)
	delete(nmd.ValidatedPeers, srcUnval.ID)
	addGroup(nmd, "g-src", srcOK.ID, srcUnval.ID, "peer-deleted")
	addGroup(nmd, "g-dst", targetID)
	nmd.Policies = []*nmdata.Policy{newPolicy("p-1", newRule([]string{"g-src"}, []string{"g-dst"}))}

	c := compute(nmd, targetID)

	assert.ElementsMatch(t, []string{targetID, srcOK.ID}, peerIDSet(c.Peers),
		"unvalidated and dangling group members must not connect")
	assert.Equal(t, []string{srcOK.ID}, c.Groups["g-src"].Peers)
}

// Multi-group rules take the union path of getPeersFromGroups (no All-group
// short-circuit); validation and source posture checks apply per member.
func TestGetPeerNetworkMapComponents_MultiGroupSources(t *testing.T) {
	target := newPeer(targetID, 1)
	dup := newPeer("peer-dup", 2)
	unval := newPeer("peer-unval", 3)
	failing := newPeer("peer-failing", 4)
	failing.Meta.WtVersion = failingVersion
	solo := newPeer("peer-solo", 5)
	nmd := newNMD(target, dup, unval, failing, solo)
	delete(nmd.ValidatedPeers, unval.ID)
	addVersionCheck(nmd, "pc-1", postureMinVersion)
	addGroup(nmd, "g-1", targetID, dup.ID, unval.ID, "peer-deleted")
	addGroup(nmd, "g-2", dup.ID, failing.ID, solo.ID)
	addGroup(nmd, "g-tgt", targetID)
	p := newPolicy("p-1", newRule([]string{"g-1", "g-2"}, []string{"g-tgt"}))
	p.SourcePostureChecks = []string{"pc-1"}
	nmd.Policies = []*nmdata.Policy{p}

	c := compute(nmd, targetID)

	assert.Equal(t, []string{"p-1"}, policyIDs(c.Policies))
	assert.ElementsMatch(t, []string{targetID, dup.ID, solo.ID}, peerIDSet(c.Peers))
	assert.Empty(t, c.PostureFailedPeers,
		"failing is not otherwise connected, so its failure record is pruned")
}

func TestGetPeerNetworkMapComponents_PostureChecks(t *testing.T) {
	t.Run("failing source peer excluded without orphan failure record", func(t *testing.T) {
		target := newPeer(targetID, 1)
		failing := newPeer("peer-failing", 2)
		failing.Meta.WtVersion = failingVersion
		nmd := newNMD(target, failing)
		addVersionCheck(nmd, "pc-1", postureMinVersion)
		addGroup(nmd, "g-src", failing.ID)
		addGroup(nmd, "g-dst", targetID)
		p := newPolicy("p-1", newRule([]string{"g-src"}, []string{"g-dst"}))
		p.SourcePostureChecks = []string{"pc-1"}
		nmd.Policies = []*nmdata.Policy{p}

		c := compute(nmd, targetID)

		assert.Equal(t, []string{"p-1"}, policyIDs(c.Policies))
		assert.ElementsMatch(t, []string{targetID}, peerIDSet(c.Peers))
		assert.Empty(t, c.PostureFailedPeers,
			"failure records for peers absent from the map must be pruned")
	})

	t.Run("failure recorded when peer is connected via another policy", func(t *testing.T) {
		target := newPeer(targetID, 1)
		failing := newPeer("peer-failing", 2)
		failing.Meta.WtVersion = failingVersion
		nmd := newNMD(target, failing)
		addVersionCheck(nmd, "pc-1", postureMinVersion)
		addGroup(nmd, "g-src", failing.ID)
		addGroup(nmd, "g-dst", targetID)
		checked := newPolicy("p-checked", newRule([]string{"g-src"}, []string{"g-dst"}))
		checked.SourcePostureChecks = []string{"pc-1"}
		open := newPolicy("p-open", newRule([]string{"g-src"}, []string{"g-dst"}))
		nmd.Policies = []*nmdata.Policy{checked, open}

		c := compute(nmd, targetID)

		assert.ElementsMatch(t, []string{targetID, failing.ID}, peerIDSet(c.Peers))
		assert.Equal(t, map[string]map[string]struct{}{"pc-1": {failing.ID: {}}}, c.PostureFailedPeers)
	})

	t.Run("destination peers bypass source posture checks", func(t *testing.T) {
		target := newPeer(targetID, 1)
		failing := newPeer("peer-failing", 2)
		failing.Meta.WtVersion = failingVersion
		nmd := newNMD(target, failing)
		addVersionCheck(nmd, "pc-1", postureMinVersion)
		addGroup(nmd, "g-src", targetID)
		addGroup(nmd, "g-dst", failing.ID)
		p := newPolicy("p-1", newRule([]string{"g-src"}, []string{"g-dst"}))
		p.SourcePostureChecks = []string{"pc-1"}
		nmd.Policies = []*nmdata.Policy{p}

		c := compute(nmd, targetID)

		assert.ElementsMatch(t, []string{targetID, failing.ID}, peerIDSet(c.Peers))
		assert.Empty(t, c.PostureFailedPeers)
	})

	t.Run("target failing its own source check drops the policy", func(t *testing.T) {
		target := newPeer(targetID, 1)
		target.Meta.WtVersion = failingVersion
		dst := newPeer("peer-dst", 2)
		nmd := newNMD(target, dst)
		addVersionCheck(nmd, "pc-1", postureMinVersion)
		addGroup(nmd, "g-src", targetID)
		addGroup(nmd, "g-dst", dst.ID)
		p := newPolicy("p-1", newRule([]string{"g-src"}, []string{"g-dst"}))
		p.SourcePostureChecks = []string{"pc-1"}
		nmd.Policies = []*nmdata.Policy{p}

		c := compute(nmd, targetID)

		assert.Empty(t, c.Policies)
		assert.ElementsMatch(t, []string{targetID}, peerIDSet(c.Peers))
		assert.Empty(t, c.PostureFailedPeers)
	})

	t.Run("failure keyed by the first failing check", func(t *testing.T) {
		target := newPeer(targetID, 1)
		failing := newPeer("peer-failing", 2)
		nmd := newNMD(target, failing)
		addVersionCheck(nmd, "pc-pass", postureMinVersion)
		addVersionCheck(nmd, "pc-fail", "2.0.0")
		addGroup(nmd, "g-src", failing.ID)
		addGroup(nmd, "g-dst", targetID)
		checked := newPolicy("p-checked", newRule([]string{"g-src"}, []string{"g-dst"}))
		checked.SourcePostureChecks = []string{"pc-pass", "pc-fail"}
		open := newPolicy("p-open", newRule([]string{"g-src"}, []string{"g-dst"}))
		nmd.Policies = []*nmdata.Policy{checked, open}

		c := compute(nmd, targetID)

		assert.Equal(t, map[string]map[string]struct{}{"pc-fail": {failing.ID: {}}}, c.PostureFailedPeers,
			"the record must be keyed by the failing check, not the first listed")
	})

	t.Run("unknown posture check id passes everyone", func(t *testing.T) {
		target := newPeer(targetID, 1)
		src := newPeer("peer-src", 2)
		nmd := newNMD(target, src)
		addGroup(nmd, "g-src", src.ID)
		addGroup(nmd, "g-dst", targetID)
		p := newPolicy("p-1", newRule([]string{"g-src"}, []string{"g-dst"}))
		p.SourcePostureChecks = []string{"pc-ghost"}
		nmd.Policies = []*nmdata.Policy{p}

		c := compute(nmd, targetID)

		assert.ElementsMatch(t, []string{targetID, src.ID}, peerIDSet(c.Peers))
		assert.Empty(t, c.PostureFailedPeers)
	})
}

func TestGetPeerNetworkMapComponents_Routes(t *testing.T) {
	t.Run("owned route relevant even when disabled", func(t *testing.T) {
		target := newPeer(targetID, 1)
		dist := newPeer("peer-dist", 2)
		nmd := newNMD(target, dist)
		addGroup(nmd, "g-dist", dist.ID)
		addGroup(nmd, "g-acl")
		r := &nmdata.Route{ID: "r-1", Peer: targetID, Enabled: false, Groups: []string{"g-dist"}, AccessControlGroups: []string{"g-acl"}}
		nmd.Routes = []*nmdata.Route{r}

		c := compute(nmd, targetID)

		require.Len(t, c.Routes, 1)
		assert.Same(t, r, c.Routes[0])
		assert.Contains(t, c.Groups, "g-dist")
		assert.NotContains(t, c.Groups, "g-acl",
			"access control groups of a disabled route must not be collected")
		assert.ElementsMatch(t, []string{targetID}, peerIDSet(c.Peers),
			"distribution group members are not connected by the route itself")
	})

	t.Run("peer-group route disabled still ships and connects HA members", func(t *testing.T) {
		target := newPeer(targetID, 1)
		ha := newPeer("peer-ha", 2)
		haUnval := newPeer("peer-ha-unval", 3)
		nmd := newNMD(target, ha, haUnval)
		delete(nmd.ValidatedPeers, haUnval.ID)
		addGroup(nmd, "g-ha", targetID, ha.ID, haUnval.ID)
		r := &nmdata.Route{ID: "r-1", PeerGroups: []string{"g-ha", "g-ghost"}, Enabled: false}
		nmd.Routes = []*nmdata.Route{r}

		c := compute(nmd, targetID)

		require.Len(t, c.Routes, 1)
		assert.ElementsMatch(t, []string{targetID, ha.ID}, peerIDSet(c.Peers))
		assert.Equal(t, []string{targetID, ha.ID}, c.Groups["g-ha"].Peers)
	})

	t.Run("route consumer connects HA routing peers from peer groups", func(t *testing.T) {
		target := newPeer(targetID, 1)
		router1 := newPeer("peer-router-1", 2)
		router2 := newPeer("peer-router-2", 3)
		routerUnval := newPeer("peer-router-unval", 4)
		nmd := newNMD(target, router1, router2, routerUnval)
		delete(nmd.ValidatedPeers, routerUnval.ID)
		addGroup(nmd, "g-ha", router1.ID, router2.ID, routerUnval.ID)
		addGroup(nmd, "g-dist", targetID)
		nmd.Routes = []*nmdata.Route{{ID: "r-1", PeerGroups: []string{"g-ha"}, Groups: []string{"g-dist"}, Enabled: true}}

		c := compute(nmd, targetID)

		require.Len(t, c.Routes, 1)
		assert.ElementsMatch(t, []string{targetID, router1.ID, router2.ID}, peerIDSet(c.Peers),
			"the consumer must connect to every validated HA router")
		assert.Equal(t, []string{router1.ID, router2.ID}, c.Groups["g-ha"].Peers)
	})

	t.Run("distribution route connects routing peer", func(t *testing.T) {
		target := newPeer(targetID, 1)
		router := newPeer("peer-router", 2)
		nmd := newNMD(target, router)
		addGroup(nmd, "g-dist", targetID)
		r := &nmdata.Route{ID: "r-1", Peer: router.ID, Enabled: true, Groups: []string{"g-dist"}}
		nmd.Routes = []*nmdata.Route{r}

		c := compute(nmd, targetID)

		require.Len(t, c.Routes, 1)
		assert.ElementsMatch(t, []string{targetID, router.ID}, peerIDSet(c.Peers))
	})

	t.Run("disabled distribution route not relevant", func(t *testing.T) {
		target := newPeer(targetID, 1)
		router := newPeer("peer-router", 2)
		nmd := newNMD(target, router)
		addGroup(nmd, "g-dist", targetID)
		nmd.Routes = []*nmdata.Route{{ID: "r-1", Peer: router.ID, Enabled: false, Groups: []string{"g-dist"}}}

		c := compute(nmd, targetID)

		assert.Empty(t, c.Routes)
		assert.ElementsMatch(t, []string{targetID}, peerIDSet(c.Peers))
	})

	t.Run("unvalidated routing peer excluded but route ships", func(t *testing.T) {
		target := newPeer(targetID, 1)
		router := newPeer("peer-router", 2)
		nmd := newNMD(target, router)
		delete(nmd.ValidatedPeers, router.ID)
		addGroup(nmd, "g-dist", targetID)
		nmd.Routes = []*nmdata.Route{{ID: "r-1", Peer: router.ID, Enabled: true, Groups: []string{"g-dist"}}}

		c := compute(nmd, targetID)

		require.Len(t, c.Routes, 1)
		assert.ElementsMatch(t, []string{targetID}, peerIDSet(c.Peers))
	})

	t.Run("nil and unrelated routes skipped", func(t *testing.T) {
		target := newPeer(targetID, 1)
		other := newPeer("peer-other", 2)
		nmd := newNMD(target, other)
		addGroup(nmd, "g-dist", targetID)
		addGroup(nmd, "g-foreign", other.ID)
		owned := &nmdata.Route{ID: "r-owned", Peer: targetID, Enabled: true}
		nmd.Routes = []*nmdata.Route{nil, {ID: "r-foreign", Peer: other.ID, Enabled: true, Groups: []string{"g-foreign"}}, owned}

		c := compute(nmd, targetID)

		require.Len(t, c.Routes, 1)
		assert.Same(t, owned, c.Routes[0])
	})
}

// A policy whose destinations hit an enabled route's access control groups is
// shipped so the routing peer can build route firewall rules, but its peers
// are not connected through this bridge.
func TestGetPeerNetworkMapComponents_RouteAccessControlBridging(t *testing.T) {
	t.Run("policy targeting route ACG becomes relevant", func(t *testing.T) {
		target := newPeer(targetID, 1)
		router := newPeer("peer-router", 2)
		remote := newPeer("peer-remote", 3)
		nmd := newNMD(target, router, remote)
		addGroup(nmd, "g-dist", targetID)
		addGroup(nmd, "g-acl")
		addGroup(nmd, "g-remote", remote.ID)
		nmd.Routes = []*nmdata.Route{{ID: "r-1", Peer: router.ID, Enabled: true, Groups: []string{"g-dist"}, AccessControlGroups: []string{"g-acl"}}}
		nmd.Policies = []*nmdata.Policy{newPolicy("p-acl", newRule([]string{"g-remote"}, []string{"g-acl"}))}

		c := compute(nmd, targetID)

		assert.Equal(t, []string{"p-acl"}, policyIDs(c.Policies))
		assert.ElementsMatch(t, []string{"g-dist", "g-acl", "g-remote"}, groupIDSet(c.Groups))
		assert.ElementsMatch(t, []string{targetID, router.ID}, peerIDSet(c.Peers),
			"the bridged policy's source peers must not be connected")
	})

	t.Run("disabled route does not bridge its ACG policies", func(t *testing.T) {
		target := newPeer(targetID, 1)
		remote := newPeer("peer-remote", 2)
		nmd := newNMD(target, remote)
		addGroup(nmd, "g-acl")
		addGroup(nmd, "g-remote", remote.ID)
		nmd.Routes = []*nmdata.Route{{ID: "r-1", Peer: targetID, Enabled: false, AccessControlGroups: []string{"g-acl"}}}
		nmd.Policies = []*nmdata.Policy{newPolicy("p-acl", newRule([]string{"g-remote"}, []string{"g-acl"}))}

		c := compute(nmd, targetID)

		assert.Empty(t, c.Policies)
	})
}

func TestGetPeerNetworkMapComponents_SSHRequirements(t *testing.T) {
	allowedUsers := map[string]struct{}{"user-1": {}, "user-2": {}}
	groupUsers := map[string][]string{"g-auth": {"user-a"}, "g-other": {"user-b"}}

	cases := []struct {
		name          string
		mutateRule    func(*nmdata.PolicyRule)
		sshEnabled    bool
		targetInSrc   bool
		wantAllowed   bool
		wantGroupsMap map[string][]string
	}{
		{
			name: "netbird-ssh with authorized groups",
			mutateRule: func(r *nmdata.PolicyRule) {
				r.Protocol = string(nbtypes.PolicyRuleProtocolNetbirdSSH)
				r.AuthorizedGroups = map[string][]string{"g-auth": nil}
			},
			wantGroupsMap: map[string][]string{"g-auth": {"user-a"}},
		},
		{
			name: "netbird-ssh with authorized user",
			mutateRule: func(r *nmdata.PolicyRule) {
				r.Protocol = string(nbtypes.PolicyRuleProtocolNetbirdSSH)
				r.AuthorizedUser = "root"
			},
		},
		{
			name: "netbird-ssh default needs allowed users",
			mutateRule: func(r *nmdata.PolicyRule) {
				r.Protocol = string(nbtypes.PolicyRuleProtocolNetbirdSSH)
			},
			wantAllowed: true,
		},
		{
			name:        "legacy all-protocol with SSH enabled",
			mutateRule:  func(r *nmdata.PolicyRule) { r.Protocol = string(nbtypes.PolicyRuleProtocolALL) },
			sshEnabled:  true,
			wantAllowed: true,
		},
		{
			name:       "legacy all-protocol with SSH disabled",
			mutateRule: func(r *nmdata.PolicyRule) { r.Protocol = string(nbtypes.PolicyRuleProtocolALL) },
		},
		{
			name:        "tcp port 22 with SSH enabled",
			mutateRule:  func(r *nmdata.PolicyRule) { r.Ports = []string{"22"} },
			sshEnabled:  true,
			wantAllowed: true,
		},
		{
			name:        "tcp port range covering 22",
			mutateRule:  func(r *nmdata.PolicyRule) { r.PortRanges = []nmdata.RulePortRange{{Start: 20, End: 30}} },
			sshEnabled:  true,
			wantAllowed: true,
		},
		{
			name:        "tcp native ssh port 22022",
			mutateRule:  func(r *nmdata.PolicyRule) { r.Ports = []string{"22022"} },
			sshEnabled:  true,
			wantAllowed: true,
		},
		{
			name:        "tcp port range covering only native ssh port",
			mutateRule:  func(r *nmdata.PolicyRule) { r.PortRanges = []nmdata.RulePortRange{{Start: 22000, End: 23000}} },
			sshEnabled:  true,
			wantAllowed: true,
		},
		{
			name:       "tcp unrelated port",
			mutateRule: func(r *nmdata.PolicyRule) { r.Ports = []string{"443"} },
			sshEnabled: true,
		},
		{
			name: "netbird-ssh only counts on the destination side",
			mutateRule: func(r *nmdata.PolicyRule) {
				r.Protocol = string(nbtypes.PolicyRuleProtocolNetbirdSSH)
			},
			targetInSrc: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			target := newPeer(targetID, 1)
			target.SSHEnabled = tc.sshEnabled
			admin := newPeer("peer-admin", 2)
			nmd := newNMD(target, admin)
			nmd.AllowedUserIDs = allowedUsers
			nmd.GroupIDToUserIDs = groupUsers
			addGroup(nmd, "g-adm", admin.ID)
			addGroup(nmd, "g-tgt", targetID)
			rule := newRule([]string{"g-adm"}, []string{"g-tgt"})
			if tc.targetInSrc {
				rule = newRule([]string{"g-tgt"}, []string{"g-adm"})
			}
			tc.mutateRule(rule)
			nmd.Policies = []*nmdata.Policy{newPolicy("p-1", rule)}

			c := compute(nmd, targetID)

			if tc.wantAllowed {
				assert.Equal(t, allowedUsers, c.AllowedUserIDs)
			} else {
				assert.Nil(t, c.AllowedUserIDs)
			}
			assert.Equal(t, tc.wantGroupsMap, c.GroupIDToUserIDs)
		})
	}
}

func TestGetPeerNetworkMapComponents_DNSRecordFiltering(t *testing.T) {
	record := func(name, rdata string) nmdata.SimpleRecord {
		return nmdata.SimpleRecord{Name: name, Type: 1, Class: "IN", TTL: 300, RData: rdata}
	}

	build := func(ipv6Target bool) (*networkmap.NetworkMapData, nmdata.CustomZone) {
		target := newPeer(targetID, 1)
		if ipv6Target {
			target.IPv6 = netip.MustParseAddr("fd00::1")
			target.Meta.Capabilities = []int32{nmdata.PeerCapabilityIPv6Overlay}
		}
		buddy := newPeer("peer-buddy", 2)
		buddy.IPv6 = netip.MustParseAddr("fd00::2")
		stranger := newPeer("peer-stranger", 3)
		nmd := newNMD(target, buddy, stranger)
		addGroup(nmd, "g-src", targetID)
		addGroup(nmd, "g-dst", buddy.ID)
		nmd.Policies = []*nmdata.Policy{newPolicy("p-1", newRule([]string{"g-src"}, []string{"g-dst"}))}
		zone := nmdata.CustomZone{
			Domain: "acme.netbird.cloud.",
			Records: []nmdata.SimpleRecord{
				record(targetID, "100.64.0.1"),
				record("peer-buddy", "100.64.0.2"),
				record("peer-stranger", "100.64.0.3"),
				record("outsider", "9.9.9.9"),
				record("peer-buddy-v6", "fd00::2"),
			},
		}
		return nmd, zone
	}

	t.Run("records limited to relevant peers, IPv6 dropped without capability", func(t *testing.T) {
		nmd, zone := build(false)

		c := nmd.GetPeerNetworkMapComponents(targetID, zone)

		assert.Equal(t, "acme.netbird.cloud.", c.CustomZoneDomain)
		assert.Equal(t, []nmdata.SimpleRecord{
			record(targetID, "100.64.0.1"),
			record("peer-buddy", "100.64.0.2"),
		}, c.AllDNSRecords)
	})

	t.Run("IPv6 records of relevant peers kept for capable target", func(t *testing.T) {
		nmd, zone := build(true)

		c := nmd.GetPeerNetworkMapComponents(targetID, zone)

		assert.Equal(t, []nmdata.SimpleRecord{
			record(targetID, "100.64.0.1"),
			record("peer-buddy", "100.64.0.2"),
			record("peer-buddy-v6", "fd00::2"),
		}, c.AllDNSRecords)
	})

	t.Run("no records yields nil", func(t *testing.T) {
		nmd, _ := build(false)

		c := nmd.GetPeerNetworkMapComponents(targetID, nmdata.CustomZone{Domain: "acme.netbird.cloud."})

		assert.Nil(t, c.AllDNSRecords)
	})
}

func TestGetPeerNetworkMapComponents_AccountZones(t *testing.T) {
	rec := func(name string) nmdata.SimpleRecord {
		return nmdata.SimpleRecord{Name: name, Type: 1, Class: "IN", RData: "100.64.0.9"}
	}

	t.Run("applied and private service zones for peer groups", func(t *testing.T) {
		target := newPeer(targetID, 1)
		nmd := newNMD(target)
		addGroup(nmd, "g-a", targetID)
		appliedZone := nmdata.CustomZone{Domain: "zone-one.example.com.", Records: []nmdata.SimpleRecord{rec("z1")}}
		nmd.AppliedZoneCandidates = []networkmap.AppliedZoneCandidate{
			{DistributionGroups: []string{"g-a"}, Zone: appliedZone},
			{DistributionGroups: []string{"g-x"}, Zone: nmdata.CustomZone{Domain: "zone-two.example.com."}},
		}
		nmd.PrivateServiceCandidates = []networkmap.PrivateServiceCandidate{
			{AccessGroups: []string{"g-a"}, Zone: nmdata.CustomZone{Domain: "svc.example.com", SearchDomainDisabled: true, NonAuthoritative: true, Records: []nmdata.SimpleRecord{rec("svc-1")}}},
			{AccessGroups: []string{"g-a"}, Zone: nmdata.CustomZone{Domain: "svc.example.com", Records: []nmdata.SimpleRecord{rec("svc-2")}}},
			{AccessGroups: []string{"g-x"}, Zone: nmdata.CustomZone{Domain: "other.example.com", Records: []nmdata.SimpleRecord{rec("other")}}},
			{AccessGroups: []string{"g-a"}, Zone: nmdata.CustomZone{Domain: "empty.example.com"}},
		}

		c := compute(nmd, targetID)

		require.Len(t, c.AccountZones, 2)
		assert.Equal(t, appliedZone, c.AccountZones[0])
		assert.Equal(t, nmdata.CustomZone{
			Domain:               "svc.example.com",
			SearchDomainDisabled: true,
			NonAuthoritative:     true,
			Records:              []nmdata.SimpleRecord{rec("svc-1"), rec("svc-2")},
		}, c.AccountZones[1], "same-apex private service candidates must merge, flags from the first")
	})

	t.Run("groupless peer receives no zones", func(t *testing.T) {
		target := newPeer(targetID, 1)
		nmd := newNMD(target)
		nmd.AppliedZoneCandidates = []networkmap.AppliedZoneCandidate{
			{DistributionGroups: []string{"g-a"}, Zone: nmdata.CustomZone{Domain: "zone-one.example.com."}},
		}
		nmd.PrivateServiceCandidates = []networkmap.PrivateServiceCandidate{
			{AccessGroups: []string{"g-a"}, Zone: nmdata.CustomZone{Domain: "svc.example.com", Records: []nmdata.SimpleRecord{rec("svc")}}},
		}

		c := compute(nmd, targetID)

		assert.Empty(t, c.AccountZones)
	})
}

func TestGetPeerNetworkMapComponents_NameServerGroups(t *testing.T) {
	target := newPeer(targetID, 1)
	other := newPeer("peer-other", 2)
	nmd := newNMD(target, other)
	addGroup(nmd, "g-own", targetID)
	addGroup(nmd, "g-dst", other.ID)
	addGroup(nmd, "g-foreign")
	nmd.Policies = []*nmdata.Policy{newPolicy("p-1", newRule([]string{"g-own"}, []string{"g-dst"}))}
	nsOwn := &nmdata.NameServerGroup{ID: "ns-own", Enabled: true, Groups: []string{"g-own"}}
	nsDst := &nmdata.NameServerGroup{ID: "ns-dst", Enabled: true, Groups: []string{"g-dst"}}
	nsDisabled := &nmdata.NameServerGroup{ID: "ns-disabled", Enabled: false, Groups: []string{"g-own"}}
	nsForeign := &nmdata.NameServerGroup{ID: "ns-foreign", Enabled: true, Groups: []string{"g-foreign"}}
	nsBoth := &nmdata.NameServerGroup{ID: "ns-both", Enabled: true, Groups: []string{"g-own", "g-dst"}}
	nmd.NameServerGroups = []*nmdata.NameServerGroup{nsOwn, nil, nsDst, nsDisabled, nsForeign, nsBoth}

	c := compute(nmd, targetID)

	assert.Equal(t, []*nmdata.NameServerGroup{nsOwn, nsDst, nsBoth}, c.NameServerGroups,
		"nameserver groups attach to any relevant group and ship once even when several groups match")
}

func TestGetPeerNetworkMapComponents_NetworkResources_SourceSide(t *testing.T) {
	target := newPeer(targetID, 1)
	routerOK := newPeer("peer-router-ok", 2)
	routerUnval := newPeer("peer-router-unval", 3)
	nmd := newNMD(target, routerOK, routerUnval)
	delete(nmd.ValidatedPeers, routerUnval.ID)
	addGroup(nmd, "g-clients", targetID)
	addGroup(nmd, "g-resource")
	res := &nmdata.NetworkResource{ID: "res-1", NetworkID: "net-1", Enabled: true}
	nmd.NetworkResources = []*nmdata.NetworkResource{res}
	rp := newPolicy("rp-1", newRule([]string{"g-clients"}, []string{"g-resource"}))
	nmd.Policies = []*nmdata.Policy{rp}
	nmd.ResourcePolicies = map[string][]*nmdata.Policy{"res-1": {rp}}
	routers := map[string]*nmdata.NetworkRouter{
		routerOK.ID:    {Metric: 100},
		routerUnval.ID: {Metric: 200},
	}
	nmd.Routers = map[string]map[string]*nmdata.NetworkRouter{"net-1": routers}

	c := compute(nmd, targetID)

	assert.Equal(t, []*nmdata.NetworkResource{res}, c.NetworkResources)
	assert.Equal(t, map[string][]*nmdata.Policy{"res-1": {rp}}, c.ResourcePoliciesMap)
	assert.Equal(t, map[string]map[string]*nmdata.NetworkRouter{"net-1": routers}, c.RoutersMap)
	assert.ElementsMatch(t, []string{routerOK.ID}, peerIDSet(c.RouterPeers),
		"an unvalidated routing peer is withheld from RouterPeers too, since the envelope encoder "+
			"indexes that map into the wire peer table and the client restores every entry from it")
	assert.ElementsMatch(t, []string{targetID, routerOK.ID}, peerIDSet(c.Peers),
		"only validated routing peers are connected")
	assert.ElementsMatch(t, []string{"g-clients", "g-resource"}, groupIDSet(c.Groups))
}

func TestGetPeerNetworkMapComponents_NetworkResources_RouterSide(t *testing.T) {
	t.Run("posture-valid validated source peers connected, failures recorded", func(t *testing.T) {
		target := newPeer(targetID, 1)
		clientOK := newPeer("peer-client-ok", 2)
		clientUnval := newPeer("peer-client-unval", 3)
		clientFail := newPeer("peer-client-fail", 4)
		clientFail.Meta.WtVersion = failingVersion
		nmd := newNMD(target, clientOK, clientUnval, clientFail)
		delete(nmd.ValidatedPeers, clientUnval.ID)
		addVersionCheck(nmd, "pc-1", postureMinVersion)
		addGroup(nmd, "g-clients", clientOK.ID, clientUnval.ID, clientFail.ID)
		addGroup(nmd, "g-resource")
		addGroup(nmd, "g-tgt", targetID)
		res := &nmdata.NetworkResource{ID: "res-1", NetworkID: "net-1", Enabled: true}
		nmd.NetworkResources = []*nmdata.NetworkResource{res}
		rp := newPolicy("rp-1", newRule([]string{"g-clients"}, []string{"g-resource"}))
		rp.SourcePostureChecks = []string{"pc-1"}
		acl := newPolicy("p-acl", newRule([]string{"g-clients"}, []string{"g-tgt"}))
		nmd.Policies = []*nmdata.Policy{acl}
		nmd.ResourcePolicies = map[string][]*nmdata.Policy{"res-1": {rp}}
		nmd.Routers = map[string]map[string]*nmdata.NetworkRouter{"net-1": {targetID: {Metric: 100}}}

		c := compute(nmd, targetID)

		assert.Equal(t, []*nmdata.NetworkResource{res}, c.NetworkResources)
		assert.ElementsMatch(t, []string{targetID}, peerIDSet(c.RouterPeers))
		assert.ElementsMatch(t, []string{targetID, clientOK.ID, clientFail.ID}, peerIDSet(c.Peers),
			"clientFail connects via the open ACL policy, clientUnval never connects")
		assert.Equal(t, map[string]map[string]struct{}{"pc-1": {clientFail.ID: {}}}, c.PostureFailedPeers)
	})

	t.Run("peer source resource collects exactly that peer", func(t *testing.T) {
		target := newPeer(targetID, 1)
		client := newPeer("peer-client", 2)
		other := newPeer("peer-other", 3)
		nmd := newNMD(target, client, other)
		res := &nmdata.NetworkResource{ID: "res-1", NetworkID: "net-1", Enabled: true}
		nmd.NetworkResources = []*nmdata.NetworkResource{res}
		rule := newRule(nil, nil)
		rule.SourceResource = nmdata.Resource{ID: client.ID, Type: string(nbtypes.ResourceTypePeer)}
		nmd.ResourcePolicies = map[string][]*nmdata.Policy{"res-1": {newPolicy("rp-1", rule)}}
		nmd.Routers = map[string]map[string]*nmdata.NetworkRouter{"net-1": {targetID: {}}}

		c := compute(nmd, targetID)

		assert.Equal(t, []*nmdata.NetworkResource{res}, c.NetworkResources)
		assert.ElementsMatch(t, []string{targetID, client.ID}, peerIDSet(c.Peers))
	})

	t.Run("multiple source groups unioned, missing group tolerated", func(t *testing.T) {
		target := newPeer(targetID, 1)
		c1 := newPeer("peer-c1", 2)
		c2 := newPeer("peer-c2", 3)
		nmd := newNMD(target, c1, c2)
		addGroup(nmd, "g-c1", c1.ID)
		addGroup(nmd, "g-c2", c2.ID)
		res := &nmdata.NetworkResource{ID: "res-1", NetworkID: "net-1", Enabled: true}
		nmd.NetworkResources = []*nmdata.NetworkResource{res}
		nmd.ResourcePolicies = map[string][]*nmdata.Policy{
			"res-1": {newPolicy("rp-1", newRule([]string{"g-c1", "g-c2", "g-ghost"}, nil))},
		}
		nmd.Routers = map[string]map[string]*nmdata.NetworkRouter{"net-1": {targetID: {}}}

		c := compute(nmd, targetID)

		assert.ElementsMatch(t, []string{targetID, c1.ID, c2.ID}, peerIDSet(c.Peers))
	})
}

func TestGetPeerNetworkMapComponents_NetworkResources_PeerResourceSource(t *testing.T) {
	build := func(sourcePeerID string) *networkmap.NetworkMapData {
		target := newPeer(targetID, 1)
		router := newPeer("peer-router", 2)
		other := newPeer("peer-other", 3)
		nmd := newNMD(target, router, other)
		res := &nmdata.NetworkResource{ID: "res-1", NetworkID: "net-1", Enabled: true}
		nmd.NetworkResources = []*nmdata.NetworkResource{res}
		rule := newRule(nil, nil)
		rule.SourceResource = nmdata.Resource{ID: sourcePeerID, Type: string(nbtypes.ResourceTypePeer)}
		nmd.ResourcePolicies = map[string][]*nmdata.Policy{"res-1": {newPolicy("rp-1", rule)}}
		nmd.Routers = map[string]map[string]*nmdata.NetworkRouter{"net-1": {"peer-router": {}}}
		return nmd
	}

	t.Run("target named as source resource gains access", func(t *testing.T) {
		c := compute(build(targetID), targetID)

		assert.Len(t, c.NetworkResources, 1)
		assert.ElementsMatch(t, []string{targetID, "peer-router"}, peerIDSet(c.Peers))
	})

	t.Run("other peer named as source resource denies target", func(t *testing.T) {
		c := compute(build("peer-other"), targetID)

		assert.Empty(t, c.NetworkResources)
		assert.ElementsMatch(t, []string{targetID}, peerIDSet(c.Peers))
	})
}

func TestGetPeerNetworkMapComponents_NetworkResources_Gating(t *testing.T) {
	build := func() (*networkmap.NetworkMapData, *nmdata.NetworkResource, *nmdata.Policy) {
		target := newPeer(targetID, 1)
		router := newPeer("peer-router", 2)
		nmd := newNMD(target, router)
		addGroup(nmd, "g-clients", targetID)
		addGroup(nmd, "g-resource")
		res := &nmdata.NetworkResource{ID: "res-1", NetworkID: "net-1", Enabled: true}
		nmd.NetworkResources = []*nmdata.NetworkResource{res}
		rp := newPolicy("rp-1", newRule([]string{"g-clients"}, []string{"g-resource"}))
		nmd.Policies = []*nmdata.Policy{rp}
		nmd.ResourcePolicies = map[string][]*nmdata.Policy{"res-1": {rp}}
		nmd.Routers = map[string]map[string]*nmdata.NetworkRouter{"net-1": {router.ID: {}}}
		return nmd, res, rp
	}

	assertResourceSkipped := func(t *testing.T, c *nbtypes.NetworkMapComponents) {
		t.Helper()
		assert.Empty(t, c.NetworkResources)
		assert.Empty(t, c.RoutersMap)
		assert.Empty(t, c.RouterPeers)
		assert.Empty(t, c.ResourcePoliciesMap)
	}

	t.Run("baseline grants access", func(t *testing.T) {
		nmd, res, _ := build()
		c := compute(nmd, targetID)
		assert.Equal(t, []*nmdata.NetworkResource{res}, c.NetworkResources)
	})

	t.Run("disabled resource skipped", func(t *testing.T) {
		nmd, res, _ := build()
		res.Enabled = false
		assertResourceSkipped(t, compute(nmd, targetID))
	})

	t.Run("resource without policies skipped", func(t *testing.T) {
		nmd, _, _ := build()
		nmd.ResourcePolicies = nil
		assertResourceSkipped(t, compute(nmd, targetID))
	})

	t.Run("peer neither router nor in sources skipped", func(t *testing.T) {
		nmd, _, _ := build()
		nmd.Groups["g-clients"].Peers = []string{"peer-router"}
		c := compute(nmd, targetID)
		assertResourceSkipped(t, c)
		assert.ElementsMatch(t, []string{targetID}, peerIDSet(c.Peers))
	})

	t.Run("nil and rule-less resource policy entries tolerated", func(t *testing.T) {
		nmd, res, rp := build()
		nmd.NetworkResources = append([]*nmdata.NetworkResource{nil}, nmd.NetworkResources...)
		rp.Rules = append(rp.Rules, nil)
		nmd.ResourcePolicies["res-1"] = append([]*nmdata.Policy{nil, {ID: "rp-empty", Enabled: true}}, nmd.ResourcePolicies["res-1"]...)

		c := compute(nmd, targetID)

		assert.Equal(t, []*nmdata.NetworkResource{res}, c.NetworkResources,
			"poisoned sibling entries must not prevent the valid policy from granting access")
		assert.NotPanics(t, func() { c.Calculate(context.Background()) },
			"the downstream network map calculation must survive the poisoned components")
	})

	t.Run("granting policy without routers still ships the resource", func(t *testing.T) {
		nmd, res, rp := build()
		nmd.Routers = nil
		c := compute(nmd, targetID)
		assert.Equal(t, []*nmdata.NetworkResource{res}, c.NetworkResources)
		assert.Equal(t, map[string][]*nmdata.Policy{"res-1": {rp}}, c.ResourcePoliciesMap)
		assert.Contains(t, c.RoutersMap, "net-1")
		assert.Empty(t, c.RoutersMap["net-1"])
		assert.Empty(t, c.RouterPeers)
	})

	t.Run("target failing resource policy posture check skipped", func(t *testing.T) {
		nmd, _, rp := build()
		addVersionCheck(nmd, "pc-1", postureMinVersion)
		rp.SourcePostureChecks = []string{"pc-1"}
		nmd.Policies = nil
		nmd.Peers[targetID].Meta.WtVersion = failingVersion
		c := compute(nmd, targetID)
		assertResourceSkipped(t, c)
		assert.Empty(t, c.PostureFailedPeers)
		assert.ElementsMatch(t, []string{targetID}, peerIDSet(c.Peers))
	})
}

// Legacy parity: resource-policy access consults only Rules[0] for peer-type
// sources, while group sources union across all rules via SourceGroups.
func TestGetPeerNetworkMapComponents_MultiRulePolicies(t *testing.T) {
	t.Run("policy matching via multiple rules ships once", func(t *testing.T) {
		target := newPeer(targetID, 1)
		a := newPeer("peer-a", 2)
		b := newPeer("peer-b", 3)
		nmd := newNMD(target, a, b)
		addGroup(nmd, "g-tgt", targetID)
		addGroup(nmd, "g-a", a.ID)
		addGroup(nmd, "g-b", b.ID)
		p := newPolicy("p-1",
			newRule([]string{"g-tgt"}, []string{"g-a"}),
			newRule([]string{"g-tgt"}, []string{"g-b"}))
		nmd.Policies = []*nmdata.Policy{p}

		c := compute(nmd, targetID)

		assert.Equal(t, []string{"p-1"}, policyIDs(c.Policies))
		assert.ElementsMatch(t, []string{targetID, a.ID, b.ID}, peerIDSet(c.Peers))
	})

	t.Run("resource access consults only the first rule's peer source", func(t *testing.T) {
		target := newPeer(targetID, 1)
		other := newPeer("peer-other", 2)
		router := newPeer("peer-router", 3)
		nmd := newNMD(target, other, router)
		addGroup(nmd, "g-other", other.ID)
		res := &nmdata.NetworkResource{ID: "res-1", NetworkID: "net-1", Enabled: true}
		nmd.NetworkResources = []*nmdata.NetworkResource{res}
		second := newRule(nil, nil)
		second.SourceResource = nmdata.Resource{ID: targetID, Type: string(nbtypes.ResourceTypePeer)}
		rp := newPolicy("rp-1", newRule([]string{"g-other"}, nil), second)
		nmd.ResourcePolicies = map[string][]*nmdata.Policy{"res-1": {rp}}
		nmd.Routers = map[string]map[string]*nmdata.NetworkRouter{"net-1": {router.ID: {}}}

		c := compute(nmd, targetID)

		assert.Empty(t, c.NetworkResources,
			"a second rule naming the target as peer source must not grant resource access")
	})

	t.Run("router-side source collection consults only the first rule's peer source", func(t *testing.T) {
		target := newPeer(targetID, 1)
		x := newPeer("peer-x", 2)
		y := newPeer("peer-y", 3)
		nmd := newNMD(target, x, y)
		addGroup(nmd, "g-y", y.ID)
		res := &nmdata.NetworkResource{ID: "res-1", NetworkID: "net-1", Enabled: true}
		nmd.NetworkResources = []*nmdata.NetworkResource{res}
		first := newRule(nil, nil)
		first.SourceResource = nmdata.Resource{ID: x.ID, Type: string(nbtypes.ResourceTypePeer)}
		rp := newPolicy("rp-1", first, newRule([]string{"g-y"}, nil))
		nmd.ResourcePolicies = map[string][]*nmdata.Policy{"res-1": {rp}}
		nmd.Routers = map[string]map[string]*nmdata.NetworkRouter{"net-1": {targetID: {}}}

		c := compute(nmd, targetID)

		assert.ElementsMatch(t, []string{targetID, x.ID}, peerIDSet(c.Peers),
			"second-rule group sources are not collected when the first rule names a peer")
	})
}

// Characterization of legacy parity: once one resource policy grants the peer
// access, the source peers of the resource's subsequent policies are collected
// as if the peer were a router.
func TestGetPeerNetworkMapComponents_NetworkResources_LaterPoliciesContributeSourcePeers(t *testing.T) {
	target := newPeer(targetID, 1)
	otherSrc := newPeer("peer-other-src", 2)
	router := newPeer("peer-router", 3)
	nmd := newNMD(target, otherSrc, router)
	addGroup(nmd, "g-a", targetID)
	addGroup(nmd, "g-b", otherSrc.ID)
	addGroup(nmd, "g-resource")
	res := &nmdata.NetworkResource{ID: "res-1", NetworkID: "net-1", Enabled: true}
	nmd.NetworkResources = []*nmdata.NetworkResource{res}
	rpA := newPolicy("rp-a", newRule([]string{"g-a"}, []string{"g-resource"}))
	rpB := newPolicy("rp-b", newRule([]string{"g-b"}, []string{"g-resource"}))
	nmd.ResourcePolicies = map[string][]*nmdata.Policy{"res-1": {rpA, rpB}}
	nmd.Routers = map[string]map[string]*nmdata.NetworkRouter{"net-1": {router.ID: {}}}

	c := compute(nmd, targetID)

	assert.Contains(t, c.Peers, otherSrc.ID)
}

func TestGetPeerNetworkMapComponents_StoreImmutableAndDeterministic(t *testing.T) {
	zone := nmdata.CustomZone{
		Domain:  "acme.netbird.cloud.",
		Records: []nmdata.SimpleRecord{{Name: "peer-src", Type: 1, Class: "IN", TTL: 300, RData: "100.64.0.2"}},
	}
	build := func() *networkmap.NetworkMapData {
		target := newPeer(targetID, 1)
		src := newPeer("peer-src", 2)
		failing := newPeer("peer-failing", 3)
		failing.Meta.WtVersion = failingVersion
		router := newPeer("peer-router", 4)
		resRouter := newPeer("peer-res-router", 5)
		nmd := newNMD(target, src, failing, router, resRouter)
		addVersionCheck(nmd, "pc-1", postureMinVersion)
		addGroup(nmd, "g-src", src.ID, failing.ID)
		addGroup(nmd, "g-dst", targetID, src.ID)
		addGroup(nmd, "g-dist", targetID, src.ID)
		addGroup(nmd, "g-auth", src.ID)
		addGroup(nmd, "g-clients", targetID)
		addGroup(nmd, "g-resource")
		nmd.AllowedUserIDs = map[string]struct{}{"user-1": {}}
		nmd.GroupIDToUserIDs = map[string][]string{"g-auth": {"user-a"}}
		checked := newPolicy("p-checked", newRule([]string{"g-src"}, []string{"g-dst"}))
		checked.SourcePostureChecks = []string{"pc-1"}
		open := newPolicy("p-open", newRule([]string{"g-src"}, []string{"g-dst"}))
		sshAuth := newRule([]string{"g-src"}, []string{"g-dst"})
		sshAuth.Protocol = string(nbtypes.PolicyRuleProtocolNetbirdSSH)
		sshAuth.AuthorizedGroups = map[string][]string{"g-auth": nil}
		sshPlain := newRule([]string{"g-src"}, []string{"g-dst"})
		sshPlain.Protocol = string(nbtypes.PolicyRuleProtocolNetbirdSSH)
		rp := newPolicy("rp-1", newRule([]string{"g-clients"}, []string{"g-resource"}))
		nmd.Policies = []*nmdata.Policy{checked, open, newPolicy("p-ssh", sshAuth, sshPlain), rp}
		nmd.Routes = []*nmdata.Route{{ID: "r-1", Peer: router.ID, Enabled: true, Groups: []string{"g-dist"}}}
		nmd.NetworkResources = []*nmdata.NetworkResource{{ID: "res-1", NetworkID: "net-1", Enabled: true}}
		nmd.ResourcePolicies = map[string][]*nmdata.Policy{"res-1": {rp}}
		nmd.Routers = map[string]map[string]*nmdata.NetworkRouter{"net-1": {resRouter.ID: {Metric: 100}}}
		nmd.NameServerGroups = []*nmdata.NameServerGroup{{ID: "ns-1", Enabled: true, Groups: []string{"g-dst"}}}
		nmd.AppliedZoneCandidates = []networkmap.AppliedZoneCandidate{
			{DistributionGroups: []string{"g-dst"}, Zone: nmdata.CustomZone{Domain: "zone.example.com.", Records: []nmdata.SimpleRecord{{Name: "z", Type: 1, RData: "100.64.0.9"}}}},
		}
		nmd.PrivateServiceCandidates = []networkmap.PrivateServiceCandidate{
			{AccessGroups: []string{"g-dst"}, Zone: nmdata.CustomZone{Domain: "svc.example.com", Records: []nmdata.SimpleRecord{{Name: "s", Type: 1, RData: "100.64.0.8"}}}},
		}
		return nmd
	}

	nmd := build()
	groupSnapshots := make(map[string][]string, len(nmd.Groups))
	for id, g := range nmd.Groups {
		groupSnapshots[id] = append([]string(nil), g.Peers...)
	}

	first := nmd.GetPeerNetworkMapComponents(targetID, zone)
	_ = nmd.GetPeerNetworkMapComponents("peer-src", zone)
	second := nmd.GetPeerNetworkMapComponents(targetID, zone)

	for id, g := range nmd.Groups {
		assert.Equal(t, groupSnapshots[id], g.Peers, "group %s mutated in the store", id)
	}

	for name, field := range map[string]any{
		"Peers":               first.Peers,
		"PostureFailedPeers":  first.PostureFailedPeers,
		"RoutersMap":          first.RoutersMap,
		"RouterPeers":         first.RouterPeers,
		"NetworkResources":    first.NetworkResources,
		"NameServerGroups":    first.NameServerGroups,
		"AccountZones":        first.AccountZones,
		"AllDNSRecords":       first.AllDNSRecords,
		"AllowedUserIDs":      first.AllowedUserIDs,
		"GroupIDToUserIDs":    first.GroupIDToUserIDs,
		"ResourcePoliciesMap": first.ResourcePoliciesMap,
	} {
		require.NotEmpty(t, field, "fixture must populate %s or the determinism check is vacuous", name)
	}

	assert.Equal(t, first.Peers, second.Peers)
	assert.Equal(t, first.Groups, second.Groups)
	assert.Equal(t, first.Policies, second.Policies)
	assert.Equal(t, first.Routes, second.Routes)
	assert.Equal(t, first.PostureFailedPeers, second.PostureFailedPeers)
	assert.Equal(t, first.ResourcePoliciesMap, second.ResourcePoliciesMap)
	assert.Equal(t, first.RoutersMap, second.RoutersMap)
	assert.Equal(t, first.RouterPeers, second.RouterPeers)
	assert.Equal(t, first.NetworkResources, second.NetworkResources)
	assert.Equal(t, first.NameServerGroups, second.NameServerGroups)
	assert.Equal(t, first.AccountZones, second.AccountZones)
	assert.Equal(t, first.AllDNSRecords, second.AllDNSRecords)
	assert.Equal(t, first.AllowedUserIDs, second.AllowedUserIDs)
	assert.Equal(t, first.GroupIDToUserIDs, second.GroupIDToUserIDs)
}

func TestPrecomputePostureValidation(t *testing.T) {
	newFixture := func() *networkmap.NetworkMapData {
		target := newPeer(targetID, 1)
		srcPass := newPeer("peer-src-pass", 2)
		srcFail := newPeer("peer-src-fail", 3)
		srcFail.Meta.WtVersion = failingVersion
		other := newPeer("peer-other", 4)
		other.Meta.WtVersion = failingVersion

		nmd := newNMD(target, srcPass, srcFail, other)
		addVersionCheck(nmd, "pc-1", postureMinVersion)
		addGroup(nmd, "g-src", srcPass.ID, srcFail.ID)
		addGroup(nmd, "g-dst", targetID)
		addGroup(nmd, "g-open", srcPass.ID, srcFail.ID, other.ID)

		checked := newPolicy("p-checked", newRule([]string{"g-src"}, []string{"g-dst"}))
		checked.SourcePostureChecks = []string{"pc-1"}
		open := newPolicy("p-open", newRule([]string{"g-open"}, []string{"g-dst"}))
		disabled := newPolicy("p-disabled", newRule([]string{"g-open"}, []string{"g-dst"}))
		disabled.Enabled = false
		disabled.SourcePostureChecks = []string{"pc-1"}
		nmd.Policies = []*nmdata.Policy{checked, open, disabled}

		return nmd
	}

	type snapshot struct {
		peers              []string
		postureFailedPeers map[string]map[string]struct{}
	}
	snapshotAll := func(nmd *networkmap.NetworkMapData) map[string]snapshot {
		out := make(map[string]snapshot, len(nmd.Peers))
		for peerID := range nmd.Peers {
			c := compute(nmd, peerID)
			out[peerID] = snapshot{peers: peerIDSet(c.Peers), postureFailedPeers: c.PostureFailedPeers}
		}
		return out
	}

	t.Run("memoized results match direct evaluation", func(t *testing.T) {
		nmd := newFixture()
		direct := snapshotAll(nmd)

		nmd.PrecomputePostureValidation()
		memoized := snapshotAll(nmd)

		require.Len(t, memoized, len(direct))
		for peerID, want := range direct {
			assert.ElementsMatch(t, want.peers, memoized[peerID].peers, "visible peers changed for %s", peerID)
			assert.Equal(t, want.postureFailedPeers, memoized[peerID].postureFailedPeers, "posture failures changed for %s", peerID)
		}
	})

	t.Run("only source peers of enabled checked policies are evaluated", func(t *testing.T) {
		nmd := newFixture()
		nmd.PrecomputePostureValidation()

		assert.Equal(t, map[string]map[string]bool{
			"pc-1": {"peer-src-pass": true, "peer-src-fail": false},
		}, nmd.PostureValidation)
	})

	t.Run("peer source resources are evaluated", func(t *testing.T) {
		nmd := newFixture()
		resourcePolicy := newPolicy("p-resource", newRule(nil, []string{"g-dst"}))
		resourcePolicy.Rules[0].SourceResource = nmdata.Resource{ID: "peer-other", Type: string(nbtypes.ResourceTypePeer)}
		resourcePolicy.SourcePostureChecks = []string{"pc-1"}
		nmd.Policies = append(nmd.Policies, resourcePolicy)

		nmd.PrecomputePostureValidation()

		assert.Equal(t, map[string]bool{"peer-src-pass": true, "peer-src-fail": false, "peer-other": false},
			nmd.PostureValidation["pc-1"])
	})

	t.Run("memoized result wins over direct evaluation", func(t *testing.T) {
		nmd := newFixture()
		nmd.PostureValidation = map[string]map[string]bool{
			"pc-1": {"peer-src-pass": false, "peer-src-fail": true},
		}

		c := compute(nmd, targetID)

		assert.Equal(t, map[string]map[string]struct{}{"pc-1": {"peer-src-pass": {}}}, c.PostureFailedPeers)
	})

	t.Run("no posture checks clears the memo", func(t *testing.T) {
		nmd := newFixture()
		nmd.PrecomputePostureValidation()
		require.NotEmpty(t, nmd.PostureValidation)

		nmd.PostureChecks = nil
		nmd.PrecomputePostureValidation()

		assert.Nil(t, nmd.PostureValidation)
	})

	t.Run("unresolvable check id memoized as passing", func(t *testing.T) {
		nmd := newFixture()
		nmd.Policies[0].SourcePostureChecks = []string{"pc-ghost"}
		nmd.PrecomputePostureValidation()

		require.Contains(t, nmd.PostureValidation, "pc-ghost")
		assert.Nil(t, nmd.PostureValidation["pc-ghost"])

		c := compute(nmd, targetID)
		assert.ElementsMatch(t, []string{targetID, "peer-src-pass", "peer-src-fail", "peer-other"}, peerIDSet(c.Peers))
		assert.Empty(t, c.PostureFailedPeers)
	})

	t.Run("peers missing from the memo fall back to direct evaluation", func(t *testing.T) {
		nmd := newFixture()
		nmd.PostureValidation = map[string]map[string]bool{"pc-1": {"peer-src-pass": true}}

		c := compute(nmd, targetID)

		assert.Equal(t, map[string]map[string]struct{}{"pc-1": {"peer-src-fail": {}}}, c.PostureFailedPeers)
	})
}

func TestNetworkMapData_GetPeerGroups(t *testing.T) {
	target := newPeer(targetID, 1)
	other := newPeer("peer-other", 2)
	nmd := newNMD(target, other)
	addGroup(nmd, "g-1", targetID, other.ID)
	addGroup(nmd, "g-2", targetID)
	addGroup(nmd, "g-3", other.ID)
	nmd.Groups["g-nil"] = nil

	assert.Equal(t, map[string]struct{}{"g-1": {}, "g-2": {}}, nmd.GetPeerGroups(targetID))
	assert.Empty(t, nmd.GetPeerGroups("missing"))
}
