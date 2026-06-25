package affectedpeers

import (
	"testing"

	"github.com/stretchr/testify/assert"

	resourceTypes "github.com/netbirdio/netbird/management/server/networks/resources/types"
	networkTypes "github.com/netbirdio/netbird/management/server/networks/types"
	"github.com/netbirdio/netbird/management/server/types"
)

// policyGroupsAndPeers mirrors the explicit-policy extraction (RuleGroups +
// direct peers) the resolver folds in, for asserting the pure logic.
func policyGroupsAndPeers(policies ...*types.Policy) (groups []string, peers []string) {
	peerSet := map[string]struct{}{}
	for _, p := range policies {
		if p == nil {
			continue
		}
		groups = append(groups, p.RuleGroups()...)
		collectPolicyDirectPeers(p, peerSet)
	}
	for id := range peerSet {
		peers = append(peers, id)
	}
	return groups, peers
}

func TestPolicyGroupsAndPeers_Basic(t *testing.T) {
	policy := &types.Policy{Rules: []*types.PolicyRule{{Sources: []string{"g1", "g2"}, Destinations: []string{"g3"}}}}
	groups, peers := policyGroupsAndPeers(policy)
	assert.ElementsMatch(t, []string{"g1", "g2", "g3"}, groups)
	assert.Empty(t, peers)
}

func TestPolicyGroupsAndPeers_WithPeerResources(t *testing.T) {
	policy := &types.Policy{Rules: []*types.PolicyRule{{
		Sources:             []string{"g1"},
		SourceResource:      types.Resource{ID: "p1", Type: types.ResourceTypePeer},
		Destinations:        []string{"g2"},
		DestinationResource: types.Resource{ID: "p2", Type: types.ResourceTypePeer},
	}}}
	groups, peers := policyGroupsAndPeers(policy)
	assert.ElementsMatch(t, []string{"g1", "g2"}, groups)
	assert.ElementsMatch(t, []string{"p1", "p2"}, peers)
}

func TestPolicyGroupsAndPeers_NilPolicy(t *testing.T) {
	groups, peers := policyGroupsAndPeers(nil)
	assert.Nil(t, groups)
	assert.Nil(t, peers)
}

func TestPolicyGroupsAndPeers_MultiplePolicies(t *testing.T) {
	old := &types.Policy{Rules: []*types.PolicyRule{{Sources: []string{"g1"}, Destinations: []string{"g2"}}}}
	updated := &types.Policy{Rules: []*types.PolicyRule{{Sources: []string{"g3"}, Destinations: []string{"g4"}}}}
	groups, _ := policyGroupsAndPeers(updated, old)
	assert.ElementsMatch(t, []string{"g1", "g2", "g3", "g4"}, groups)
}

func TestPolicyGroupsAndPeers_NonPeerResource(t *testing.T) {
	policy := &types.Policy{Rules: []*types.PolicyRule{{
		Sources:        []string{"g1"},
		SourceResource: types.Resource{ID: "domain-1", Type: types.ResourceTypeDomain},
		Destinations:   []string{"g2"},
	}}}
	groups, peers := policyGroupsAndPeers(policy)
	assert.ElementsMatch(t, []string{"g1", "g2"}, groups)
	assert.Empty(t, peers, "domain resource type should not produce direct peer IDs")
}

func TestChangeIsEmpty(t *testing.T) {
	assert.True(t, Change{}.isEmpty())
	assert.False(t, Change{ChangedGroupIDs: []string{"g"}}.isEmpty())
	assert.False(t, Change{ChangedPeerIDs: []string{"p"}}.isEmpty())
	assert.False(t, Change{Policies: []*types.Policy{{}}}.isEmpty())
	assert.False(t, Change{Resources: []*resourceTypes.NetworkResource{{ID: "r"}}}.isEmpty())
	assert.False(t, Change{Networks: []*networkTypes.Network{{ID: "n"}}}.isEmpty())
	assert.False(t, Change{PostureCheckIDs: []string{"pc"}}.isEmpty())
}

func TestGroupsFromPolicyDirectionally(t *testing.T) {
	policy := &types.Policy{Rules: []*types.PolicyRule{
		{Sources: []string{"g1", "g2"}, Destinations: []string{"g3"}},
		{Sources: []string{"g4"}, Destinations: []string{"g5", "g6"}},
		{Sources: []string{"g7"}, Destinations: []string{"g8"},
			SourceResource:      types.Resource{ID: "r7", Type: types.ResourceTypePeer},
			DestinationResource: types.Resource{ID: "r8", Type: types.ResourceTypePeer}},
		{Sources: []string{"g9"}, Destinations: []string{"g10"},
			SourceResource:      types.Resource{ID: "", Type: types.ResourceTypePeer},
			DestinationResource: types.Resource{ID: "", Type: types.ResourceTypePeer}},
		{Sources: []string{"g11"}, Destinations: []string{"g12"},
			SourceResource:      types.Resource{ID: "r11", Type: types.ResourceTypeHost},
			DestinationResource: types.Resource{ID: "r12", Type: types.ResourceTypeHost}},
	}}

	var tests = []struct {
		name             string
		inGroups         map[string]struct{}
		expectedPeerIds  []string
		expectedGroupIds []string
	}{
		{
			name:             "match sources",
			inGroups:         map[string]struct{}{"g1": {}, "g4": {}},
			expectedPeerIds:  []string{},
			expectedGroupIds: []string{"g1", "g4", "g3", "g5", "g6"},
		},
		{
			name:             "match destinations",
			inGroups:         map[string]struct{}{"g3": {}, "g6": {}},
			expectedPeerIds:  []string{},
			expectedGroupIds: []string{"g1", "g2", "g4", "g3", "g6"},
		},
		{
			name:             "should return destinations and destination resource",
			inGroups:         map[string]struct{}{"g7": {}},
			expectedPeerIds:  []string{"r8"},
			expectedGroupIds: []string{"g7", "g8"},
		},
		{
			name:             "should return sources and source resource",
			inGroups:         map[string]struct{}{"g8": {}},
			expectedPeerIds:  []string{"r7"},
			expectedGroupIds: []string{"g7", "g8"},
		},
		{
			name:             "should not return source resource (empty id)",
			inGroups:         map[string]struct{}{"g10": {}},
			expectedPeerIds:  []string{},
			expectedGroupIds: []string{"g9", "g10"},
		},
		{
			name:             "should not return destination resource (empty id)",
			inGroups:         map[string]struct{}{"g9": {}},
			expectedPeerIds:  []string{},
			expectedGroupIds: []string{"g9", "g10"},
		},
		{
			name:             "should not return source resource (non-peer type)",
			inGroups:         map[string]struct{}{"g12": {}},
			expectedPeerIds:  []string{},
			expectedGroupIds: []string{"g11", "g12"},
		},
		{
			name:             "should not return destination resource (non-peer type)",
			inGroups:         map[string]struct{}{"g12": {}},
			expectedPeerIds:  []string{},
			expectedGroupIds: []string{"g11", "g12"},
		},
		{
			name:             "non-existing group",
			inGroups:         map[string]struct{}{"g33": {}},
			expectedPeerIds:  []string{},
			expectedGroupIds: []string{},
		},
		{
			name:             "empty groupset",
			inGroups:         map[string]struct{}{},
			expectedPeerIds:  []string{},
			expectedGroupIds: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			peerIds, groupIds := getGroupsAndPeersFromPolicyViaGroups(policy, tt.inGroups)
			assert.ElementsMatch(t, peerIds, tt.expectedPeerIds)
			assert.ElementsMatch(t, groupIds, tt.expectedGroupIds)
		})
	}
}

func TestPolicyReferencesDirectPeers(t *testing.T) {
	policy := &types.Policy{Rules: []*types.PolicyRule{
		{
			SourceResource:      types.Resource{Type: types.ResourceTypePeer, ID: "p1"},
			DestinationResource: types.Resource{Type: types.ResourceTypePeer, ID: "r1"},
			Sources:             []string{"sg1"},
			Destinations:        []string{"dg1"},
		},
		{
			SourceResource:      types.Resource{Type: types.ResourceTypePeer, ID: "p2"},
			DestinationResource: types.Resource{Type: types.ResourceTypePeer, ID: "r2"},
			Sources:             []string{"sg2"},
			Destinations:        []string{"dg2"},
		},
		{
			SourceResource:      types.Resource{Type: types.ResourceTypePeer, ID: "p3"},
			DestinationResource: types.Resource{Type: types.ResourceTypeHost, ID: "r3"},
			Sources:             []string{"sg3"},
			Destinations:        []string{"dg3"},
		},
		{
			SourceResource:      types.Resource{Type: types.ResourceTypeHost, ID: "p4"},
			DestinationResource: types.Resource{Type: types.ResourceTypePeer, ID: "r4"},
			Sources:             []string{"sg4"},
			Destinations:        []string{"dg4"},
		},
		{
			SourceResource:      types.Resource{Type: types.ResourceTypeHost, ID: "p5"},
			DestinationResource: types.Resource{Type: types.ResourceTypePeer, ID: "r5"},
			Sources:             []string{"sg5"},
			Destinations:        []string{"dg5"},
		},
		{
			SourceResource:      types.Resource{Type: types.ResourceTypePeer, ID: "p6"},
			DestinationResource: types.Resource{Type: types.ResourceTypeHost, ID: "r6"},
			Sources:             []string{"sg6"},
			Destinations:        []string{"dg6"},
		},
		{
			SourceResource:      types.Resource{Type: types.ResourceTypePeer, ID: "p7"},
			DestinationResource: types.Resource{Type: types.ResourceTypePeer, ID: "r7"},
			Sources:             []string{"sg7"},
			Destinations:        []string{"dg7"},
		},
	}}

	var tests = []struct {
		name             string
		changedPeerIds   map[string]struct{}
		expectedPeerIds  []string
		expectedGroupIds []string
	}{
		{
			name:             "match sources",
			changedPeerIds:   map[string]struct{}{"p1": {}, "p2": {}},
			expectedPeerIds:  []string{"p1", "p2", "r1", "r2"},
			expectedGroupIds: []string{"dg1", "dg2"},
		},
		{
			name:             "match destinations",
			changedPeerIds:   map[string]struct{}{"r1": {}, "r2": {}},
			expectedPeerIds:  []string{"r1", "r2", "p1", "p2"},
			expectedGroupIds: []string{"sg1", "sg2"},
		},
		{
			name:             "wrong opposing peer types, only changed peer ids and groups on the opposing end of the rule",
			changedPeerIds:   map[string]struct{}{"p3": {}, "r4": {}},
			expectedPeerIds:  []string{"p3", "r4"},
			expectedGroupIds: []string{"dg3", "sg4"},
		},
		{
			name:             "wrong peer type, no matching peer ids",
			changedPeerIds:   map[string]struct{}{"p5": {}, "r6": {}},
			expectedPeerIds:  []string{},
			expectedGroupIds: []string{},
		},
		{
			name:             "changed peers on both sides of the policy",
			changedPeerIds:   map[string]struct{}{"p7": {}, "r7": {}},
			expectedPeerIds:  []string{"p7", "r7"},
			expectedGroupIds: []string{"sg7", "dg7"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			peerIds, groupIds := getGroupsAndPeersFromPolicyViaPeers(policy, tt.changedPeerIds)
			assert.ElementsMatch(t, peerIds, tt.expectedPeerIds)
			assert.ElementsMatch(t, groupIds, tt.expectedGroupIds)
		})
	}
}

func TestPolicyReferencesPostureChecks(t *testing.T) {
	policy := &types.Policy{SourcePostureChecks: []string{"pc1", "pc2"}}

	assert.True(t, policyReferencesPostureChecks(policy, map[string]struct{}{"pc1": {}}))
	assert.False(t, policyReferencesPostureChecks(policy, map[string]struct{}{"pc3": {}}))
}

func TestCollectPolicyDirectPeers(t *testing.T) {
	policy := &types.Policy{Rules: []*types.PolicyRule{{
		SourceResource:      types.Resource{Type: types.ResourceTypePeer, ID: "p1"},
		DestinationResource: types.Resource{Type: types.ResourceTypePeer, ID: "p2"},
	}, {
		DestinationResource: types.Resource{Type: types.ResourceTypeHost, ID: "r1"},
	}}}

	peerSet := map[string]struct{}{}
	collectPolicyDirectPeers(policy, peerSet)

	assert.Contains(t, peerSet, "p1")
	assert.Contains(t, peerSet, "p2")
	assert.NotContains(t, peerSet, "r1")
}

func TestCollectPolicySources(t *testing.T) {
	policy := &types.Policy{Rules: []*types.PolicyRule{{
		Sources:        []string{"g1"},
		SourceResource: types.Resource{Type: types.ResourceTypePeer, ID: "p1"},
		Destinations:   []string{"g2"},
	}}}

	groupSet := map[string]struct{}{}
	peerSet := map[string]struct{}{}
	collectPolicySources(policy, groupSet, peerSet)

	assert.Contains(t, groupSet, "g1")
	assert.NotContains(t, groupSet, "g2", "destination groups must not be collected as sources")
	assert.Contains(t, peerSet, "p1")
}
