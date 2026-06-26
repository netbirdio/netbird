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

func TestPolicyReferencesGroups(t *testing.T) {
	policy := &types.Policy{Rules: []*types.PolicyRule{{Sources: []string{"g1", "g2"}, Destinations: []string{"g3"}}}}

	assert.True(t, policyReferencesGroups(policy, map[string]struct{}{"g1": {}}))
	assert.True(t, policyReferencesGroups(policy, map[string]struct{}{"g3": {}}))
	assert.False(t, policyReferencesGroups(policy, map[string]struct{}{"g4": {}}))
	assert.False(t, policyReferencesGroups(policy, map[string]struct{}{}))
}

func TestPolicyReferencesDirectPeers(t *testing.T) {
	policy := &types.Policy{Rules: []*types.PolicyRule{{
		SourceResource:      types.Resource{Type: types.ResourceTypePeer, ID: "p1"},
		DestinationResource: types.Resource{Type: types.ResourceTypeHost, ID: "r1"},
	}}}

	assert.True(t, policyReferencesDirectPeers(policy, map[string]struct{}{"p1": {}}))
	assert.False(t, policyReferencesDirectPeers(policy, map[string]struct{}{"r1": {}}))
	assert.False(t, policyReferencesDirectPeers(policy, map[string]struct{}{"p2": {}}))
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
