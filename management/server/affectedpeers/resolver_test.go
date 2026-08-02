package affectedpeers

import (
	"testing"

	"github.com/stretchr/testify/assert"

	resourceTypes "github.com/netbirdio/netbird/management/server/networks/resources/types"
	networkTypes "github.com/netbirdio/netbird/management/server/networks/types"
	"github.com/netbirdio/netbird/management/server/types"
)

// policyGroupsAndPeers mirrors the both-sides extraction (RuleGroups + direct peers)
// the resolver folds in for a changed policy, for asserting the pure logic.
func policyGroupsAndPeers(policies ...*types.Policy) (groups []string, peers []string) {
	peerSet := map[string]struct{}{}
	for _, p := range policies {
		if p == nil {
			continue
		}
		groups = append(groups, p.RuleGroups()...)
		for _, rule := range p.Rules {
			if rule.SourceResource.Type == types.ResourceTypePeer && rule.SourceResource.ID != "" {
				peerSet[rule.SourceResource.ID] = struct{}{}
			}
			if rule.DestinationResource.Type == types.ResourceTypePeer && rule.DestinationResource.ID != "" {
				peerSet[rule.DestinationResource.ID] = struct{}{}
			}
		}
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

func TestPolicyReferencesPostureChecks(t *testing.T) {
	policy := &types.Policy{SourcePostureChecks: []string{"pc1", "pc2"}}

	assert.True(t, policyReferencesPostureChecks(policy, map[string]struct{}{"pc1": {}}))
	assert.False(t, policyReferencesPostureChecks(policy, map[string]struct{}{"pc3": {}}))
}

func TestCollectPolicySources(t *testing.T) {
	policy := &types.Policy{Rules: []*types.PolicyRule{{
		Enabled:        true,
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
