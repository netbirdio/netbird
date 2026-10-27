package affectedpeers

import (
	"context"
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

func TestExpand_NilSnapshot(t *testing.T) {
	var snap *Snapshot
	assert.Nil(t, snap.Expand(context.Background(), "acc", Change{ChangedGroupIDs: []string{"g"}}))
}

func TestChangeIsEmpty(t *testing.T) {
	assert.True(t, Change{}.isEmpty())
	assert.False(t, Change{ChangedGroupIDs: []string{"g"}}.isEmpty())
	assert.False(t, Change{ChangedPeerIDs: []string{"p"}}.isEmpty())
	assert.False(t, Change{Policies: []*types.Policy{{}}}.isEmpty())
	assert.False(t, Change{Resources: []*resourceTypes.NetworkResource{{ID: "r"}}}.isEmpty())
	assert.False(t, Change{Networks: []*networkTypes.Network{{ID: "n"}}}.isEmpty())
	assert.False(t, Change{PostureCheckIDs: []string{"pc"}}.isEmpty())
	assert.False(t, Change{UserGroupIDs: []string{"g"}}.isEmpty())
	assert.False(t, Change{AllowedUsersChanged: true}.isEmpty())
	assert.False(t, Change{ChangedUserIDs: []string{"u"}}.isEmpty())
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

func TestRuleShipsAllowedUsers_OnlyAcceptRules(t *testing.T) {
	tests := []struct {
		name string
		rule *types.PolicyRule
		want bool
	}{
		{"accept netbird-ssh", &types.PolicyRule{Protocol: types.PolicyRuleProtocolNetbirdSSH, Action: types.PolicyTrafficActionAccept}, true},
		{"drop netbird-ssh", &types.PolicyRule{Protocol: types.PolicyRuleProtocolNetbirdSSH, Action: types.PolicyTrafficActionDrop}, false},
		{"accept all protocols", &types.PolicyRule{Protocol: types.PolicyRuleProtocolALL, Action: types.PolicyTrafficActionAccept}, true},
		{"drop all protocols", &types.PolicyRule{Protocol: types.PolicyRuleProtocolALL, Action: types.PolicyTrafficActionDrop}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, ruleShipsAllowedUsers(tt.rule))
		})
	}
}

func TestExpand_ChangedUserIDs_FoldsAuthorizedUserRuleDestinations(t *testing.T) {
	sshRule := func(action types.PolicyTrafficActionType, authorizedUser, destination string) *types.PolicyRule {
		return &types.PolicyRule{
			Enabled:        true,
			Sources:        []string{"src"},
			Destinations:   []string{destination},
			Protocol:       types.PolicyRuleProtocolNetbirdSSH,
			Action:         action,
			AuthorizedUser: authorizedUser,
		}
	}
	snap := &Snapshot{
		policies: []*types.Policy{{
			Enabled: true,
			Rules: []*types.PolicyRule{
				sshRule(types.PolicyTrafficActionAccept, "user-1", "dst-accept"),
				sshRule(types.PolicyTrafficActionDrop, "user-1", "dst-drop"),
				sshRule(types.PolicyTrafficActionAccept, "user-2", "dst-other-user"),
			},
		}},
		groupPeers: map[string]map[string]struct{}{
			"src":            {"peer-src": {}},
			"dst-accept":     {"peer-accept": {}},
			"dst-drop":       {"peer-drop": {}},
			"dst-other-user": {"peer-other-user": {}},
		},
	}

	affected := snap.Expand(context.Background(), "acc", Change{ChangedUserIDs: []string{"user-1"}})

	assert.ElementsMatch(t, []string{"peer-accept"}, affected)
}
