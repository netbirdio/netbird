package server

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/server/affectedpeers"
	resourceTypes "github.com/netbirdio/netbird/management/server/networks/resources/types"
	networkTypes "github.com/netbirdio/netbird/management/server/networks/types"
	"github.com/netbirdio/netbird/management/server/posture"
	"github.com/netbirdio/netbird/management/server/types"
)

// TestAffectedPeers_DependencyCoverageMatrix enumerates each network-map
// dependency crossed with the change-type that can alter it, asserting the
// resolver folds in exactly the peers whose map changes. A new dependency that
// the resolver fails to walk should fail one of these rows; a new change-type
// without a row is a coverage gap to add here.
func TestAffectedPeers_DependencyCoverageMatrix(t *testing.T) {
	type row struct {
		name  string
		build func(t *testing.T, s *routerScenario, ctx context.Context) (affectedpeers.Change, []string, []string)
	}

	rows := []row{
		{
			name: "policy-groups/source-group-change refreshes source+routing, excludes unrelated",
			build: func(t *testing.T, s *routerScenario, ctx context.Context) (affectedpeers.Change, []string, []string) {
				_, err := s.manager.SavePolicy(ctx, s.accountID, userID, peerToResourcePolicyByGroup(s.sourceGroupID, s.resourceGroupID), true)
				require.NoError(t, err)
				return affectedpeers.Change{ChangedGroupIDs: []string{s.sourceGroupID}},
					[]string{s.sourcePeerID, s.routerPeerID}, []string{s.unrelatedPeerID}
			},
		},
		{
			name: "resource-routing-bridge/router-peer-change refreshes policy sources",
			build: func(t *testing.T, s *routerScenario, ctx context.Context) (affectedpeers.Change, []string, []string) {
				_, err := s.manager.SavePolicy(ctx, s.accountID, userID, peerToResourcePolicyByGroup(s.sourceGroupID, s.resourceGroupID), true)
				require.NoError(t, err)
				return affectedpeers.Change{ChangedPeerIDs: []string{s.routerPeerID}},
					[]string{s.sourcePeerID}, []string{s.unrelatedPeerID}
			},
		},
		{
			name: "policy-change/explicit-policy refreshes source+routing",
			build: func(t *testing.T, s *routerScenario, ctx context.Context) (affectedpeers.Change, []string, []string) {
				policy := peerToResourcePolicyByGroup(s.sourceGroupID, s.resourceGroupID)
				return affectedpeers.Change{Policies: []*types.Policy{policy}},
					[]string{s.sourcePeerID, s.routerPeerID}, []string{s.unrelatedPeerID}
			},
		},
		{
			name: "policy-destinationresource/explicit-policy bridges to routing peer",
			build: func(t *testing.T, s *routerScenario, ctx context.Context) (affectedpeers.Change, []string, []string) {
				policy := peerToResourcePolicyByResource(s.sourceGroupID, s.resourceID)
				return affectedpeers.Change{Policies: []*types.Policy{policy}},
					[]string{s.sourcePeerID, s.routerPeerID}, []string{s.unrelatedPeerID}
			},
		},
		{
			name: "resource-change refreshes source+routing on its network",
			build: func(t *testing.T, s *routerScenario, ctx context.Context) (affectedpeers.Change, []string, []string) {
				_, err := s.manager.SavePolicy(ctx, s.accountID, userID, peerToResourcePolicyByGroup(s.sourceGroupID, s.resourceGroupID), true)
				require.NoError(t, err)
				return affectedpeers.Change{Resources: []*resourceTypes.NetworkResource{
						{ID: s.resourceID, NetworkID: s.networkID, GroupIDs: []string{s.resourceGroupID}},
					}},
					[]string{s.sourcePeerID, s.routerPeerID}, []string{s.unrelatedPeerID}
			},
		},
		{
			name: "network-change refreshes source+routing on that network",
			build: func(t *testing.T, s *routerScenario, ctx context.Context) (affectedpeers.Change, []string, []string) {
				_, err := s.manager.SavePolicy(ctx, s.accountID, userID, peerToResourcePolicyByGroup(s.sourceGroupID, s.resourceGroupID), true)
				require.NoError(t, err)
				return affectedpeers.Change{Networks: []*networkTypes.Network{{ID: s.networkID}}},
					[]string{s.sourcePeerID, s.routerPeerID}, []string{s.unrelatedPeerID}
			},
		},
		{
			name: "posture-check-change refreshes source+routing of gated policy",
			build: func(t *testing.T, s *routerScenario, ctx context.Context) (affectedpeers.Change, []string, []string) {
				check, err := s.manager.SavePostureChecks(ctx, s.accountID, userID, &posture.Checks{
					Name:   "cov-min-version",
					Checks: posture.ChecksDefinition{NBVersionCheck: &posture.NBVersionCheck{MinVersion: "0.30.0"}},
				}, true)
				require.NoError(t, err)
				policy := peerToResourcePolicyByGroup(s.sourceGroupID, s.resourceGroupID)
				policy.SourcePostureChecks = []string{check.ID}
				_, err = s.manager.SavePolicy(ctx, s.accountID, userID, policy, true)
				require.NoError(t, err)
				return affectedpeers.Change{PostureCheckIDs: []string{check.ID}},
					[]string{s.sourcePeerID, s.routerPeerID}, []string{s.unrelatedPeerID}
			},
		},
	}

	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			s := setupRouterScenario(t, true)
			ctx := context.Background()

			change, mustContain, mustExclude := r.build(t, s, ctx)
			affected := resolveAffected(t, s.manager.Store, s.accountID, change)

			for _, id := range mustContain {
				assert.Contains(t, affected, id, "expected peer to be affected")
			}
			for _, id := range mustExclude {
				assert.NotContains(t, affected, id, "peer must not be affected")
			}
		})
	}
}
