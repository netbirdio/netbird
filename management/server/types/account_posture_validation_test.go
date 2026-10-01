package types_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	nbdns "github.com/netbirdio/netbird/dns"
	"github.com/netbirdio/netbird/management/server/posture"
)

func TestPrecomputePostureValidation_MatchesDirectEvaluation(t *testing.T) {
	account, validatedPeers := scalableTestAccount(60, 5)

	account.PostureChecks = append(account.PostureChecks, &posture.Checks{
		ID: "posture-check-strict", Name: "Strict version",
		Checks: posture.ChecksDefinition{
			NBVersionCheck: &posture.NBVersionCheck{MinVersion: "0.50.0"},
		},
	})
	account.Policies[0].SourcePostureChecks = []string{"posture-check-ver", "posture-check-unknown"}
	account.Policies[1].SourcePostureChecks = []string{"posture-check-strict"}
	account.Policies[2].SourcePostureChecks = []string{"posture-check-ver"}
	account.Policies[2].Enabled = false

	ctx := context.Background()
	resourcePolicies := account.GetResourcePoliciesMap()
	routers := account.GetResourceRoutersMap()

	type result struct {
		peers              map[string]struct{}
		postureFailedPeers map[string]map[string]struct{}
	}
	snapshot := func() map[string]result {
		results := make(map[string]result, len(account.Peers))
		for peerID := range account.Peers {
			components := account.GetPeerNetworkMapComponents(ctx, peerID, nbdns.CustomZone{}, nil, validatedPeers, resourcePolicies, routers, nil)
			require.NotNil(t, components)
			peerSet := make(map[string]struct{}, len(components.Peers))
			for id := range components.Peers {
				peerSet[id] = struct{}{}
			}
			results[peerID] = result{peers: peerSet, postureFailedPeers: components.PostureFailedPeers}
		}
		return results
	}

	direct := snapshot()
	account.PrecomputePostureValidation(ctx)
	memoized := snapshot()

	require.Equal(t, len(direct), len(memoized))
	for peerID, want := range direct {
		got := memoized[peerID]
		assert.Equal(t, want.peers, got.peers, "visible peers changed for %s", peerID)
		assert.Equal(t, want.postureFailedPeers, got.postureFailedPeers, "posture failed peers changed for %s", peerID)
	}
}

func TestPrecomputePostureValidation_NoPostureChecks(t *testing.T) {
	account, validatedPeers := scalableTestAccount(10, 2)
	account.PostureChecks = nil

	ctx := context.Background()
	account.PrecomputePostureValidation(ctx)

	components := account.GetPeerNetworkMapComponents(ctx, "peer-0", nbdns.CustomZone{}, nil, validatedPeers, account.GetResourcePoliciesMap(), account.GetResourceRoutersMap(), nil)
	require.NotNil(t, components)
	assert.NotEmpty(t, components.Peers)
}
