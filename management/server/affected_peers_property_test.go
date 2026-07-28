package server

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"sort"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/exp/maps"

	nbdns "github.com/netbirdio/netbird/dns"
	"github.com/netbirdio/netbird/management/server/affectedpeers"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
)

// allPeerMaps computes the serialized per-peer network map for every peer in the
// account, mirroring the controller's compute path so the property test compares
// against real output.
func allPeerMaps(t *testing.T, manager *DefaultAccountManager, accountID string) map[string]string {
	t.Helper()
	ctx := context.Background()

	account, err := manager.Store.GetAccount(ctx, accountID)
	require.NoError(t, err)

	account.InjectProxyPolicies(ctx)

	validated := make(map[string]struct{}, len(account.Peers))
	for id := range account.Peers {
		validated[id] = struct{}{}
	}
	resourcePolicies := account.GetResourcePoliciesMap()
	routers := account.GetResourceRoutersMap()
	groupIDToUserIDs := account.GetActiveGroupUsers()

	out := make(map[string]string, len(account.Peers))
	for peerID := range account.Peers {
		nm := account.GetPeerNetworkMapFromComponents(ctx, peerID, nbdns.CustomZone{}, nil, validated, resourcePolicies, routers, nil, groupIDToUserIDs)
		// Network.Serial is an account-global counter bumped on every change; it
		// is not a per-peer dependency, so normalize it out of the comparison.
		if nm.Network != nil {
			nm.Network.Serial = 0
		}
		out[peerID] = canonicalJSON(t, nm)
	}
	return out
}

// canonicalJSON marshals v and returns an order-insensitive string form: every
// JSON array is sorted by the canonical form of its elements. The network map's
// Peers/Routes/FirewallRules/SourceRanges slices have nondeterministic order, so
// a raw JSON compare would report spurious changes.
func canonicalJSON(t *testing.T, v interface{}) string {
	t.Helper()
	b, err := json.Marshal(v)
	require.NoError(t, err)
	var parsed interface{}
	require.NoError(t, json.Unmarshal(b, &parsed))
	canonicalized, err := json.Marshal(sortAny(parsed))
	require.NoError(t, err)
	return string(canonicalized)
}

func sortAny(v interface{}) interface{} {
	switch val := v.(type) {
	case []interface{}:
		for i := range val {
			val[i] = sortAny(val[i])
		}
		sort.Slice(val, func(i, j int) bool {
			bi, _ := json.Marshal(val[i])
			bj, _ := json.Marshal(val[j])
			return string(bi) < string(bj)
		})
		return val
	case map[string]interface{}:
		for k := range val {
			val[k] = sortAny(val[k])
		}
		return val
	default:
		return v
	}
}

// changedPeers returns the peer IDs whose serialized map differs between before
// and after.
func changedPeers(before, after map[string]string) []string {
	var changed []string
	for id, b := range before {
		a, ok := after[id]
		if !ok || a != b {
			changed = append(changed, id)
		}
	}
	for id := range after {
		if _, ok := before[id]; !ok {
			changed = append(changed, id)
		}
	}
	return changed
}

// TestAffectedPeers_Property_ResolverSupersetsRealChanges builds a topology,
// applies random changes, and asserts that the resolver's affected set is a
// superset of the peers whose real network map actually changed. If the resolver
// ever misses a dependency, a change will alter a peer's map without that peer
// appearing in the affected set, failing here.
func TestAffectedPeers_Property_ResolverSupersetsRealChanges(t *testing.T) {
	s := setupRouterScenario(t, true)
	ctx := context.Background()

	// A pre-existing peer->resource policy so the resource/router bridge is live.
	_, err := s.manager.SavePolicy(ctx, s.accountID, userID, peerToResourcePolicyByGroup(s.sourceGroupID, s.resourceGroupID), true)
	require.NoError(t, err)

	// Extra peers and groups to give mutations room to move membership around.
	setupKey, err := s.manager.CreateSetupKey(ctx, s.accountID, "prop-key", types.SetupKeyReusable, 0, nil, 999, userID, false, false)
	require.NoError(t, err)
	extraPeers := make([]string, 0, 4)
	for i := 0; i < 4; i++ {
		p := addPeerToAccount(t, s.manager, s.accountID, setupKey.Key)
		extraPeers = append(extraPeers, p.ID)
	}
	extraGroups := []string{"prop-grp-0", "prop-grp-1"}
	for _, g := range extraGroups {
		require.NoError(t, s.manager.CreateGroup(ctx, s.accountID, userID, &types.Group{ID: g, Name: g}))
	}

	rng := rand.New(rand.NewSource(1))
	allGroups := append([]string{s.sourceGroupID, s.resourceGroupID, s.routerPeerGroupID}, extraGroups...)
	allPeers := append([]string{s.sourcePeerID, s.routerPeerID, s.routerGroupPeerID, s.unrelatedPeerID}, extraPeers...)

	for iter := 0; iter < 60; iter++ {
		change, apply := s.randomMutation(t, rng, allGroups, allPeers)
		if apply == nil {
			continue
		}

		before := allPeerMaps(t, s.manager, s.accountID)

		resolvedSet := make(map[string]struct{})
		resolve := func() {
			require.NoError(t, s.manager.Store.ExecuteInTransaction(ctx, func(tx store.Store) error {
				snap, err := affectedpeers.Load(ctx, tx, s.accountID, change)
				if err != nil {
					return err
				}
				for _, id := range snap.Expand(ctx, s.accountID, change) {
					resolvedSet[id] = struct{}{}
				}
				return nil
			}))
		}

		// Resolve on both sides of the mutation and union: removals are visible
		// only pre-apply (the leaving peer is still a member), additions only
		// post-apply (the joining peer is now a member). Production captures both
		// via per-path handling (e.g. UpdateGroup passes peersToRemove); the union
		// models that without coupling the test to each path's ordering.
		resolve()
		changedIDs := change.ChangedPeerIDs
		apply()
		resolve()

		after := allPeerMaps(t, s.manager, s.accountID)

		// The explicitly-changed peer's own map refresh is the caller's
		// responsibility (the resolver returns the peers to propagate to), so it
		// is allowed to be absent from the resolved set.
		changedExplicitly := make(map[string]struct{}, len(changedIDs))
		for _, id := range changedIDs {
			changedExplicitly[id] = struct{}{}
		}

		for _, id := range changedPeers(before, after) {
			if _, stillExists := after[id]; !stillExists {
				continue
			}
			if _, isExplicit := changedExplicitly[id]; isExplicit {
				continue
			}
			_, ok := resolvedSet[id]
			require.Truef(t, ok,
				"iter %d: peer %s network map changed but was not in the resolver's affected set %v (change=%+v)",
				iter, id, maps.Keys(resolvedSet), change)
		}
	}
}

// randomMutation picks a random change, returns the Change to resolve and a
// function that applies the underlying store mutation. apply is nil when the
// drawn mutation is a no-op for the current state.
func (s *routerScenario) randomMutation(t *testing.T, rng *rand.Rand, allGroups, allPeers []string) (affectedpeers.Change, func()) {
	t.Helper()
	ctx := context.Background()

	switch rng.Intn(3) {
	case 0:
		groupID := allGroups[rng.Intn(len(allGroups))]
		peerID := allPeers[rng.Intn(len(allPeers))]
		grp, err := s.manager.Store.GetGroupByID(ctx, store.LockingStrengthNone, s.accountID, groupID)
		require.NoError(t, err)
		if slicesContains(grp.Peers, peerID) {
			return affectedpeers.Change{}, nil
		}
		return affectedpeers.Change{ChangedGroupIDs: []string{groupID}, ChangedPeerIDs: []string{peerID}},
			func() {
				require.NoError(t, s.manager.GroupAddPeer(ctx, s.accountID, groupID, peerID))
			}
	case 1:
		groupID := allGroups[rng.Intn(len(allGroups))]
		grp, err := s.manager.Store.GetGroupByID(ctx, store.LockingStrengthNone, s.accountID, groupID)
		require.NoError(t, err)
		if len(grp.Peers) == 0 {
			return affectedpeers.Change{}, nil
		}
		peerID := grp.Peers[rng.Intn(len(grp.Peers))]
		return affectedpeers.Change{ChangedGroupIDs: []string{groupID}, ChangedPeerIDs: []string{peerID}},
			func() {
				require.NoError(t, s.manager.GroupDeletePeer(ctx, s.accountID, groupID, peerID))
			}
	default:
		src := allGroups[rng.Intn(len(allGroups))]
		dst := allGroups[rng.Intn(len(allGroups))]
		policy := &types.Policy{
			Enabled: true,
			Name:    fmt.Sprintf("prop-policy-%d", rng.Int()),
			Rules: []*types.PolicyRule{{
				Enabled:      true,
				Sources:      []string{src},
				Destinations: []string{dst},
				Action:       types.PolicyTrafficActionAccept,
			}},
		}
		return affectedpeers.Change{Policies: []*types.Policy{policy}},
			func() {
				_, err := s.manager.SavePolicy(ctx, s.accountID, userID, policy, true)
				require.NoError(t, err)
			}
	}
}

func slicesContains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
