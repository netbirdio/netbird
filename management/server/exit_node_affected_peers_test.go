package server

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/internals/modules/exitnodes"
	exitnodesmanager "github.com/netbirdio/netbird/management/internals/modules/exitnodes/manager"
	"github.com/netbirdio/netbird/management/internals/shared/db"
	"github.com/netbirdio/netbird/management/server/affectedpeers"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
)

const affectedExitNodeID = "exit-node-1"

// setupExitNodeAffectedPeers adds, on top of setupAffectedPeersTest, an exit node routed
// by peer1 (enabled) and peer2 (disabled), and a policy giving group0 access to it.
func setupExitNodeAffectedPeers(t *testing.T) (*DefaultAccountManager, store.Store, string, []string, []string, *types.Policy) {
	t.Helper()
	manager, s, accountID, peerIDs, groupIDs := setupAffectedPeersTest(t)
	ctx := context.Background()

	cs, ok := s.(interface{ Conn() *db.Conn })
	require.True(t, ok, "the test store must expose its connection")
	node := &exitnodes.ExitNode{
		ID:        affectedExitNodeID,
		AccountID: accountID,
		PublicID:  "exit-node-1-public",
		Name:      "office exit",
		Enabled:   true,
		Peers: []exitnodes.Peer{
			{PeerID: peerIDs[1], PublicID: "exit-peer-1", Metric: 100, Enabled: true},
			{PeerID: peerIDs[2], PublicID: "exit-peer-2", Metric: 200, Enabled: false},
		},
	}
	node.BindPeers()
	repo := exitnodesmanager.NewRepository(cs.Conn())
	require.NoError(t, cs.Conn().RunInTx(ctx, func(tx *db.Tx) error {
		return repo.WithTx(tx).Create(ctx, node)
	}))

	policy := exitNodePolicy(accountID, "policy-exit", groupIDs[0])
	require.NoError(t, s.CreatePolicy(ctx, policy))

	return manager, s, accountID, peerIDs, groupIDs, policy
}

func exitNodePolicy(accountID, id string, sources ...string) *types.Policy {
	return &types.Policy{
		ID:        id,
		AccountID: accountID,
		Name:      id,
		Enabled:   true,
		Rules: []*types.PolicyRule{{
			ID:                  id,
			PolicyID:            id,
			Enabled:             true,
			Action:              types.PolicyTrafficActionAccept,
			Protocol:            types.PolicyRuleProtocolALL,
			Sources:             sources,
			DestinationResource: types.Resource{ID: affectedExitNodeID, Type: exitnodes.PolicyResourceType},
		}},
	}
}

func TestResolveAffectedPeers_RevokeExitNodeAccess_RefreshesExitNodePeers(t *testing.T) {
	_, s, accountID, peerIDs, groupIDs, oldPolicy := setupExitNodeAffectedPeers(t)

	// The policy moves exit node access from group0 to group3: peer0 loses it.
	newPolicy := exitNodePolicy(accountID, oldPolicy.ID, groupIDs[3])
	result := resolveAffected(t, s, accountID, affectedpeers.Change{Policies: []*types.Policy{oldPolicy, newPolicy}})

	assert.ElementsMatch(t, []string{peerIDs[0], peerIDs[3], peerIDs[1]}, result,
		"the old and new sources and the enabled exit node peer should be refreshed, not the disabled exit node peer")
}

func TestResolveAffectedPeers_ExitNodePeersLoadInsideTransaction(t *testing.T) {
	_, s, accountID, peerIDs, _, policy := setupExitNodeAffectedPeers(t)
	ctx := context.Background()
	change := affectedpeers.Change{Policies: []*types.Policy{policy}}

	// Policy writes load the snapshot inside their transaction. The exit nodes must be
	// read through it: on SQLite a second connection would block until it ends.
	var snap *affectedpeers.Snapshot
	require.NoError(t, s.ExecuteInTransaction(ctx, func(tx store.Store) error {
		var err error
		snap, err = affectedpeers.Load(ctx, tx, accountID, change)
		return err
	}))

	assert.Contains(t, snap.Expand(ctx, accountID, change), peerIDs[1],
		"the exit node peer should be found when the snapshot loads inside a transaction")
}

func TestResolveAffectedPeers_DeleteExitNodePolicy_RefreshesExitNodePeers(t *testing.T) {
	_, s, accountID, peerIDs, _, policy := setupExitNodeAffectedPeers(t)

	result := resolveAffected(t, s, accountID, affectedpeers.Change{Policies: []*types.Policy{policy}})

	assert.ElementsMatch(t, []string{peerIDs[0], peerIDs[1]}, result,
		"deleting the policy should refresh its source and the enabled exit node peer")
}

func TestResolveAffectedPeers_SourcePeerLeavesExitNodePolicy_RefreshesExitNodePeers(t *testing.T) {
	manager, s, accountID, peerIDs, groupIDs, _ := setupExitNodeAffectedPeers(t)

	require.NoError(t, manager.GroupDeletePeer(context.Background(), accountID, groupIDs[0], peerIDs[0]))
	result := resolveAffected(t, s, accountID, affectedpeers.Change{OutputPeerIDs: []string{peerIDs[0]}, LinkGroups: []string{groupIDs[0]}})

	assert.Contains(t, result, peerIDs[1], "the exit node peer should stop forwarding for the peer that left the source group")
	assert.NotContains(t, result, peerIDs[2], "a disabled exit node peer routes nothing and needs no update")
}
