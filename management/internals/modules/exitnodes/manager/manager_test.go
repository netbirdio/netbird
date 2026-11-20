package manager

import (
	"context"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/netbirdio/netbird/management/internals/modules/exitnodes"
	"github.com/netbirdio/netbird/management/server/mock_server"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/permissions"
	"github.com/netbirdio/netbird/management/server/permissions/modules"
	"github.com/netbirdio/netbird/management/server/permissions/operations"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/status"
)

const (
	testAccountID = "test-account-id"
	testUserID    = "test-user-id"
	testGroupID   = "test-group-id"
)

var testPeerIDs = []string{"peer-a", "peer-b", "peer-c", "peer-d"}

type testEnv struct {
	manager         *managerImpl
	store           store.Store
	perms           *permissions.MockManager
	deletedPolicies []string
	deletePolicyErr error
}

func setupTest(t *testing.T) *testEnv {
	t.Helper()

	ctx := context.Background()
	testStore, cleanup, err := store.NewTestStoreFromSQL(ctx, "", t.TempDir())
	require.NoError(t, err)
	t.Cleanup(cleanup)

	peers := make(map[string]*nbpeer.Peer, len(testPeerIDs))
	for i, id := range testPeerIDs {
		peers[id] = &nbpeer.Peer{
			ID:        id,
			AccountID: testAccountID,
			Key:       "key-" + id,
			Name:      id,
			DNSLabel:  id,
			IP:        netip.AddrFrom4([4]byte{100, 64, 0, byte(i + 1)}),
			Status:    &nbpeer.PeerStatus{},
		}
	}

	err = testStore.SaveAccount(ctx, &types.Account{
		Id:    testAccountID,
		Peers: peers,
		Groups: map[string]*types.Group{
			testGroupID: {ID: testGroupID, AccountID: testAccountID, Name: "Exit peers", Peers: []string{"peer-c", "peer-d"}},
		},
	})
	require.NoError(t, err)

	ctrl := gomock.NewController(t)
	perms := permissions.NewMockManager(ctrl)
	perms.EXPECT().
		ValidateUserPermissions(gomock.Any(), testAccountID, testUserID, modules.Routes, gomock.Any()).
		DoAndReturn(func(ctx context.Context, _, _ string, _ modules.Module, _ operations.Operation) (bool, context.Context, error) {
			return true, ctx, nil
		}).AnyTimes()

	env := &testEnv{store: testStore, perms: perms}
	accountManager := &mock_server.MockAccountManager{
		DeletePolicyFunc: func(ctx context.Context, accountID, policyID, userID string) error {
			if env.deletePolicyErr != nil {
				return env.deletePolicyErr
			}
			env.deletedPolicies = append(env.deletedPolicies, policyID)
			return testStore.DeletePolicy(ctx, accountID, policyID)
		},
	}
	env.manager = NewManager(testStore, accountManager, perms).(*managerImpl)
	return env
}

func exitNode(name string, peerIDs ...string) *exitnodes.ExitNode {
	node := &exitnodes.ExitNode{Name: name, Enabled: true, AutoApply: true}
	for i, id := range peerIDs {
		node.Peers = append(node.Peers, exitnodes.Peer{PeerID: id, Metric: (i + 1) * 100, Enabled: true})
	}
	return node
}

func assertStatus(t *testing.T, err error, want status.Type) {
	t.Helper()
	require.Error(t, err)
	s, ok := status.FromError(err)
	require.True(t, ok, "error should be a status error: %v", err)
	assert.Equal(t, want, s.Type(), "unexpected status type for %v", err)
}

func TestManager_SeedsMockExitNodeFromAccountPeers(t *testing.T) {
	env := setupTest(t)

	nodes, err := env.manager.GetAllExitNodes(context.Background(), testAccountID, testUserID)
	require.NoError(t, err)
	require.Len(t, nodes, 1, "account should start with one mock exit node")

	node := nodes[0]
	assert.Equal(t, mockExitNodeName, node.Name)
	assert.Equal(t, []exitnodes.Peer{
		{PeerID: "peer-a", Metric: 100, Enabled: true},
		{PeerID: "peer-b", Metric: 200, Enabled: true},
	}, node.Peers, "mock should use the first two account peers by name")
}

func TestManager_CreateGetUpdateDelete(t *testing.T) {
	env := setupTest(t)
	ctx := context.Background()

	created, err := env.manager.CreateExitNode(ctx, testAccountID, testUserID, exitNode("US Egress", "peer-c"))
	require.NoError(t, err)
	require.NotEmpty(t, created.ID, "create should generate an ID")
	assert.Equal(t, "US Egress", created.Name)

	got, err := env.manager.GetExitNode(ctx, testAccountID, testUserID, created.ID)
	require.NoError(t, err)
	assert.Equal(t, created.Peers, got.Peers)

	update := exitNode("US Egress HA", "peer-c", "peer-d")
	update.ID = created.ID
	update.AutoApply = false
	updated, err := env.manager.UpdateExitNode(ctx, testAccountID, testUserID, update)
	require.NoError(t, err)
	assert.Equal(t, "US Egress HA", updated.Name)
	assert.False(t, updated.AutoApply, "update should be a full replace")
	assert.Len(t, updated.Peers, 2)

	require.NoError(t, env.manager.DeleteExitNode(ctx, testAccountID, testUserID, created.ID))
	_, err = env.manager.GetExitNode(ctx, testAccountID, testUserID, created.ID)
	assertStatus(t, err, status.NotFound)
}

func TestManager_ReturnedExitNodeIsACopy(t *testing.T) {
	env := setupTest(t)
	ctx := context.Background()

	created, err := env.manager.CreateExitNode(ctx, testAccountID, testUserID, exitNode("US Egress", "peer-c"))
	require.NoError(t, err)
	created.Peers[0].Metric = 9999

	got, err := env.manager.GetExitNode(ctx, testAccountID, testUserID, created.ID)
	require.NoError(t, err)
	assert.Equal(t, 100, got.Peers[0].Metric, "mutating a returned exit node must not change the stored one")
}

func TestManager_ValidationAndConflicts(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name string
		node *exitnodes.ExitNode
		want status.Type
	}{
		{name: "invalid metric", node: func() *exitnodes.ExitNode {
			n := exitNode("US Egress", "peer-c")
			n.Peers[0].Metric = 0
			return n
		}(), want: status.InvalidArgument},
		{name: "no peers", node: exitNode("US Egress"), want: status.InvalidArgument},
		{name: "unknown peer", node: exitNode("US Egress", "peer-unknown"), want: status.InvalidArgument},
		{name: "duplicate name ignoring case", node: exitNode("default EGRESS", "peer-c"), want: status.AlreadyExists},
		{name: "peer already in another exit node", node: exitNode("US Egress", "peer-a"), want: status.AlreadyExists},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := setupTest(t)
			_, err := env.manager.CreateExitNode(ctx, testAccountID, testUserID, tt.node)
			assertStatus(t, err, tt.want)

			nodes, err := env.manager.GetAllExitNodes(ctx, testAccountID, testUserID)
			require.NoError(t, err)
			assert.Len(t, nodes, 1, "a rejected create must not add an exit node")
		})
	}
}

func TestManager_UpdateKeepsOwnNameAndPeers(t *testing.T) {
	env := setupTest(t)
	ctx := context.Background()

	nodes, err := env.manager.GetAllExitNodes(ctx, testAccountID, testUserID)
	require.NoError(t, err)
	seeded := nodes[0]

	// Toggling a single flag resends the same name and peers, which must not
	// conflict with the exit node itself.
	seeded.Enabled = false
	updated, err := env.manager.UpdateExitNode(ctx, testAccountID, testUserID, seeded)
	require.NoError(t, err)
	assert.False(t, updated.Enabled)

	missing := exitNode("Other", "peer-c")
	missing.ID = "does-not-exist"
	_, err = env.manager.UpdateExitNode(ctx, testAccountID, testUserID, missing)
	assertStatus(t, err, status.NotFound)
}

func TestManager_DeleteRemovesPolicies(t *testing.T) {
	env := setupTest(t)
	ctx := context.Background()

	created, err := env.manager.CreateExitNode(ctx, testAccountID, testUserID, exitNode("US Egress", "peer-c"))
	require.NoError(t, err)

	policy := &types.Policy{
		ID:        "policy-1",
		AccountID: testAccountID,
		Name:      "US Egress Access",
		Enabled:   true,
		Rules: []*types.PolicyRule{{
			ID:                  "policy-1",
			PolicyID:            "policy-1",
			Enabled:             true,
			Action:              types.PolicyTrafficActionAccept,
			Protocol:            types.PolicyRuleProtocolALL,
			Sources:             []string{testGroupID},
			DestinationResource: types.Resource{ID: string(created.ID), Type: exitnodes.PolicyResourceType},
		}},
	}
	require.NoError(t, env.store.SavePolicy(ctx, policy))

	// A failed policy delete keeps the exit node so the delete can be retried.
	env.deletePolicyErr = status.NewPermissionDeniedError()
	err = env.manager.DeleteExitNode(ctx, testAccountID, testUserID, created.ID)
	assertStatus(t, err, status.PermissionDenied)
	_, err = env.manager.GetExitNode(ctx, testAccountID, testUserID, created.ID)
	require.NoError(t, err, "a failed delete must keep the exit node")

	env.deletePolicyErr = nil
	require.NoError(t, env.manager.DeleteExitNode(ctx, testAccountID, testUserID, created.ID))
	assert.Equal(t, []string{"policy-1"}, env.deletedPolicies, "delete should remove the policies targeting the exit node")

	_, err = env.store.GetPolicyByID(ctx, store.LockingStrengthNone, testAccountID, "policy-1")
	assertStatus(t, err, status.NotFound)
	_, err = env.manager.GetExitNode(ctx, testAccountID, testUserID, created.ID)
	assertStatus(t, err, status.NotFound)
}

func TestManager_PermissionDenied(t *testing.T) {
	ctx := context.Background()
	testStore, cleanup, err := store.NewTestStoreFromSQL(ctx, "", t.TempDir())
	require.NoError(t, err)
	t.Cleanup(cleanup)

	ctrl := gomock.NewController(t)
	perms := permissions.NewMockManager(ctrl)
	perms.EXPECT().
		ValidateUserPermissions(gomock.Any(), testAccountID, testUserID, modules.Routes, operations.Create).
		Return(false, ctx, nil)

	m := NewManager(testStore, &mock_server.MockAccountManager{}, perms)
	_, err = m.CreateExitNode(ctx, testAccountID, testUserID, exitNode("US Egress", "peer-c"))
	assertStatus(t, err, status.PermissionDenied)
}
