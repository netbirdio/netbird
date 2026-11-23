package manager

import (
	"context"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/netbirdio/netbird/management/internals/modules/exitnodes"
	"github.com/netbirdio/netbird/management/internals/shared/db"
	"github.com/netbirdio/netbird/management/internals/shared/db/dbtest"
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

// newTestStore returns a store holding one account with the test peers.
func newTestStore(t *testing.T) store.Store {
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
			testGroupID: {ID: testGroupID, AccountID: testAccountID, Name: "Users"},
		},
	})
	require.NoError(t, err)
	return testStore
}

func allowAll(t *testing.T) *permissions.MockManager {
	t.Helper()
	perms := permissions.NewMockManager(gomock.NewController(t))
	perms.EXPECT().
		ValidateUserPermissions(gomock.Any(), testAccountID, testUserID, modules.Routes, gomock.Any()).
		DoAndReturn(func(ctx context.Context, _, _ string, _ modules.Module, _ operations.Operation) (bool, context.Context, error) {
			return true, ctx, nil
		}).AnyTimes()
	return perms
}

type managerEnv struct {
	manager *managerImpl
	repo    *exitnodes.MockRepository
	store   store.Store
	// deletedPolicies records the policies the account manager was asked to delete.
	deletedPolicies []string
	deletePolicyErr error
	// peerUpdates records the reasons of the peer updates the manager asked for.
	peerUpdates []types.UpdateReason
}

func setupManager(t *testing.T) *managerEnv {
	t.Helper()

	repo := exitnodes.NewMockRepository(gomock.NewController(t))
	repo.EXPECT().WithTx(gomock.Any()).Return(repo).AnyTimes()
	repo.EXPECT().LockAccount(gomock.Any(), testAccountID).Return(nil).AnyTimes()
	repo.EXPECT().IncrementNetworkSerial(gomock.Any(), testAccountID).Return(nil).AnyTimes()

	env := &managerEnv{repo: repo, store: newTestStore(t)}
	accountManager := &mock_server.MockAccountManager{
		DeletePolicyFunc: func(ctx context.Context, accountID, policyID, userID string) error {
			if env.deletePolicyErr != nil {
				return env.deletePolicyErr
			}
			env.deletedPolicies = append(env.deletedPolicies, policyID)
			return env.store.DeletePolicy(ctx, accountID, policyID)
		},
		UpdateAccountPeersFunc: func(_ context.Context, accountID string, reason types.UpdateReason) {
			if accountID == testAccountID {
				env.peerUpdates = append(env.peerUpdates, reason)
			}
		},
	}

	conn := dbtest.NewConn(t)
	env.manager = NewManager(repo, conn, env.store, accountManager, allowAll(t)).(*managerImpl)
	return env
}

func exitNode(name string, peerIDs ...string) *exitnodes.ExitNode {
	node := &exitnodes.ExitNode{Name: name, Enabled: true, AutoApply: true}
	for i, id := range peerIDs {
		node.Peers = append(node.Peers, exitnodes.Peer{PeerID: id, Metric: (i + 1) * 100, Enabled: true})
	}
	return node
}

func storedExitNode(id exitnodes.ID, name string, peerIDs ...string) *exitnodes.ExitNode {
	node := exitNode(name, peerIDs...)
	node.ID = id
	node.AccountID = testAccountID
	node.BindPeers()
	return node
}

func assertStatus(t *testing.T, err error, want status.Type) {
	t.Helper()
	require.Error(t, err)
	s, ok := status.FromError(err)
	require.True(t, ok, "error should be a status error: %v", err)
	assert.Equal(t, want, s.Type(), "unexpected status type for %v", err)
}

func TestManager_CreateStoresBoundExitNode(t *testing.T) {
	env := setupManager(t)
	ctx := context.Background()

	env.repo.EXPECT().ListByAccount(gomock.Any(), db.LockingStrengthNone, testAccountID).
		Return([]*exitnodes.ExitNode{storedExitNode("other", "EU Egress", "peer-a")}, nil)

	var stored *exitnodes.ExitNode
	env.repo.EXPECT().Create(gomock.Any(), gomock.Any()).
		DoAndReturn(func(_ context.Context, node *exitnodes.ExitNode) error {
			stored = node
			return nil
		})

	created, err := env.manager.CreateExitNode(ctx, testAccountID, testUserID, exitNode("US Egress", "peer-c", "peer-d"))
	require.NoError(t, err)

	require.NotNil(t, stored)
	assert.NotEmpty(t, created.ID, "create should generate an ID")
	assert.Equal(t, created.ID, stored.ID)
	assert.Equal(t, testAccountID, stored.AccountID)
	assert.NotEmpty(t, stored.PublicID, "create should generate a public ID")
	assert.NotEqual(t, string(stored.ID), stored.PublicID, "the public ID should be generated separately")
	require.Len(t, stored.Peers, 2)
	for _, p := range stored.Peers {
		assert.Equal(t, created.ID, p.ExitNodeID, "peers should be bound to the new exit node")
		assert.Equal(t, testAccountID, p.AccountID, "peers should carry the account for the unique index")
		assert.NotEmpty(t, p.PublicID, "every peer should get a public ID")
	}
	assert.NotEqual(t, stored.Peers[0].PublicID, stored.Peers[1].PublicID, "peer public IDs should be unique")
	assert.Equal(t, []types.UpdateReason{{Resource: types.UpdateResourceExitNode, Operation: types.UpdateOperationCreate}},
		env.peerUpdates, "create should update the account peers once")
}

func TestManager_UpdateKeepsPublicIDs(t *testing.T) {
	env := setupManager(t)
	ctx := context.Background()

	current := storedExitNode("en-1", "EU Egress", "peer-a", "peer-b")
	current.PublicID = "node-public"
	current.Peers[0].PublicID = "peer-a-public"
	current.Peers[1].PublicID = "peer-b-public"
	env.repo.EXPECT().Get(gomock.Any(), gomock.Any(), testAccountID, exitnodes.ID("en-1")).Return(current, nil).Times(2)
	env.repo.EXPECT().ListByAccount(gomock.Any(), db.LockingStrengthNone, testAccountID).Return([]*exitnodes.ExitNode{current}, nil)

	var stored *exitnodes.ExitNode
	env.repo.EXPECT().Update(gomock.Any(), gomock.Any()).
		DoAndReturn(func(_ context.Context, node *exitnodes.ExitNode) error {
			stored = node
			return nil
		})

	// The request drops peer-b, keeps peer-a and adds peer-c. Public IDs sent in the
	// request are ignored.
	update := storedExitNode("en-1", "EU Egress", "peer-a", "peer-c")
	update.PublicID = "from-request"
	update.Peers[1].PublicID = "from-request"
	updated, err := env.manager.UpdateExitNode(ctx, testAccountID, testUserID, update)
	require.NoError(t, err)

	require.NotNil(t, stored)
	assert.Equal(t, "node-public", stored.PublicID, "update should keep the exit node's public ID")
	assert.Equal(t, "node-public", updated.PublicID, "the returned exit node should carry the stored public ID")
	require.Len(t, stored.Peers, 2)
	assert.Equal(t, "peer-a-public", stored.Peers[0].PublicID, "a kept peer should keep its public ID")
	assert.NotEmpty(t, stored.Peers[1].PublicID, "a new peer should get a public ID")
	assert.NotEqual(t, "from-request", stored.Peers[1].PublicID, "a public ID from the request should be ignored")
	assert.NotEqual(t, "peer-b-public", stored.Peers[1].PublicID, "a removed peer's public ID should not be reused")
	assert.Equal(t, []types.UpdateReason{{Resource: types.UpdateResourceExitNode, Operation: types.UpdateOperationUpdate}},
		env.peerUpdates, "update should update the account peers once")
}

func TestManager_CreateRejectsInvalidInput(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name string
		node *exitnodes.ExitNode
	}{
		{name: "invalid metric", node: func() *exitnodes.ExitNode {
			n := exitNode("US Egress", "peer-c")
			n.Peers[0].Metric = 0
			return n
		}()},
		{name: "no peers", node: exitNode("US Egress")},
		{name: "unknown peer", node: exitNode("US Egress", "peer-unknown")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// The mock has no ListByAccount or Create expectation: invalid input must not reach the repository.
			env := setupManager(t)
			_, err := env.manager.CreateExitNode(ctx, testAccountID, testUserID, tt.node)
			assertStatus(t, err, status.InvalidArgument)
		})
	}
}

func TestManager_CreateConflicts(t *testing.T) {
	ctx := context.Background()
	existing := []*exitnodes.ExitNode{storedExitNode("en-1", "EU Egress", "peer-a")}

	tests := []struct {
		name string
		node *exitnodes.ExitNode
	}{
		{name: "duplicate name ignoring case", node: exitNode("eu EGRESS", "peer-c")},
		{name: "peer already in another exit node", node: exitNode("US Egress", "peer-a")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// No Create expectation: a conflicting exit node must not be written.
			env := setupManager(t)
			env.repo.EXPECT().ListByAccount(gomock.Any(), db.LockingStrengthNone, testAccountID).Return(existing, nil)

			_, err := env.manager.CreateExitNode(ctx, testAccountID, testUserID, tt.node)
			assertStatus(t, err, status.AlreadyExists)
			assert.Empty(t, env.peerUpdates, "a rejected create should not update peers")
		})
	}
}

func TestManager_UpdateKeepsOwnNameAndPeers(t *testing.T) {
	env := setupManager(t)
	ctx := context.Background()

	current := storedExitNode("en-1", "EU Egress", "peer-a", "peer-b")
	env.repo.EXPECT().Get(gomock.Any(), gomock.Any(), testAccountID, exitnodes.ID("en-1")).Return(current, nil).Times(2)
	env.repo.EXPECT().ListByAccount(gomock.Any(), db.LockingStrengthNone, testAccountID).Return([]*exitnodes.ExitNode{current}, nil)
	env.repo.EXPECT().Update(gomock.Any(), gomock.Any()).Return(nil)

	// Toggling a single flag resends the same name and peers, which must not
	// conflict with the exit node itself.
	update := storedExitNode("en-1", "EU Egress", "peer-a", "peer-b")
	update.Enabled = false
	updated, err := env.manager.UpdateExitNode(ctx, testAccountID, testUserID, update)
	require.NoError(t, err)
	assert.False(t, updated.Enabled)
}

func TestManager_UpdateKeepsDeletedPeer(t *testing.T) {
	env := setupManager(t)
	ctx := context.Background()

	// peer-gone was deleted from the account after it was added to the exit node.
	current := storedExitNode("en-1", "EU Egress", "peer-a", "peer-gone")
	env.repo.EXPECT().Get(gomock.Any(), gomock.Any(), testAccountID, exitnodes.ID("en-1")).Return(current, nil).Times(2)
	env.repo.EXPECT().ListByAccount(gomock.Any(), db.LockingStrengthNone, testAccountID).Return([]*exitnodes.ExitNode{current}, nil)
	env.repo.EXPECT().Update(gomock.Any(), gomock.Any()).Return(nil)

	update := storedExitNode("en-1", "EU Egress", "peer-a", "peer-gone")
	update.AutoApply = false
	_, err := env.manager.UpdateExitNode(ctx, testAccountID, testUserID, update)
	assert.NoError(t, err, "an exit node that lists a deleted peer should stay editable")
}

func TestManager_UpdateRejectsNewUnknownPeer(t *testing.T) {
	env := setupManager(t)

	current := storedExitNode("en-1", "EU Egress", "peer-a")
	env.repo.EXPECT().Get(gomock.Any(), db.LockingStrengthNone, testAccountID, exitnodes.ID("en-1")).Return(current, nil)

	_, err := env.manager.UpdateExitNode(context.Background(), testAccountID, testUserID, storedExitNode("en-1", "EU Egress", "peer-a", "peer-unknown"))
	assertStatus(t, err, status.InvalidArgument)
}

func TestManager_UpdateUnknownExitNode(t *testing.T) {
	env := setupManager(t)

	env.repo.EXPECT().Get(gomock.Any(), db.LockingStrengthNone, testAccountID, exitnodes.ID("missing")).
		Return(nil, exitnodes.NewNotFoundError("missing"))

	_, err := env.manager.UpdateExitNode(context.Background(), testAccountID, testUserID, storedExitNode("missing", "EU Egress", "peer-a"))
	assertStatus(t, err, status.NotFound)
}

func exitNodePolicy(id, exitNodeID string) *types.Policy {
	return &types.Policy{
		ID:        id,
		AccountID: testAccountID,
		Name:      id,
		Enabled:   true,
		Rules: []*types.PolicyRule{{
			ID:                  id,
			PolicyID:            id,
			Enabled:             true,
			Action:              types.PolicyTrafficActionAccept,
			Protocol:            types.PolicyRuleProtocolALL,
			Sources:             []string{testGroupID},
			DestinationResource: types.Resource{ID: exitNodeID, Type: exitnodes.PolicyResourceType},
		}},
	}
}

func TestManager_DeleteRemovesPolicies(t *testing.T) {
	env := setupManager(t)
	ctx := context.Background()

	require.NoError(t, env.store.CreatePolicy(ctx, exitNodePolicy("policy-1", "en-1")))
	require.NoError(t, env.store.CreatePolicy(ctx, exitNodePolicy("policy-2", "en-2")))

	env.repo.EXPECT().Get(gomock.Any(), db.LockingStrengthNone, testAccountID, exitnodes.ID("en-1")).
		Return(storedExitNode("en-1", "EU Egress", "peer-a"), nil).Times(2)

	// A failed policy delete keeps the exit node so the delete can be retried:
	// the mock has no Delete expectation yet.
	env.deletePolicyErr = status.NewPermissionDeniedError()
	err := env.manager.DeleteExitNode(ctx, testAccountID, testUserID, "en-1")
	assertStatus(t, err, status.PermissionDenied)
	assert.Empty(t, env.peerUpdates, "a failed delete should not update peers")

	env.deletePolicyErr = nil
	env.repo.EXPECT().Delete(gomock.Any(), testAccountID, exitnodes.ID("en-1")).Return(nil)
	require.NoError(t, env.manager.DeleteExitNode(ctx, testAccountID, testUserID, "en-1"))
	assert.Equal(t, []types.UpdateReason{{Resource: types.UpdateResourceExitNode, Operation: types.UpdateOperationDelete}},
		env.peerUpdates, "delete should update the account peers once")

	assert.Equal(t, []string{"policy-1"}, env.deletedPolicies, "only the policy targeting the exit node should be deleted")
	_, err = env.store.GetPolicyByID(ctx, store.LockingStrengthNone, testAccountID, "policy-2")
	assert.NoError(t, err, "a policy targeting another exit node must survive")
}

func TestManager_DeleteUnknownExitNode(t *testing.T) {
	env := setupManager(t)

	env.repo.EXPECT().Get(gomock.Any(), db.LockingStrengthNone, testAccountID, exitnodes.ID("missing")).
		Return(nil, exitnodes.NewNotFoundError("missing"))

	err := env.manager.DeleteExitNode(context.Background(), testAccountID, testUserID, "missing")
	assertStatus(t, err, status.NotFound)
	assert.Empty(t, env.deletedPolicies, "no policy should be deleted for an unknown exit node")
}

func TestManager_PermissionDenied(t *testing.T) {
	ctx := context.Background()
	ctrl := gomock.NewController(t)

	perms := permissions.NewMockManager(ctrl)
	perms.EXPECT().
		ValidateUserPermissions(gomock.Any(), testAccountID, testUserID, modules.Routes, operations.Create).
		Return(false, ctx, nil)

	// No repository expectations: a denied request must not touch the database.
	repo := exitnodes.NewMockRepository(ctrl)
	m := NewManager(repo, dbtest.NewConn(t), newTestStore(t), &mock_server.MockAccountManager{}, perms)

	_, err := m.CreateExitNode(ctx, testAccountID, testUserID, exitNode("US Egress", "peer-c"))
	assertStatus(t, err, status.PermissionDenied)
}
