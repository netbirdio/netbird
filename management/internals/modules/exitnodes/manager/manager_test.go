package manager

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/netbirdio/netbird/management/internals/modules/exitnodes"
	"github.com/netbirdio/netbird/management/internals/shared/db"
	"github.com/netbirdio/netbird/management/server/activity"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/permissions"
	"github.com/netbirdio/netbird/management/server/permissions/modules"
	"github.com/netbirdio/netbird/management/server/permissions/operations"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/route"
	"github.com/netbirdio/netbird/shared/management/domain"
	"github.com/netbirdio/netbird/shared/management/status"
)

const (
	testAccountID = "account"
	testUserID    = "user"
)

// fakeTxRunner runs the function in place; the mocked repository ignores the transaction.
type fakeTxRunner struct {
	calls int
}

func (f *fakeTxRunner) RunInTx(_ context.Context, fn func(tx *db.Tx) error) error {
	f.calls++
	return fn(&db.Tx{})
}

type storedEvent struct {
	initiatorID string
	targetID    string
	accountID   string
	activity    activity.ActivityDescriber
	meta        map[string]any
}

type fakeEvents struct {
	events []storedEvent
}

func (f *fakeEvents) StoreEvent(_ context.Context, initiatorID, targetID, accountID string, activityID activity.ActivityDescriber, meta map[string]any) {
	f.events = append(f.events, storedEvent{initiatorID: initiatorID, targetID: targetID, accountID: accountID, activity: activityID, meta: meta})
}

// fixture is the account state the mocked store and repository serve.
type fixture struct {
	groups map[string]*types.Group
	peers  map[string]*nbpeer.Peer
	routes []*route.Route
	nodes  []*exitnodes.ExitNode
}

func newFixture() *fixture {
	f := &fixture{
		groups: map[string]*types.Group{},
		peers:  map[string]*nbpeer.Peer{},
	}
	f.addGroup("dist", "u1")
	f.addGroup("acl")
	f.addGroup("pgA", "p1", "p2")
	f.addGroup("pgB", "p3")
	f.addGroup("pgC", "p4", "p5")
	for _, id := range []string{"p1", "p2", "p3", "p4", "p5", "p6", "p7"} {
		f.peers[id] = &nbpeer.Peer{ID: id, AccountID: testAccountID, Name: "name-" + id}
	}
	return f
}

func (f *fixture) addGroup(id string, peers ...string) {
	f.groups[id] = &types.Group{ID: id, AccountID: testAccountID, Name: "group-" + id, Peers: peers}
}

type testEnv struct {
	repo    *exitnodes.MockRepository
	store   *store.MockStore
	perms   *permissions.MockManager
	tx      *fakeTxRunner
	events  *fakeEvents
	manager *managerImpl
	fixture *fixture
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	ctrl := gomock.NewController(t)
	env := &testEnv{
		repo:    exitnodes.NewMockRepository(ctrl),
		store:   store.NewMockStore(ctrl),
		perms:   permissions.NewMockManager(ctrl),
		tx:      &fakeTxRunner{},
		events:  &fakeEvents{},
		fixture: newFixture(),
	}
	env.manager = newManager(env.repo, env.tx, env.store, env.perms, env.events)
	return env
}

func (e *testEnv) allow(operation operations.Operation) {
	e.perms.EXPECT().
		ValidateUserPermissions(gomock.Any(), testAccountID, testUserID, modules.Routes, operation).
		DoAndReturn(func(ctx context.Context, _, _ string, _ modules.Module, _ operations.Operation) (bool, context.Context, error) {
			return true, ctx, nil
		})
}

// serveFixture makes the mocked store and repository answer from the fixture.
func (e *testEnv) serveFixture() {
	e.serveStore()
	e.serveRepo()
}

// serveStore answers store reads from the fixture. Groups and peers are
// returned only when asked for, so a lookup the manager forgets to make shows
// up as a missing reference.
func (e *testEnv) serveStore() {
	f := e.fixture
	e.store.EXPECT().GetAccountRoutes(gomock.Any(), store.LockingStrengthNone, testAccountID).
		Return(f.routes, nil).AnyTimes()
	e.store.EXPECT().GetGroupsByIDs(gomock.Any(), store.LockingStrengthNone, testAccountID, gomock.Any()).
		DoAndReturn(func(_ context.Context, _ store.LockingStrength, _ string, ids []string) (map[string]*types.Group, error) {
			out := map[string]*types.Group{}
			for _, id := range ids {
				if g, ok := f.groups[id]; ok {
					out[id] = g
				}
			}
			return out, nil
		}).AnyTimes()
	e.store.EXPECT().GetPeersByIDs(gomock.Any(), store.LockingStrengthNone, testAccountID, gomock.Any()).
		DoAndReturn(func(_ context.Context, _ store.LockingStrength, _ string, ids []string) (map[string]*nbpeer.Peer, error) {
			out := map[string]*nbpeer.Peer{}
			for _, id := range ids {
				if p, ok := f.peers[id]; ok {
					out[id] = p
				}
			}
			return out, nil
		}).AnyTimes()
}

// serveRepo answers exit node reads from the fixture and accepts the lock.
func (e *testEnv) serveRepo() {
	f := e.fixture
	e.repo.EXPECT().WithTx(gomock.Any()).Return(e.repo).AnyTimes()
	e.repo.EXPECT().LockAccount(gomock.Any(), testAccountID).Return(nil).AnyTimes()
	e.repo.EXPECT().ListByAccount(gomock.Any(), gomock.Any(), testAccountID).
		DoAndReturn(func(context.Context, db.LockingStrength, string) ([]*exitnodes.ExitNode, error) {
			out := make([]*exitnodes.ExitNode, 0, len(f.nodes))
			for _, n := range f.nodes {
				out = append(out, n.Copy())
			}
			return out, nil
		}).AnyTimes()
}

func validInput() *exitnodes.ExitNode {
	return &exitnodes.ExitNode{
		Name:        "office",
		Description: "office uplink",
		Enabled:     true,
		RoutingPeers: []exitnodes.RoutingPeer{
			{Peer: "p6", Metric: 10, Enabled: true},
			{PeerGroups: []string{"pgA"}, Metric: 20, Enabled: true},
		},
		Masquerade:          true,
		Groups:              []string{"dist"},
		AccessControlGroups: []string{"acl"},
		AutoApply:           true,
	}
}

func legacyRoute(netID, network, peer string, peerGroups ...string) *route.Route {
	return &route.Route{
		ID:          route.ID("route-" + netID),
		AccountID:   testAccountID,
		NetID:       route.NetID(netID),
		Network:     netip.MustParsePrefix(network),
		NetworkType: route.IPv4Network,
		Peer:        peer,
		PeerGroups:  peerGroups,
		Metric:      9999,
		Enabled:     true,
		Groups:      []string{"dist"},
	}
}

func storedNode(id, name string, routingPeers ...exitnodes.RoutingPeer) *exitnodes.ExitNode {
	return &exitnodes.ExitNode{
		ID:           id,
		AccountID:    testAccountID,
		PublicID:     "pub-" + id,
		Name:         name,
		Enabled:      true,
		RoutingPeers: routingPeers,
		Groups:       []string{"dist"},
		CreatedAt:    time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	}
}

func assertStatus(t *testing.T, err error, wantType status.Type, wantMessage string) {
	t.Helper()
	require.Error(t, err)
	sErr, ok := status.FromError(err)
	require.True(t, ok, "error should be a status error: %v", err)
	assert.Equal(t, wantType, sErr.Type(), "error type of %q", sErr.Message)
	assert.Contains(t, sErr.Message, wantMessage, "error message")
}

func TestManager_PermissionDenied(t *testing.T) {
	calls := map[operations.Operation]func(m *managerImpl) error{
		operations.Read: func(m *managerImpl) error {
			_, err := m.GetAllExitNodes(context.Background(), testAccountID, testUserID)
			return err
		},
		operations.Create: func(m *managerImpl) error {
			_, err := m.CreateExitNode(context.Background(), testAccountID, testUserID, validInput())
			return err
		},
		operations.Update: func(m *managerImpl) error {
			input := validInput()
			input.ID = "en1"
			_, err := m.UpdateExitNode(context.Background(), testAccountID, testUserID, input)
			return err
		},
		operations.Delete: func(m *managerImpl) error {
			return m.DeleteExitNode(context.Background(), testAccountID, testUserID, "en1")
		},
	}

	for operation, call := range calls {
		t.Run(string(operation)+" denied", func(t *testing.T) {
			env := newTestEnv(t)
			env.perms.EXPECT().
				ValidateUserPermissions(gomock.Any(), testAccountID, testUserID, modules.Routes, operation).
				Return(false, context.Background(), nil)

			// No repository or store expectation: denied requests must not touch either.
			assertStatus(t, call(env.manager), status.PermissionDenied, "permission denied")
			assert.Empty(t, env.events.events, "no event should be stored")
		})

		t.Run(string(operation)+" validation error", func(t *testing.T) {
			env := newTestEnv(t)
			env.perms.EXPECT().
				ValidateUserPermissions(gomock.Any(), testAccountID, testUserID, modules.Routes, operation).
				Return(false, context.Background(), errors.New("user lookup failed"))

			assertStatus(t, call(env.manager), status.PermissionDenied, "user lookup failed")
		})
	}

	t.Run("get one denied", func(t *testing.T) {
		env := newTestEnv(t)
		env.perms.EXPECT().
			ValidateUserPermissions(gomock.Any(), testAccountID, testUserID, modules.Routes, operations.Read).
			Return(false, context.Background(), nil)

		_, err := env.manager.GetExitNode(context.Background(), testAccountID, testUserID, "en1")
		assertStatus(t, err, status.PermissionDenied, "permission denied")
	})
}

func TestManager_GetExitNodes(t *testing.T) {
	env := newTestEnv(t)
	stored := storedNode("en1", "office", exitnodes.RoutingPeer{ID: "rp1", Peer: "p1", Metric: 1})

	env.allow(operations.Read)
	env.repo.EXPECT().ListByAccount(gomock.Any(), db.LockingStrengthNone, testAccountID).Return([]*exitnodes.ExitNode{stored}, nil)
	nodes, err := env.manager.GetAllExitNodes(context.Background(), testAccountID, testUserID)
	require.NoError(t, err)
	assert.Equal(t, []*exitnodes.ExitNode{stored}, nodes, "listed exit nodes")

	env.allow(operations.Read)
	env.repo.EXPECT().GetByID(gomock.Any(), db.LockingStrengthNone, testAccountID, "en1").Return(stored, nil)
	node, err := env.manager.GetExitNode(context.Background(), testAccountID, testUserID, "en1")
	require.NoError(t, err)
	assert.Equal(t, stored, node, "fetched exit node")
}

func TestManager_CreateExitNode(t *testing.T) {
	env := newTestEnv(t)
	env.allow(operations.Create)
	env.serveFixture()

	var created *exitnodes.ExitNode
	env.repo.EXPECT().Create(gomock.Any(), gomock.Any()).
		DoAndReturn(func(_ context.Context, node *exitnodes.ExitNode) error {
			created = node.Copy()
			return nil
		})

	input := validInput()
	input.ID = "client-chosen"
	input.PublicID = "client-chosen-public"
	input.RoutingPeers[0].ID = "client-chosen-rp"
	input.RoutingPeers[0].PublicID = "client-chosen-rp-public"

	node, err := env.manager.CreateExitNode(context.Background(), testAccountID, testUserID, input)
	require.NoError(t, err)
	require.NotNil(t, created, "the exit node should be written")
	assert.Equal(t, created, node, "the returned exit node should be the stored one")
	assert.Equal(t, 1, env.tx.calls, "the write should run in one transaction")

	assert.Equal(t, testAccountID, node.AccountID, "account id")
	assert.NotEmpty(t, node.ID, "id")
	assert.NotEmpty(t, node.PublicID, "public id")
	assert.NotEqual(t, "client-chosen", node.ID, "the input id must be ignored on create")
	assert.NotEqual(t, "client-chosen-public", node.PublicID, "the input public id must be ignored on create")
	assert.NotEqual(t, node.ID, node.PublicID, "id and public id should be distinct")
	assert.Equal(t, "office", node.Name)
	assert.Equal(t, "office uplink", node.Description)
	assert.True(t, node.Enabled, "enabled")
	assert.True(t, node.Masquerade, "masquerade")
	assert.True(t, node.AutoApply, "auto apply")
	assert.Equal(t, []string{"dist"}, node.Groups, "groups")
	assert.Equal(t, []string{"acl"}, node.AccessControlGroups, "access control groups")

	require.Len(t, node.RoutingPeers, 2, "routing peers")
	ids := map[string]struct{}{node.ID: {}, node.PublicID: {}}
	for _, rp := range node.RoutingPeers {
		assert.NotEmpty(t, rp.ID, "routing peer id")
		assert.NotEmpty(t, rp.PublicID, "routing peer public id")
		ids[rp.ID] = struct{}{}
		ids[rp.PublicID] = struct{}{}
	}
	assert.Len(t, ids, 6, "every generated identifier should be unique")
	assert.NotEqual(t, "client-chosen-rp", node.RoutingPeers[0].ID, "the input routing peer id must be ignored on create")
	assert.Equal(t, "p6", node.RoutingPeers[0].Peer)
	assert.Equal(t, 10, node.RoutingPeers[0].Metric)
	assert.Equal(t, []string{"pgA"}, node.RoutingPeers[1].PeerGroups)
	assert.Equal(t, 20, node.RoutingPeers[1].Metric)

	assert.Equal(t, "client-chosen", input.ID, "the caller's input must not be modified")

	require.Len(t, env.events.events, 1, "one event should be stored")
	assert.Equal(t, storedEvent{
		initiatorID: testUserID,
		targetID:    node.ID,
		accountID:   testAccountID,
		activity:    activity.ExitNodeCreated,
		meta:        map[string]any{"name": "office"},
	}, env.events.events[0], "stored event")
}

func TestManager_CreateExitNode_Validation(t *testing.T) {
	tests := []struct {
		name        string
		mutate      func(n *exitnodes.ExitNode)
		setup       func(f *fixture)
		wantType    status.Type
		wantMessage string
	}{
		{
			name:        "empty name",
			mutate:      func(n *exitnodes.ExitNode) { n.Name = "" },
			wantType:    status.InvalidArgument,
			wantMessage: "name should be between 1 and 40",
		},
		{
			name:        "name longer than 40 characters",
			mutate:      func(n *exitnodes.ExitNode) { n.Name = strings.Repeat("a", 41) },
			wantType:    status.InvalidArgument,
			wantMessage: "name should be between 1 and 40",
		},
		{
			name:        "name with the v6 suffix",
			mutate:      func(n *exitnodes.ExitNode) { n.Name = "office-v6" },
			wantType:    status.InvalidArgument,
			wantMessage: `should not end with "-v6"`,
		},
		{
			name:        "no routing peers",
			mutate:      func(n *exitnodes.ExitNode) { n.RoutingPeers = nil },
			wantType:    status.InvalidArgument,
			wantMessage: "at least one routing peer",
		},
		{
			name: "routing peer with both peer and peer groups",
			mutate: func(n *exitnodes.ExitNode) {
				n.RoutingPeers[0].PeerGroups = []string{"pgB"}
			},
			wantType:    status.InvalidArgument,
			wantMessage: "can not set both peer and peer_groups",
		},
		{
			name:        "routing peer with neither peer nor peer groups",
			mutate:      func(n *exitnodes.ExitNode) { n.RoutingPeers[0].Peer = "" },
			wantType:    status.InvalidArgument,
			wantMessage: "requires either peer or peer_groups",
		},
		{
			name:        "metric below the minimum",
			mutate:      func(n *exitnodes.ExitNode) { n.RoutingPeers[1].Metric = 0 },
			wantType:    status.InvalidArgument,
			wantMessage: "metric should be between 1 and 9999",
		},
		{
			name:        "metric above the maximum",
			mutate:      func(n *exitnodes.ExitNode) { n.RoutingPeers[0].Metric = 10000 },
			wantType:    status.InvalidArgument,
			wantMessage: "metric should be between 1 and 9999",
		},
		{
			name:        "no distribution groups",
			mutate:      func(n *exitnodes.ExitNode) { n.Groups = nil },
			wantType:    status.InvalidArgument,
			wantMessage: "at least one distribution group",
		},
		{
			name:        "unknown distribution group",
			mutate:      func(n *exitnodes.ExitNode) { n.Groups = []string{"dist", "missing"} },
			wantType:    status.InvalidArgument,
			wantMessage: "group missing not found",
		},
		{
			name:        "unknown access control group",
			mutate:      func(n *exitnodes.ExitNode) { n.AccessControlGroups = []string{"missing"} },
			wantType:    status.InvalidArgument,
			wantMessage: "group missing not found",
		},
		{
			name:        "unknown peer",
			mutate:      func(n *exitnodes.ExitNode) { n.RoutingPeers[0].Peer = "ghost" },
			wantType:    status.InvalidArgument,
			wantMessage: "peer ghost not found",
		},
		{
			name:        "unknown peer group",
			mutate:      func(n *exitnodes.ExitNode) { n.RoutingPeers[1].PeerGroups = []string{"pgA", "missing"} },
			wantType:    status.InvalidArgument,
			wantMessage: "peer group missing not found",
		},
		{
			name: "name used by a legacy exit route",
			setup: func(f *fixture) {
				f.routes = append(f.routes, legacyRoute("office", "0.0.0.0/0", "p7"))
			},
			wantType:    status.AlreadyExists,
			wantMessage: `name "office" is already used by a 0.0.0.0/0 route`,
		},
		{
			name: "name used by another exit node",
			setup: func(f *fixture) {
				f.nodes = append(f.nodes, storedNode("en1", "office", exitnodes.RoutingPeer{ID: "rp", Peer: "p7", Metric: 1}))
			},
			wantType:    status.AlreadyExists,
			wantMessage: `exit node with name "office" already exists`,
		},
		{
			name: "peer already routes a legacy exit route",
			setup: func(f *fixture) {
				f.routes = append(f.routes, legacyRoute("legacy", "0.0.0.0/0", "p6"))
			},
			wantType:    status.AlreadyExists,
			wantMessage: `peer p6 already serves 0.0.0.0/0 through route "legacy"`,
		},
		{
			name: "peer is a member of a legacy exit route's peer group",
			setup: func(f *fixture) {
				f.addGroup("pgLegacy", "p6")
				f.routes = append(f.routes, legacyRoute("legacy", "0.0.0.0/0", "", "pgLegacy"))
			},
			wantType:    status.AlreadyExists,
			wantMessage: `peer p6 already serves 0.0.0.0/0 through route "legacy"`,
		},
		{
			name: "peer group already routes a legacy exit route",
			setup: func(f *fixture) {
				f.routes = append(f.routes, legacyRoute("legacy", "0.0.0.0/0", "", "pgA"))
			},
			wantType:    status.AlreadyExists,
			wantMessage: `peer group group-pgA already serves 0.0.0.0/0 through route "legacy"`,
		},
		{
			name: "peer group member is a legacy exit route's peer",
			setup: func(f *fixture) {
				f.routes = append(f.routes, legacyRoute("legacy", "0.0.0.0/0", "p2"))
			},
			wantType:    status.AlreadyExists,
			wantMessage: `peer p2 from group group-pgA already serves 0.0.0.0/0 through route "legacy"`,
		},
		{
			name: "peer already routes another exit node",
			setup: func(f *fixture) {
				f.nodes = append(f.nodes, storedNode("en1", "lab", exitnodes.RoutingPeer{ID: "rp", Peer: "p6", Metric: 1}))
			},
			wantType:    status.AlreadyExists,
			wantMessage: `peer p6 already serves 0.0.0.0/0 through exit node "lab"`,
		},
		{
			name: "peer group member routes another exit node through its group",
			setup: func(f *fixture) {
				f.addGroup("pgOther", "p1")
				f.nodes = append(f.nodes, storedNode("en1", "lab", exitnodes.RoutingPeer{ID: "rp", PeerGroups: []string{"pgOther"}, Metric: 1}))
			},
			wantType:    status.AlreadyExists,
			wantMessage: `peer p1 from group group-pgA already serves 0.0.0.0/0 through exit node "lab"`,
		},
		{
			name: "same peer twice within the exit node",
			mutate: func(n *exitnodes.ExitNode) {
				n.RoutingPeers = append(n.RoutingPeers, exitnodes.RoutingPeer{Peer: "p6", Metric: 30})
			},
			wantType:    status.AlreadyExists,
			wantMessage: "peer p6 already serves 0.0.0.0/0 through another routing peer entry of this exit node",
		},
		{
			name: "peer and a group containing it within the exit node",
			mutate: func(n *exitnodes.ExitNode) {
				n.RoutingPeers = append(n.RoutingPeers, exitnodes.RoutingPeer{Peer: "p1", Metric: 30})
			},
			wantType:    status.AlreadyExists,
			wantMessage: "peer p1 already serves 0.0.0.0/0 through another routing peer entry of this exit node",
		},
		{
			name: "same peer group twice within the exit node",
			mutate: func(n *exitnodes.ExitNode) {
				n.RoutingPeers = append(n.RoutingPeers, exitnodes.RoutingPeer{PeerGroups: []string{"pgA"}, Metric: 30})
			},
			wantType:    status.AlreadyExists,
			wantMessage: "peer group group-pgA already serves 0.0.0.0/0 through another routing peer entry of this exit node",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := newTestEnv(t)
			env.allow(operations.Create)
			if tt.setup != nil {
				tt.setup(env.fixture)
			}
			env.serveFixture()
			input := validInput()
			if tt.mutate != nil {
				tt.mutate(input)
			}

			// No Create expectation: a rejected exit node must not be written.
			_, err := env.manager.CreateExitNode(context.Background(), testAccountID, testUserID, input)
			assertStatus(t, err, tt.wantType, tt.wantMessage)
			assert.Empty(t, env.events.events, "no event should be stored for a rejected exit node")
		})
	}
}

func TestManager_CreateExitNode_AllowedOverlaps(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(n *exitnodes.ExitNode)
		setup  func(f *fixture)
	}{
		{
			name:   "name of 40 characters",
			mutate: func(n *exitnodes.ExitNode) { n.Name = strings.Repeat("a", 40) },
		},
		{
			name: "name used by a route that is not 0.0.0.0/0",
			setup: func(f *fixture) {
				f.routes = append(f.routes, legacyRoute("office", "10.0.0.0/8", "p7"))
			},
		},
		{
			name: "peers routing a prefix that is not 0.0.0.0/0",
			setup: func(f *fixture) {
				f.routes = append(f.routes,
					legacyRoute("lan", "10.0.0.0/8", "p6"),
					legacyRoute("v6-default", "::/0", "", "pgA"),
				)
			},
		},
		{
			name: "domain route stored with a 0.0.0.0/0 network",
			setup: func(f *fixture) {
				r := legacyRoute("office", "0.0.0.0/0", "p6")
				r.NetworkType = route.DomainNetwork
				r.Domains = domain.List{"example.com"}
				f.routes = append(f.routes, r)
			},
		},
		{
			name: "other exit nodes on other peers",
			setup: func(f *fixture) {
				f.nodes = append(f.nodes, storedNode("en1", "lab",
					exitnodes.RoutingPeer{ID: "rp1", Peer: "p7", Metric: 1},
					exitnodes.RoutingPeer{ID: "rp2", PeerGroups: []string{"pgB"}, Metric: 1},
				))
			},
		},
		{
			name: "legacy exit route referencing a deleted group",
			setup: func(f *fixture) {
				f.routes = append(f.routes, legacyRoute("legacy", "0.0.0.0/0", "", "deleted-group"))
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := newTestEnv(t)
			env.allow(operations.Create)
			if tt.setup != nil {
				tt.setup(env.fixture)
			}
			env.serveFixture()
			env.repo.EXPECT().Create(gomock.Any(), gomock.Any()).Return(nil)
			input := validInput()
			if tt.mutate != nil {
				tt.mutate(input)
			}

			_, err := env.manager.CreateExitNode(context.Background(), testAccountID, testUserID, input)
			require.NoError(t, err)
			assert.Len(t, env.events.events, 1, "the created event should be stored")
		})
	}
}

// A concurrent writer can add a conflicting exit node after the references are
// read. The manager must catch it on the list it reads under the account lock.
func TestManager_CreateExitNode_RechecksUnderLock(t *testing.T) {
	env := newTestEnv(t)
	env.allow(operations.Create)
	f := env.fixture
	env.store.EXPECT().GetAccountRoutes(gomock.Any(), store.LockingStrengthNone, testAccountID).Return(nil, nil)
	env.store.EXPECT().GetGroupsByIDs(gomock.Any(), store.LockingStrengthNone, testAccountID, gomock.Any()).
		Return(map[string]*types.Group{"dist": f.groups["dist"], "acl": f.groups["acl"], "pgA": f.groups["pgA"]}, nil)
	env.store.EXPECT().GetPeersByIDs(gomock.Any(), store.LockingStrengthNone, testAccountID, []string{"p6"}).
		Return(map[string]*nbpeer.Peer{"p6": f.peers["p6"]}, nil)

	concurrent := storedNode("en1", "lab", exitnodes.RoutingPeer{ID: "rp", Peer: "p6", Metric: 1})
	gomock.InOrder(
		env.repo.EXPECT().ListByAccount(gomock.Any(), db.LockingStrengthNone, testAccountID).Return(nil, nil),
		env.repo.EXPECT().WithTx(gomock.Any()).Return(env.repo),
		env.repo.EXPECT().LockAccount(gomock.Any(), testAccountID).Return(nil),
		env.repo.EXPECT().ListByAccount(gomock.Any(), db.LockingStrengthUpdate, testAccountID).
			Return([]*exitnodes.ExitNode{concurrent}, nil),
	)

	_, err := env.manager.CreateExitNode(context.Background(), testAccountID, testUserID, validInput())
	assertStatus(t, err, status.AlreadyExists, `peer p6 already serves 0.0.0.0/0 through exit node "lab"`)
	assert.Empty(t, env.events.events, "no event should be stored")
}

// A concurrent writer can reference a group the manager did not read. Its
// members are unknown, so the request fails instead of skipping the check.
func TestManager_CreateExitNode_ConcurrentGroupReference(t *testing.T) {
	env := newTestEnv(t)
	env.allow(operations.Create)
	env.serveStore()
	env.repo.EXPECT().WithTx(gomock.Any()).Return(env.repo)
	env.repo.EXPECT().LockAccount(gomock.Any(), testAccountID).Return(nil)
	env.repo.EXPECT().ListByAccount(gomock.Any(), db.LockingStrengthNone, testAccountID).Return(nil, nil)
	env.repo.EXPECT().ListByAccount(gomock.Any(), db.LockingStrengthUpdate, testAccountID).
		Return([]*exitnodes.ExitNode{storedNode("en1", "lab", exitnodes.RoutingPeer{ID: "rp", PeerGroups: []string{"pgB"}, Metric: 1})}, nil)

	_, err := env.manager.CreateExitNode(context.Background(), testAccountID, testUserID, validInput())
	assertStatus(t, err, status.PreconditionFailed, "retry")
}

func TestManager_UpdateExitNode_PreservesIdentity(t *testing.T) {
	env := newTestEnv(t)
	env.allow(operations.Update)
	current := storedNode("en1", "office",
		exitnodes.RoutingPeer{ID: "rp-keep", PublicID: "rp-keep-pub", Peer: "p6", Metric: 10, Enabled: true},
		exitnodes.RoutingPeer{ID: "rp-drop", PublicID: "rp-drop-pub", PeerGroups: []string{"pgA"}, Metric: 20},
	)
	env.fixture.nodes = []*exitnodes.ExitNode{current}
	env.serveFixture()

	var written *exitnodes.ExitNode
	env.repo.EXPECT().Update(gomock.Any(), gomock.Any()).
		DoAndReturn(func(_ context.Context, node *exitnodes.ExitNode) error {
			written = node.Copy()
			return nil
		})

	input := &exitnodes.ExitNode{
		ID:        "en1",
		PublicID:  "client-chosen-public",
		AccountID: "other-account",
		CreatedAt: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC),
		Name:      "office-renamed",
		Enabled:   false,
		RoutingPeers: []exitnodes.RoutingPeer{
			{ID: "rp-keep", PublicID: "client-chosen-rp-public", Peer: "p7", Metric: 5},
			{PeerGroups: []string{"pgB"}, Metric: 30, Enabled: true},
		},
		Groups: []string{"dist"},
	}

	node, err := env.manager.UpdateExitNode(context.Background(), testAccountID, testUserID, input)
	require.NoError(t, err)
	require.NotNil(t, written, "the exit node should be written")
	assert.Equal(t, written, node, "the returned exit node should be the stored one")

	assert.Equal(t, "en1", node.ID, "id must not change")
	assert.Equal(t, "pub-en1", node.PublicID, "public id must not change")
	assert.Equal(t, testAccountID, node.AccountID, "account id must not change")
	assert.Equal(t, current.CreatedAt, node.CreatedAt, "created at must not change")
	assert.Equal(t, "office-renamed", node.Name)
	assert.False(t, node.Enabled, "enabled")
	assert.Empty(t, node.Description, "description")

	require.Len(t, node.RoutingPeers, 2, "the dropped entry should be gone and the new one added")
	kept := node.RoutingPeers[0]
	assert.Equal(t, exitnodes.RoutingPeer{ID: "rp-keep", PublicID: "rp-keep-pub", Peer: "p7", Metric: 5}, kept,
		"a matched entry keeps its identity and takes the new fields")
	added := node.RoutingPeers[1]
	assert.NotEmpty(t, added.ID, "a new entry gets an id")
	assert.NotEmpty(t, added.PublicID, "a new entry gets a public id")
	assert.NotContains(t, []string{"rp-keep", "rp-drop"}, added.ID, "a new entry must not reuse an old id")
	assert.NotContains(t, []string{"rp-keep-pub", "rp-drop-pub"}, added.PublicID, "a new entry must not reuse an old public id")
	assert.Equal(t, []string{"pgB"}, added.PeerGroups)

	require.Len(t, env.events.events, 1, "one event should be stored")
	assert.Equal(t, storedEvent{
		initiatorID: testUserID,
		targetID:    "en1",
		accountID:   testAccountID,
		activity:    activity.ExitNodeUpdated,
		meta:        map[string]any{"name": "office-renamed"},
	}, env.events.events[0], "stored event")
}

// The exit node being updated must not conflict with its own stored name and peers.
func TestManager_UpdateExitNode_NoConflictWithItself(t *testing.T) {
	env := newTestEnv(t)
	env.allow(operations.Update)
	env.fixture.nodes = []*exitnodes.ExitNode{storedNode("en1", "office",
		exitnodes.RoutingPeer{ID: "rp1", PublicID: "rp1-pub", Peer: "p6", Metric: 10},
		exitnodes.RoutingPeer{ID: "rp2", PublicID: "rp2-pub", PeerGroups: []string{"pgA"}, Metric: 20},
	)}
	env.serveFixture()
	env.repo.EXPECT().Update(gomock.Any(), gomock.Any()).Return(nil)

	input := validInput()
	input.ID = "en1"
	input.RoutingPeers[0].ID = "rp1"
	input.RoutingPeers[1].ID = "rp2"

	_, err := env.manager.UpdateExitNode(context.Background(), testAccountID, testUserID, input)
	require.NoError(t, err)
}

func TestManager_UpdateExitNode_Rejected(t *testing.T) {
	tests := []struct {
		name        string
		mutate      func(n *exitnodes.ExitNode)
		wantType    status.Type
		wantMessage string
	}{
		{
			name:        "unknown exit node",
			mutate:      func(n *exitnodes.ExitNode) { n.ID = "missing" },
			wantType:    status.NotFound,
			wantMessage: "exit node missing not found",
		},
		{
			name:        "unknown routing peer id",
			mutate:      func(n *exitnodes.ExitNode) { n.RoutingPeers[0].ID = "rp-other" },
			wantType:    status.InvalidArgument,
			wantMessage: "routing peer rp-other not found in exit node en1",
		},
		{
			name: "routing peer id listed twice",
			mutate: func(n *exitnodes.ExitNode) {
				n.RoutingPeers[0].ID = "rp1"
				n.RoutingPeers[1].ID = "rp1"
			},
			wantType:    status.InvalidArgument,
			wantMessage: "routing peer rp1 is listed more than once",
		},
		{
			name:        "name taken by another exit node",
			mutate:      func(n *exitnodes.ExitNode) { n.Name = "lab" },
			wantType:    status.AlreadyExists,
			wantMessage: `exit node with name "lab" already exists`,
		},
		{
			name:        "invalid input",
			mutate:      func(n *exitnodes.ExitNode) { n.Name = "office-v6" },
			wantType:    status.InvalidArgument,
			wantMessage: "-v6",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := newTestEnv(t)
			env.allow(operations.Update)
			env.fixture.nodes = []*exitnodes.ExitNode{
				storedNode("en1", "office", exitnodes.RoutingPeer{ID: "rp1", PublicID: "rp1-pub", Peer: "p6", Metric: 10}),
				storedNode("en2", "lab", exitnodes.RoutingPeer{ID: "rp9", PublicID: "rp9-pub", Peer: "p7", Metric: 10}),
			}
			env.serveFixture()
			input := validInput()
			input.ID = "en1"
			tt.mutate(input)

			// No Update expectation: a rejected update must not be written.
			_, err := env.manager.UpdateExitNode(context.Background(), testAccountID, testUserID, input)
			assertStatus(t, err, tt.wantType, tt.wantMessage)
			assert.Empty(t, env.events.events, "no event should be stored")
		})
	}
}

func TestManager_DeleteExitNode(t *testing.T) {
	env := newTestEnv(t)
	env.allow(operations.Delete)
	stored := storedNode("en1", "office", exitnodes.RoutingPeer{ID: "rp1", Peer: "p6", Metric: 10})
	env.repo.EXPECT().WithTx(gomock.Any()).Return(env.repo)
	gomock.InOrder(
		env.repo.EXPECT().GetByID(gomock.Any(), db.LockingStrengthUpdate, testAccountID, "en1").Return(stored, nil),
		env.repo.EXPECT().Delete(gomock.Any(), testAccountID, "en1").Return(nil),
	)

	require.NoError(t, env.manager.DeleteExitNode(context.Background(), testAccountID, testUserID, "en1"))
	assert.Equal(t, 1, env.tx.calls, "the delete should run in one transaction")
	require.Len(t, env.events.events, 1, "one event should be stored")
	assert.Equal(t, storedEvent{
		initiatorID: testUserID,
		targetID:    "en1",
		accountID:   testAccountID,
		activity:    activity.ExitNodeDeleted,
		meta:        map[string]any{"name": "office"},
	}, env.events.events[0], "stored event")
}

func TestManager_DeleteExitNode_NotFound(t *testing.T) {
	env := newTestEnv(t)
	env.allow(operations.Delete)
	env.repo.EXPECT().WithTx(gomock.Any()).Return(env.repo)
	env.repo.EXPECT().GetByID(gomock.Any(), db.LockingStrengthUpdate, testAccountID, "missing").Return(nil, newNotFoundError("missing"))

	err := env.manager.DeleteExitNode(context.Background(), testAccountID, testUserID, "missing")
	assertStatus(t, err, status.NotFound, "exit node missing not found")
	assert.Empty(t, env.events.events, "no event should be stored")
}
