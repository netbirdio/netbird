package manager

import (
	"context"

	"github.com/rs/xid"

	"github.com/netbirdio/netbird/management/internals/modules/exitnodes"
	"github.com/netbirdio/netbird/management/internals/shared/db"
	"github.com/netbirdio/netbird/management/server/account"
	"github.com/netbirdio/netbird/management/server/activity"
	"github.com/netbirdio/netbird/management/server/permissions"
	"github.com/netbirdio/netbird/management/server/permissions/modules"
	"github.com/netbirdio/netbird/management/server/permissions/operations"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/shared/management/status"
)

type txRunner interface {
	RunInTx(ctx context.Context, fn func(tx *db.Tx) error) error
}

type eventStorer interface {
	StoreEvent(ctx context.Context, initiatorID, targetID, accountID string, activityID activity.ActivityDescriber, meta map[string]any)
}

type managerImpl struct {
	repo               exitnodes.Repository
	txRunner           txRunner
	store              store.Store
	permissionsManager permissions.Manager
	events             eventStorer
}

// NewManager returns the exit node manager. Exit node writes run in
// transactions on conn; groups, peers and legacy routes are read from store.
func NewManager(repo exitnodes.Repository, conn *db.Conn, store store.Store, permissionsManager permissions.Manager, accountManager account.Manager) exitnodes.Manager {
	return newManager(repo, conn, store, permissionsManager, accountManager)
}

func newManager(repo exitnodes.Repository, txRunner txRunner, store store.Store, permissionsManager permissions.Manager, events eventStorer) *managerImpl {
	return &managerImpl{
		repo:               repo,
		txRunner:           txRunner,
		store:              store,
		permissionsManager: permissionsManager,
		events:             events,
	}
}

// GetAllExitNodes returns the exit nodes of the account.
func (m *managerImpl) GetAllExitNodes(ctx context.Context, accountID, userID string) ([]*exitnodes.ExitNode, error) {
	ctx, err := m.validatePermission(ctx, accountID, userID, operations.Read)
	if err != nil {
		return nil, err
	}
	return m.repo.ListByAccount(ctx, db.LockingStrengthNone, accountID)
}

// GetExitNode returns one exit node of the account.
func (m *managerImpl) GetExitNode(ctx context.Context, accountID, userID, exitNodeID string) (*exitnodes.ExitNode, error) {
	ctx, err := m.validatePermission(ctx, accountID, userID, operations.Read)
	if err != nil {
		return nil, err
	}
	return m.repo.GetByID(ctx, db.LockingStrengthNone, accountID, exitNodeID)
}

// CreateExitNode validates and stores a new exit node. Identifiers in the
// input are ignored: the exit node and every routing peer get fresh ones.
func (m *managerImpl) CreateExitNode(ctx context.Context, accountID, userID string, input *exitnodes.ExitNode) (*exitnodes.ExitNode, error) {
	ctx, err := m.validatePermission(ctx, accountID, userID, operations.Create)
	if err != nil {
		return nil, err
	}
	if err := input.Validate(); err != nil {
		return nil, err
	}

	node := newExitNode(accountID, input)
	refs, err := m.loadReferences(ctx, accountID, node)
	if err != nil {
		return nil, err
	}

	err = m.txRunner.RunInTx(ctx, func(tx *db.Tx) error {
		repo := m.repo.WithTx(tx)
		nodes, err := lockAndListExitNodes(ctx, repo, accountID)
		if err != nil {
			return err
		}
		if err := refs.checkConflicts(node, nodes); err != nil {
			return err
		}
		return repo.Create(ctx, node)
	})
	if err != nil {
		return nil, err
	}

	m.events.StoreEvent(ctx, userID, node.ID, accountID, activity.ExitNodeCreated, node.EventMeta())
	return node, nil
}

// UpdateExitNode replaces the exit node input.ID. Routing peer entries whose ID
// matches a stored entry keep their identity; entries without an ID are new.
func (m *managerImpl) UpdateExitNode(ctx context.Context, accountID, userID string, input *exitnodes.ExitNode) (*exitnodes.ExitNode, error) {
	ctx, err := m.validatePermission(ctx, accountID, userID, operations.Update)
	if err != nil {
		return nil, err
	}
	if err := input.Validate(); err != nil {
		return nil, err
	}

	refs, err := m.loadReferences(ctx, accountID, input)
	if err != nil {
		return nil, err
	}

	var updated *exitnodes.ExitNode
	err = m.txRunner.RunInTx(ctx, func(tx *db.Tx) error {
		repo := m.repo.WithTx(tx)
		nodes, err := lockAndListExitNodes(ctx, repo, accountID)
		if err != nil {
			return err
		}
		current := findExitNode(nodes, input.ID)
		if current == nil {
			return newNotFoundError(input.ID)
		}
		if updated, err = mergeUpdate(current, input); err != nil {
			return err
		}
		if err := refs.checkConflicts(updated, nodes); err != nil {
			return err
		}
		return repo.Update(ctx, updated)
	})
	if err != nil {
		return nil, err
	}

	m.events.StoreEvent(ctx, userID, updated.ID, accountID, activity.ExitNodeUpdated, updated.EventMeta())
	return updated, nil
}

// DeleteExitNode removes an exit node of the account.
func (m *managerImpl) DeleteExitNode(ctx context.Context, accountID, userID, exitNodeID string) error {
	ctx, err := m.validatePermission(ctx, accountID, userID, operations.Delete)
	if err != nil {
		return err
	}

	var deleted *exitnodes.ExitNode
	err = m.txRunner.RunInTx(ctx, func(tx *db.Tx) error {
		repo := m.repo.WithTx(tx)
		node, err := repo.GetByID(ctx, db.LockingStrengthUpdate, accountID, exitNodeID)
		if err != nil {
			return err
		}
		if err := repo.Delete(ctx, accountID, exitNodeID); err != nil {
			return err
		}
		deleted = node
		return nil
	})
	if err != nil {
		return err
	}

	m.events.StoreEvent(ctx, userID, deleted.ID, accountID, activity.ExitNodeDeleted, deleted.EventMeta())
	return nil
}

func (m *managerImpl) validatePermission(ctx context.Context, accountID, userID string, operation operations.Operation) (context.Context, error) {
	ok, ctx, err := m.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, modules.Routes, operation)
	if err != nil {
		return ctx, status.NewPermissionValidationError(err)
	}
	if !ok {
		return ctx, status.NewPermissionDeniedError()
	}
	return ctx, nil
}

func lockAndListExitNodes(ctx context.Context, repo exitnodes.Repository, accountID string) ([]*exitnodes.ExitNode, error) {
	if err := repo.LockAccount(ctx, accountID); err != nil {
		return nil, err
	}
	return repo.ListByAccount(ctx, db.LockingStrengthUpdate, accountID)
}

func findExitNode(nodes []*exitnodes.ExitNode, exitNodeID string) *exitnodes.ExitNode {
	for _, node := range nodes {
		if node.ID == exitNodeID {
			return node
		}
	}
	return nil
}

func newExitNode(accountID string, input *exitnodes.ExitNode) *exitnodes.ExitNode {
	node := input.Copy()
	node.ID = xid.New().String()
	node.PublicID = xid.New().String()
	node.AccountID = accountID
	for i := range node.RoutingPeers {
		node.RoutingPeers[i].ID = xid.New().String()
		node.RoutingPeers[i].PublicID = xid.New().String()
	}
	return node
}

// mergeUpdate builds the stored form of an update: the identity and creation
// time come from current, everything else from input.
func mergeUpdate(current, input *exitnodes.ExitNode) (*exitnodes.ExitNode, error) {
	stored := make(map[string]exitnodes.RoutingPeer, len(current.RoutingPeers))
	for _, rp := range current.RoutingPeers {
		stored[rp.ID] = rp
	}

	updated := input.Copy()
	updated.ID = current.ID
	updated.AccountID = current.AccountID
	updated.PublicID = current.PublicID
	updated.CreatedAt = current.CreatedAt

	kept := make(map[string]struct{}, len(updated.RoutingPeers))
	for i := range updated.RoutingPeers {
		rp := &updated.RoutingPeers[i]
		if rp.ID == "" {
			rp.ID = xid.New().String()
			rp.PublicID = xid.New().String()
			continue
		}

		existing, ok := stored[rp.ID]
		if !ok {
			return nil, status.Errorf(status.InvalidArgument, "routing peer %s not found in exit node %s", rp.ID, current.ID)
		}
		if _, dup := kept[rp.ID]; dup {
			return nil, status.Errorf(status.InvalidArgument, "routing peer %s is listed more than once", rp.ID)
		}
		kept[rp.ID] = struct{}{}
		rp.PublicID = existing.PublicID
	}

	return updated, nil
}
