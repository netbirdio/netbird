// Package manager implements the exit nodes manager.
package manager

import (
	"context"
	"fmt"
	"strings"

	"github.com/rs/xid"

	"github.com/netbirdio/netbird/management/internals/modules/exitnodes"
	"github.com/netbirdio/netbird/management/internals/shared/db"
	"github.com/netbirdio/netbird/management/server/account"
	"github.com/netbirdio/netbird/management/server/permissions"
	"github.com/netbirdio/netbird/management/server/permissions/modules"
	"github.com/netbirdio/netbird/management/server/permissions/operations"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/status"
)

type managerImpl struct {
	repo               exitnodes.Repository
	conn               *db.Conn
	store              store.Store
	accountManager     account.Manager
	permissionsManager permissions.Manager
}

// NewManager returns the exit nodes manager. Peers and policies are read through the store,
// and policies are deleted through the account manager.
func NewManager(repo exitnodes.Repository, conn *db.Conn, store store.Store, accountManager account.Manager, permissionsManager permissions.Manager) exitnodes.Manager {
	return &managerImpl{
		repo:               repo,
		conn:               conn,
		store:              store,
		accountManager:     accountManager,
		permissionsManager: permissionsManager,
	}
}

// GetAllExitNodes returns all exit nodes of the account.
func (m *managerImpl) GetAllExitNodes(ctx context.Context, accountID, userID string) ([]*exitnodes.ExitNode, error) {
	ctx, err := m.validatePermission(ctx, accountID, userID, operations.Read)
	if err != nil {
		return nil, err
	}

	return m.repo.ListByAccount(ctx, db.LockingStrengthNone, accountID)
}

// GetExitNode returns one exit node of the account.
func (m *managerImpl) GetExitNode(ctx context.Context, accountID, userID string, exitNodeID exitnodes.ID) (*exitnodes.ExitNode, error) {
	ctx, err := m.validatePermission(ctx, accountID, userID, operations.Read)
	if err != nil {
		return nil, err
	}

	return m.repo.Get(ctx, db.LockingStrengthNone, accountID, exitNodeID)
}

// CreateExitNode validates and stores a new exit node with a generated ID.
func (m *managerImpl) CreateExitNode(ctx context.Context, accountID, userID string, exitNode *exitnodes.ExitNode) (*exitnodes.ExitNode, error) {
	ctx, err := m.validatePermission(ctx, accountID, userID, operations.Create)
	if err != nil {
		return nil, err
	}

	node := exitNode.Copy()
	node.ID = exitnodes.ID(xid.New().String())
	node.AccountID = accountID
	node.BindPeers()
	assignPublicIDs(node, nil)

	if err := m.validate(ctx, accountID, node, nil); err != nil {
		return nil, err
	}

	err = m.conn.RunInTx(ctx, func(tx *db.Tx) error {
		repo := m.repo.WithTx(tx)
		if err := repo.LockAccount(ctx, accountID); err != nil {
			return err
		}
		existing, err := repo.ListByAccount(ctx, db.LockingStrengthNone, accountID)
		if err != nil {
			return err
		}
		if err := checkConflicts(existing, node); err != nil {
			return err
		}
		if err := repo.Create(ctx, node); err != nil {
			return err
		}
		return repo.IncrementNetworkSerial(ctx, accountID)
	})
	if err != nil {
		return nil, err
	}

	m.updatePeers(ctx, accountID, types.UpdateOperationCreate)
	return node, nil
}

// UpdateExitNode replaces an existing exit node.
func (m *managerImpl) UpdateExitNode(ctx context.Context, accountID, userID string, exitNode *exitnodes.ExitNode) (*exitnodes.ExitNode, error) {
	ctx, err := m.validatePermission(ctx, accountID, userID, operations.Update)
	if err != nil {
		return nil, err
	}

	node := exitNode.Copy()
	node.AccountID = accountID
	node.BindPeers()

	current, err := m.repo.Get(ctx, db.LockingStrengthNone, accountID, node.ID)
	if err != nil {
		return nil, err
	}
	if err := m.validate(ctx, accountID, node, current); err != nil {
		return nil, err
	}
	assignPublicIDs(node, current)

	err = m.conn.RunInTx(ctx, func(tx *db.Tx) error {
		repo := m.repo.WithTx(tx)
		if err := repo.LockAccount(ctx, accountID); err != nil {
			return err
		}
		if _, err := repo.Get(ctx, db.LockingStrengthNone, accountID, node.ID); err != nil {
			return err
		}
		existing, err := repo.ListByAccount(ctx, db.LockingStrengthNone, accountID)
		if err != nil {
			return err
		}
		if err := checkConflicts(existing, node); err != nil {
			return err
		}
		if err := repo.Update(ctx, node); err != nil {
			return err
		}
		return repo.IncrementNetworkSerial(ctx, accountID)
	})
	if err != nil {
		return nil, err
	}

	m.updatePeers(ctx, accountID, types.UpdateOperationUpdate)
	return node, nil
}

// DeleteExitNode deletes an exit node and the policies whose destination it is.
func (m *managerImpl) DeleteExitNode(ctx context.Context, accountID, userID string, exitNodeID exitnodes.ID) error {
	ctx, err := m.validatePermission(ctx, accountID, userID, operations.Delete)
	if err != nil {
		return err
	}

	if _, err := m.repo.Get(ctx, db.LockingStrengthNone, accountID, exitNodeID); err != nil {
		return err
	}

	policyIDs, err := m.policiesTargeting(ctx, accountID, exitNodeID)
	if err != nil {
		return err
	}
	// Policies go first so a failure leaves the exit node in place and the delete can be retried.
	// They are deleted outside the transaction: the account manager runs its own.
	for _, policyID := range policyIDs {
		if err := m.accountManager.DeletePolicy(ctx, accountID, policyID, userID); err != nil {
			return fmt.Errorf("delete policy %s of exit node %s: %w", policyID, exitNodeID, err)
		}
	}

	err = m.conn.RunInTx(ctx, func(tx *db.Tx) error {
		repo := m.repo.WithTx(tx)
		if err := repo.LockAccount(ctx, accountID); err != nil {
			return err
		}
		if err := repo.Delete(ctx, accountID, exitNodeID); err != nil {
			return err
		}
		return repo.IncrementNetworkSerial(ctx, accountID)
	})
	if err != nil {
		return err
	}

	m.updatePeers(ctx, accountID, types.UpdateOperationDelete)
	return nil
}

// updatePeers sends every peer of the account a new network map. The affected peers
// resolver does not know exit nodes yet, so the update is not narrowed to them.
func (m *managerImpl) updatePeers(ctx context.Context, accountID string, operation types.UpdateOperation) {
	m.accountManager.UpdateAccountPeers(ctx, accountID, types.UpdateReason{Resource: types.UpdateResourceExitNode, Operation: operation})
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

// validate checks the exit node itself and that its new peers belong to the account. Peers
// already on current are not looked up again, so an exit node that still lists a deleted
// peer can be updated until that peer is removed from it.
func (m *managerImpl) validate(ctx context.Context, accountID string, node, current *exitnodes.ExitNode) error {
	if err := node.Validate(); err != nil {
		return status.Errorf(status.InvalidArgument, "%s", err.Error())
	}

	known := make(map[string]struct{})
	if current != nil {
		for _, p := range current.Peers {
			known[p.PeerID] = struct{}{}
		}
	}

	var newPeerIDs []string
	for _, p := range node.Peers {
		if _, ok := known[p.PeerID]; !ok {
			newPeerIDs = append(newPeerIDs, p.PeerID)
		}
	}
	if len(newPeerIDs) == 0 {
		return nil
	}

	peers, err := m.store.GetPeersByIDs(ctx, store.LockingStrengthNone, accountID, newPeerIDs)
	if err != nil {
		return err
	}
	for _, id := range newPeerIDs {
		if _, ok := peers[id]; !ok {
			return status.Errorf(status.InvalidArgument, "peer %s not found", id)
		}
	}
	return nil
}

// assignPublicIDs keeps the public IDs of current, which is nil on create, and generates
// new ones for the exit node and peers that do not have one yet. Public IDs are never
// taken from the request.
func assignPublicIDs(node, current *exitnodes.ExitNode) {
	existing := make(map[string]string)
	node.PublicID = xid.New().String()
	if current != nil {
		node.PublicID = current.PublicID
		for _, p := range current.Peers {
			existing[p.PeerID] = p.PublicID
		}
	}

	for i := range node.Peers {
		publicID := existing[node.Peers[i].PeerID]
		if publicID == "" {
			publicID = xid.New().String()
		}
		node.Peers[i].PublicID = publicID
	}
}

// checkConflicts enforces the account-wide rules: unique names and one exit node per peer.
func checkConflicts(existing []*exitnodes.ExitNode, node *exitnodes.ExitNode) error {
	peerIDs := make(map[string]struct{}, len(node.Peers))
	for _, p := range node.Peers {
		peerIDs[p.PeerID] = struct{}{}
	}

	for _, other := range existing {
		if other.ID == node.ID {
			continue
		}
		if strings.EqualFold(other.Name, node.Name) {
			return status.Errorf(status.AlreadyExists, "exit node with name %s already exists", node.Name)
		}
		for _, p := range other.Peers {
			if _, ok := peerIDs[p.PeerID]; ok {
				return status.Errorf(status.AlreadyExists, "peer %s already belongs to exit node %s", p.PeerID, other.Name)
			}
		}
	}
	return nil
}

// policiesTargeting returns the IDs of the policies whose destination is the exit node.
func (m *managerImpl) policiesTargeting(ctx context.Context, accountID string, exitNodeID exitnodes.ID) ([]string, error) {
	policies, err := m.store.GetAccountPolicies(ctx, store.LockingStrengthNone, accountID)
	if err != nil {
		return nil, err
	}

	var ids []string
	for _, policy := range policies {
		if targetsExitNode(policy, exitNodeID) {
			ids = append(ids, policy.ID)
		}
	}
	return ids, nil
}

func targetsExitNode(policy *types.Policy, exitNodeID exitnodes.ID) bool {
	for _, rule := range policy.Rules {
		dest := rule.DestinationResource
		if dest.Type == exitnodes.PolicyResourceType && exitnodes.ID(dest.ID) == exitNodeID {
			return true
		}
	}
	return false
}
