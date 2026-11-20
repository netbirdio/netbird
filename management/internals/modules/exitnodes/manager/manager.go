// Package manager implements the exit nodes manager.
//
// Exit nodes are held in memory until their persistence lands: state is lost on restart, nothing
// is distributed to peers, and each account starts with a mock exit node built from its own peers
// so the dashboard has real peer IDs to join against. Peers are only read; deleting an exit node
// deletes the policies that target it through the account manager.
package manager

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/rs/xid"

	"github.com/netbirdio/netbird/management/internals/modules/exitnodes"
	"github.com/netbirdio/netbird/management/server/account"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/permissions"
	"github.com/netbirdio/netbird/management/server/permissions/modules"
	"github.com/netbirdio/netbird/management/server/permissions/operations"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/status"
)

const (
	mockExitNodeName  = "Default Egress"
	mockExitNodePeers = 2
	metricStep        = 100
)

type accountExitNodes map[exitnodes.ID]*exitnodes.ExitNode

type managerImpl struct {
	store              store.Store
	accountManager     account.Manager
	permissionsManager permissions.Manager

	mu       sync.Mutex
	accounts map[string]accountExitNodes
}

// NewManager returns an in-memory exit nodes manager.
func NewManager(store store.Store, accountManager account.Manager, permissionsManager permissions.Manager) exitnodes.Manager {
	return &managerImpl{
		store:              store,
		accountManager:     accountManager,
		permissionsManager: permissionsManager,
		accounts:           make(map[string]accountExitNodes),
	}
}

// GetAllExitNodes returns all exit nodes of the account.
func (m *managerImpl) GetAllExitNodes(ctx context.Context, accountID, userID string) ([]*exitnodes.ExitNode, error) {
	ctx, err := m.validatePermission(ctx, accountID, userID, operations.Read)
	if err != nil {
		return nil, err
	}

	if err := m.ensureSeeded(ctx, accountID); err != nil {
		return nil, err
	}

	m.mu.Lock()
	nodes := make([]*exitnodes.ExitNode, 0, len(m.accounts[accountID]))
	for _, node := range m.accounts[accountID] {
		nodes = append(nodes, node.Copy())
	}
	m.mu.Unlock()

	sort.Slice(nodes, func(i, j int) bool { return nodes[i].Name < nodes[j].Name })
	return nodes, nil
}

// GetExitNode returns one exit node of the account.
func (m *managerImpl) GetExitNode(ctx context.Context, accountID, userID string, exitNodeID exitnodes.ID) (*exitnodes.ExitNode, error) {
	ctx, err := m.validatePermission(ctx, accountID, userID, operations.Read)
	if err != nil {
		return nil, err
	}

	if err := m.ensureSeeded(ctx, accountID); err != nil {
		return nil, err
	}

	return m.getCopy(accountID, exitNodeID)
}

// CreateExitNode validates and stores a new exit node with a generated ID.
func (m *managerImpl) CreateExitNode(ctx context.Context, accountID, userID string, exitNode *exitnodes.ExitNode) (*exitnodes.ExitNode, error) {
	ctx, err := m.validatePermission(ctx, accountID, userID, operations.Create)
	if err != nil {
		return nil, err
	}

	if err := m.ensureSeeded(ctx, accountID); err != nil {
		return nil, err
	}

	node := exitNode.Copy()
	node.ID = exitnodes.ID(xid.New().String())
	node.AccountID = accountID

	if err := m.validate(ctx, accountID, node); err != nil {
		return nil, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	nodes := m.accounts[accountID]
	if err := checkConflicts(nodes, node); err != nil {
		return nil, err
	}
	nodes[node.ID] = node

	return node.Copy(), nil
}

// UpdateExitNode replaces an existing exit node.
func (m *managerImpl) UpdateExitNode(ctx context.Context, accountID, userID string, exitNode *exitnodes.ExitNode) (*exitnodes.ExitNode, error) {
	ctx, err := m.validatePermission(ctx, accountID, userID, operations.Update)
	if err != nil {
		return nil, err
	}

	if err := m.ensureSeeded(ctx, accountID); err != nil {
		return nil, err
	}

	node := exitNode.Copy()
	node.AccountID = accountID

	if err := m.validate(ctx, accountID, node); err != nil {
		return nil, err
	}

	m.mu.Lock()
	nodes := m.accounts[accountID]
	if _, ok := nodes[node.ID]; !ok {
		m.mu.Unlock()
		return nil, newNotFoundError(node.ID)
	}
	if err := checkConflicts(nodes, node); err != nil {
		m.mu.Unlock()
		return nil, err
	}
	nodes[node.ID] = node
	m.mu.Unlock()

	return node.Copy(), nil
}

// DeleteExitNode deletes an exit node and the policies whose destination it is.
func (m *managerImpl) DeleteExitNode(ctx context.Context, accountID, userID string, exitNodeID exitnodes.ID) error {
	ctx, err := m.validatePermission(ctx, accountID, userID, operations.Delete)
	if err != nil {
		return err
	}

	if err := m.ensureSeeded(ctx, accountID); err != nil {
		return err
	}

	if _, err := m.getCopy(accountID, exitNodeID); err != nil {
		return err
	}

	policyIDs, err := m.policiesTargeting(ctx, accountID, exitNodeID)
	if err != nil {
		return err
	}
	// Policies go first so a failure leaves the exit node in place and the delete can be retried.
	for _, policyID := range policyIDs {
		if err := m.accountManager.DeletePolicy(ctx, accountID, policyID, userID); err != nil {
			return fmt.Errorf("delete policy %s of exit node %s: %w", policyID, exitNodeID, err)
		}
	}

	m.mu.Lock()
	delete(m.accounts[accountID], exitNodeID)
	m.mu.Unlock()

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

// validate checks the exit node itself and that all its peers belong to the account.
func (m *managerImpl) validate(ctx context.Context, accountID string, node *exitnodes.ExitNode) error {
	if err := node.Validate(); err != nil {
		return status.Errorf(status.InvalidArgument, "%s", err.Error())
	}

	peers, err := m.store.GetPeersByIDs(ctx, store.LockingStrengthNone, accountID, node.PeerIDs())
	if err != nil {
		return err
	}
	for _, p := range node.Peers {
		if _, ok := peers[p.PeerID]; !ok {
			return status.Errorf(status.InvalidArgument, "peer %s not found", p.PeerID)
		}
	}
	return nil
}

// checkConflicts enforces the account-wide rules: unique names and one exit node per peer.
func checkConflicts(nodes accountExitNodes, node *exitnodes.ExitNode) error {
	peerIDs := make(map[string]struct{}, len(node.Peers))
	for _, p := range node.Peers {
		peerIDs[p.PeerID] = struct{}{}
	}

	for id, other := range nodes {
		if id == node.ID {
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

func (m *managerImpl) getCopy(accountID string, exitNodeID exitnodes.ID) (*exitnodes.ExitNode, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	node, ok := m.accounts[accountID][exitNodeID]
	if !ok {
		return nil, newNotFoundError(exitNodeID)
	}
	return node.Copy(), nil
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

// ensureSeeded gives an account its mock exit node on first use.
func (m *managerImpl) ensureSeeded(ctx context.Context, accountID string) error {
	m.mu.Lock()
	_, seeded := m.accounts[accountID]
	m.mu.Unlock()
	if seeded {
		return nil
	}

	peers, err := m.store.GetAccountPeers(ctx, store.LockingStrengthNone, accountID, "", "", "")
	if err != nil {
		return err
	}
	nodes := mockExitNodes(accountID, peers)

	m.mu.Lock()
	if _, seeded := m.accounts[accountID]; !seeded {
		m.accounts[accountID] = nodes
	}
	m.mu.Unlock()
	return nil
}

func mockExitNodes(accountID string, peers []*nbpeer.Peer) accountExitNodes {
	nodes := make(accountExitNodes)
	if len(peers) == 0 {
		return nodes
	}

	sorted := append([]*nbpeer.Peer(nil), peers...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })
	if len(sorted) > mockExitNodePeers {
		sorted = sorted[:mockExitNodePeers]
	}

	node := &exitnodes.ExitNode{
		ID:          exitnodes.ID(xid.New().String()),
		AccountID:   accountID,
		Name:        mockExitNodeName,
		Description: "Mock exit node, not persisted",
		Enabled:     true,
		AutoApply:   true,
	}
	for i, p := range sorted {
		node.Peers = append(node.Peers, exitnodes.Peer{PeerID: p.ID, Metric: (i + 1) * metricStep, Enabled: true})
	}
	nodes[node.ID] = node
	return nodes
}

func newNotFoundError(exitNodeID exitnodes.ID) error {
	return status.Errorf(status.NotFound, "exit node %s not found", exitNodeID)
}
