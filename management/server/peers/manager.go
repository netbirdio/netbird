package peers

//go:generate go run github.com/golang/mock/mockgen -package peers -destination=manager_mock.go -source=./manager.go -build_flags=-mod=mod

import (
	"context"
	"fmt"

	"github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/permissions"
	"github.com/netbirdio/netbird/management/server/permissions/modules"
	"github.com/netbirdio/netbird/management/server/permissions/operations"
	"github.com/netbirdio/netbird/management/server/status"
	"github.com/netbirdio/netbird/management/server/store"
)

type Manager interface {
	GetPeer(ctx context.Context, accountID, userID, peerID string) (*peer.Peer, error)
	GetPeerAccountID(ctx context.Context, peerID string) (string, error)
	GetAllPeers(ctx context.Context, accountID, userID string) ([]*peer.Peer, error)
}

type managerImpl struct {
	store              store.Store
	permissionsManager permissions.Manager
}

func NewManager(store store.Store, permissionsManager permissions.Manager) Manager {
	return &managerImpl{
		store:              store,
		permissionsManager: permissionsManager,
	}
}

func (m *managerImpl) GetPeer(ctx context.Context, accountID, userID, peerID string) (*peer.Peer, error) {
	allowed, err := m.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, modules.Peers, operations.Read)
	if err != nil {
		return nil, fmt.Errorf("failed to validate user permissions: %w", err)
	}

	if !allowed {
		return nil, status.NewPermissionDeniedError()
	}

	return m.store.GetPeerByID(ctx, store.LockingStrengthShare, accountID, peerID)
}

func (m *managerImpl) GetAllPeers(ctx context.Context, accountID, userID string) ([]*peer.Peer, error) {
	allowed, err := m.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, modules.Peers, operations.Read)
	if err != nil {
		return nil, fmt.Errorf("failed to validate user permissions: %w", err)
	}

	if !allowed {
		return m.store.GetUserPeers(ctx, store.LockingStrengthShare, accountID, userID)
	}

	return m.store.GetAccountPeers(ctx, store.LockingStrengthShare, accountID, "", "")
}

func (m *managerImpl) GetPeerAccountID(ctx context.Context, peerID string) (string, error) {
	return m.store.GetAccountIDByPeerID(ctx, store.LockingStrengthShare, peerID)
}
