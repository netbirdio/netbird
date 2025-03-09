package peers

import (
	"context"
	"fmt"

	"github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/permissions"
	"github.com/netbirdio/netbird/management/server/status"
	"github.com/netbirdio/netbird/management/server/store"
)

type Manager interface {
	GetPeer(ctx context.Context, accountID, userID, peerID string) (*peer.Peer, error)
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
	allowed, err := m.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, permissions.Peers, permissions.Read)
	if err != nil {
		return nil, fmt.Errorf("failed to validate user permissions: %w", err)
	}

	if !allowed {
		return nil, status.NewPermissionDeniedError()
	}

	return m.store.GetPeerByID(ctx, store.LockingStrengthShare, accountID, peerID)
}

func (m *managerImpl) GetAllPeers(ctx context.Context, accountID, userID string) ([]*peer.Peer, error) {
	allowed, err := m.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, permissions.Peers, permissions.Read)
	if err != nil {
		return nil, fmt.Errorf("failed to validate user permissions: %w", err)
	}

	if !allowed {
		return nil, status.NewPermissionDeniedError()
	}

	return m.store.GetAccountPeers(ctx, store.LockingStrengthShare, accountID, "", "")
}
