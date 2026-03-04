package peers

//go:generate go run github.com/golang/mock/mockgen -package peers -destination=manager_mock.go -source=./manager.go -build_flags=-mod=mod

import (
	"context"
	"fmt"
	"time"

	"github.com/rs/xid"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/management/internals/controllers/network_map"
	"github.com/netbirdio/netbird/management/internals/modules/peers/ephemeral"
	"github.com/netbirdio/netbird/management/server/account"
	"github.com/netbirdio/netbird/management/server/activity"
	"github.com/netbirdio/netbird/management/server/integrations/integrated_validator"
	"github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/permissions"
	"github.com/netbirdio/netbird/management/server/permissions/modules"
	"github.com/netbirdio/netbird/management/server/permissions/operations"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/shared/management/status"
)

type Manager interface {
	GetPeer(ctx context.Context, accountID, userID, peerID string) (*peer.Peer, error)
	GetPeerAccountID(ctx context.Context, peerID string) (string, error)
	GetAllPeers(ctx context.Context, accountID, userID string) ([]*peer.Peer, error)
	GetPeersByGroupIDs(ctx context.Context, accountID string, groupsIDs []string) ([]*peer.Peer, error)
	DeletePeers(ctx context.Context, accountID string, peerIDs []string, userID string, checkConnected bool) error
	SetNetworkMapController(networkMapController network_map.Controller)
	SetIntegratedPeerValidator(integratedPeerValidator integrated_validator.IntegratedValidator)
	SetAccountManager(accountManager account.Manager)
	GetPeerID(ctx context.Context, peerKey string) (string, error)
	CreateProxyPeer(ctx context.Context, accountID string, peerKey string, cluster string) error
}

type managerImpl struct {
	store                   store.Store
	permissionsManager      permissions.Manager
	integratedPeerValidator integrated_validator.IntegratedValidator
	accountManager          account.Manager

	networkMapController network_map.Controller
}

func NewManager(store store.Store, permissionsManager permissions.Manager) Manager {
	return &managerImpl{
		store:              store,
		permissionsManager: permissionsManager,
	}
}

func (m *managerImpl) SetNetworkMapController(networkMapController network_map.Controller) {
	m.networkMapController = networkMapController
}

func (m *managerImpl) SetIntegratedPeerValidator(integratedPeerValidator integrated_validator.IntegratedValidator) {
	m.integratedPeerValidator = integratedPeerValidator
}

func (m *managerImpl) SetAccountManager(accountManager account.Manager) {
	m.accountManager = accountManager
}

func (m *managerImpl) GetPeer(ctx context.Context, accountID, userID, peerID string) (*peer.Peer, error) {
	allowed, err := m.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, modules.Peers, operations.Read)
	if err != nil {
		return nil, fmt.Errorf("failed to validate user permissions: %w", err)
	}

	if !allowed {
		return nil, status.NewPermissionDeniedError()
	}

	return m.store.GetPeerByID(ctx, store.LockingStrengthNone, accountID, peerID)
}

func (m *managerImpl) GetAllPeers(ctx context.Context, accountID, userID string) ([]*peer.Peer, error) {
	allowed, err := m.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, modules.Peers, operations.Read)
	if err != nil {
		return nil, fmt.Errorf("failed to validate user permissions: %w", err)
	}

	if !allowed {
		return m.store.GetUserPeers(ctx, store.LockingStrengthNone, accountID, userID)
	}

	return m.store.GetAccountPeers(ctx, store.LockingStrengthNone, accountID, "", "")
}

func (m *managerImpl) GetPeerAccountID(ctx context.Context, peerID string) (string, error) {
	return m.store.GetAccountIDByPeerID(ctx, store.LockingStrengthNone, peerID)
}

func (m *managerImpl) GetPeersByGroupIDs(ctx context.Context, accountID string, groupsIDs []string) ([]*peer.Peer, error) {
	return m.store.GetPeersByGroupIDs(ctx, accountID, groupsIDs)
}

func (m *managerImpl) DeletePeers(ctx context.Context, accountID string, peerIDs []string, userID string, checkConnected bool) error {
	settings, err := m.store.GetAccountSettings(ctx, store.LockingStrengthNone, accountID)
	if err != nil {
		return err
	}
	dnsDomain := m.networkMapController.GetDNSDomain(settings)

	for _, peerID := range peerIDs {
		var eventsToStore []func()
		err = m.store.ExecuteInTransaction(ctx, func(transaction store.Store) error {
			peer, err := transaction.GetPeerByID(ctx, store.LockingStrengthNone, accountID, peerID)
			if err != nil {
				if e, ok := status.FromError(err); ok && e.Type() == status.NotFound {
					log.WithContext(ctx).Tracef("DeletePeers: peer %s not found, skipping", peerID)
					return nil
				}
				return err
			}

			if checkConnected && (peer.Status.Connected || peer.Status.LastSeen.After(time.Now().Add(-(ephemeral.EphemeralLifeTime - 10*time.Second)))) {
				log.WithContext(ctx).Tracef("DeletePeers: peer %s skipped (connected=%t, lastSeen=%s, threshold=%s, ephemeral=%t)",
					peerID, peer.Status.Connected,
					peer.Status.LastSeen.Format(time.RFC3339),
					time.Now().Add(-(ephemeral.EphemeralLifeTime - 10*time.Second)).Format(time.RFC3339),
					peer.Ephemeral)
				return nil
			}

			if err := transaction.RemovePeerFromAllGroups(ctx, peerID); err != nil {
				return fmt.Errorf("failed to remove peer %s from groups", peerID)
			}

			peerPolicyRules, err := transaction.GetPolicyRulesByResourceID(ctx, store.LockingStrengthNone, accountID, peerID)
			if err != nil {
				return err
			}
			for _, rule := range peerPolicyRules {
				policy, err := transaction.GetPolicyByID(ctx, store.LockingStrengthNone, accountID, rule.PolicyID)
				if err != nil {
					return err
				}

				err = transaction.DeletePolicy(ctx, accountID, rule.PolicyID)
				if err != nil {
					return err
				}

				eventsToStore = append(eventsToStore, func() {
					m.accountManager.StoreEvent(ctx, userID, peer.ID, accountID, activity.PolicyRemoved, policy.EventMeta())
				})
			}

			if err = transaction.DeletePeer(ctx, accountID, peerID); err != nil {
				return err
			}

			eventsToStore = append(eventsToStore, func() {
				m.accountManager.StoreEvent(ctx, userID, peer.ID, accountID, activity.PeerRemovedByUser, peer.EventMeta(dnsDomain))
			})

			return nil
		})
		if err != nil {
			log.WithContext(ctx).Errorf("DeletePeers: failed to delete peer %s: %v", peerID, err)
			continue
		}

		if m.integratedPeerValidator != nil {
			if err = m.integratedPeerValidator.PeerDeleted(ctx, accountID, peerID, settings.Extra); err != nil {
				log.WithContext(ctx).Errorf("failed to delete peer %s from integrated validator: %v", peerID, err)
			}
		}

		for _, event := range eventsToStore {
			event()
		}
	}

	m.accountManager.UpdateAccountPeers(ctx, accountID)

	return nil
}

func (m *managerImpl) GetPeerID(ctx context.Context, peerKey string) (string, error) {
	return m.store.GetPeerIDByKey(ctx, store.LockingStrengthNone, peerKey)
}

func (m *managerImpl) CreateProxyPeer(ctx context.Context, accountID string, peerKey string, cluster string) error {
	existingPeerID, err := m.store.GetPeerIDByKey(ctx, store.LockingStrengthNone, peerKey)
	if err == nil && existingPeerID != "" {
		// Peer already exists
		return nil
	}

	name := fmt.Sprintf("proxy-%s", xid.New().String())
	peer := &peer.Peer{
		Ephemeral: true,
		ProxyMeta: peer.ProxyMeta{
			Cluster:  cluster,
			Embedded: true,
		},
		Name:                        name,
		Key:                         peerKey,
		LoginExpirationEnabled:      false,
		InactivityExpirationEnabled: false,
		Meta: peer.PeerSystemMeta{
			Hostname: name,
			GoOS:     "proxy",
			OS:       "proxy",
		},
	}

	_, _, _, err = m.accountManager.AddPeer(ctx, accountID, "", "", peer, false)
	if err != nil {
		return fmt.Errorf("failed to create proxy peer: %w", err)
	}

	return nil
}
