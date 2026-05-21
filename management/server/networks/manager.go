package networks

import (
	"context"
	"fmt"

	"github.com/rs/xid"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/management/server/account"
	"github.com/netbirdio/netbird/management/server/activity"
	"github.com/netbirdio/netbird/management/server/networks/resources"
	"github.com/netbirdio/netbird/management/server/networks/routers"
	"github.com/netbirdio/netbird/management/server/networks/types"
	"github.com/netbirdio/netbird/management/server/permissions"
	"github.com/netbirdio/netbird/management/server/permissions/modules"
	"github.com/netbirdio/netbird/management/server/permissions/operations"
	"github.com/netbirdio/netbird/management/server/store"
	nbTypes "github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/status"
)

type Manager interface {
	GetAllNetworks(ctx context.Context, accountID, userID string) ([]*types.Network, error)
	CreateNetwork(ctx context.Context, userID string, network *types.Network) (*types.Network, error)
	GetNetwork(ctx context.Context, accountID, userID, networkID string) (*types.Network, error)
	UpdateNetwork(ctx context.Context, userID string, network *types.Network) (*types.Network, error)
	DeleteNetwork(ctx context.Context, accountID, userID, networkID string) error
}

type managerImpl struct {
	store              store.Store
	accountManager     account.Manager
	permissionsManager permissions.Manager
	resourcesManager   resources.Manager
	routersManager     routers.Manager
}

type mockManager struct {
}

func NewManager(store store.Store, permissionsManager permissions.Manager, resourceManager resources.Manager, routersManager routers.Manager, accountManager account.Manager) Manager {
	return &managerImpl{
		store:              store,
		permissionsManager: permissionsManager,
		resourcesManager:   resourceManager,
		routersManager:     routersManager,
		accountManager:     accountManager,
	}
}

func (m *managerImpl) GetAllNetworks(ctx context.Context, accountID, userID string) ([]*types.Network, error) {
	ok, err := m.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, modules.Networks, operations.Read)
	if err != nil {
		return nil, status.NewPermissionValidationError(err)
	}
	if !ok {
		return nil, status.NewPermissionDeniedError()
	}

	return m.store.GetAccountNetworks(ctx, store.LockingStrengthNone, accountID)
}

func (m *managerImpl) CreateNetwork(ctx context.Context, userID string, network *types.Network) (*types.Network, error) {
	ok, err := m.permissionsManager.ValidateUserPermissions(ctx, network.AccountID, userID, modules.Networks, operations.Create)
	if err != nil {
		return nil, status.NewPermissionValidationError(err)
	}
	if !ok {
		return nil, status.NewPermissionDeniedError()
	}

	network.ID = xid.New().String()

	err = m.store.ExecuteInTransaction(ctx, func(transaction store.Store) error {
		seq, err := transaction.AllocateAccountSeqID(ctx, network.AccountID, nbTypes.AccountSeqEntityNetwork)
		if err != nil {
			return fmt.Errorf("failed to allocate network seq id: %w", err)
		}
		network.AccountSeqID = seq

		if err := transaction.SaveNetwork(ctx, network); err != nil {
			return fmt.Errorf("failed to save network: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	m.accountManager.StoreEvent(ctx, userID, network.ID, network.AccountID, activity.NetworkCreated, network.EventMeta())

	return network, nil
}

func (m *managerImpl) GetNetwork(ctx context.Context, accountID, userID, networkID string) (*types.Network, error) {
	ok, err := m.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, modules.Networks, operations.Read)
	if err != nil {
		return nil, status.NewPermissionValidationError(err)
	}
	if !ok {
		return nil, status.NewPermissionDeniedError()
	}

	return m.store.GetNetworkByID(ctx, store.LockingStrengthNone, accountID, networkID)
}

func (m *managerImpl) UpdateNetwork(ctx context.Context, userID string, network *types.Network) (*types.Network, error) {
	ok, err := m.permissionsManager.ValidateUserPermissions(ctx, network.AccountID, userID, modules.Networks, operations.Update)
	if err != nil {
		return nil, status.NewPermissionValidationError(err)
	}
	if !ok {
		return nil, status.NewPermissionDeniedError()
	}

	err = m.store.ExecuteInTransaction(ctx, func(transaction store.Store) error {
		existing, err := transaction.GetNetworkByID(ctx, store.LockingStrengthUpdate, network.AccountID, network.ID)
		if err != nil {
			return fmt.Errorf("failed to get network: %w", err)
		}
		network.AccountSeqID = existing.AccountSeqID

		if err := transaction.SaveNetwork(ctx, network); err != nil {
			return fmt.Errorf("failed to save network: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	m.accountManager.StoreEvent(ctx, userID, network.ID, network.AccountID, activity.NetworkUpdated, network.EventMeta())

	return network, nil
}

// networkAffectedPeersData holds data loaded inside the transaction for affected peer resolution.
type networkAffectedPeersData struct {
	resourceGroupIDs []string
	routerPeerGroups []string
	directPeerIDs    []string
	policies         []*nbTypes.Policy
}

func (m *managerImpl) DeleteNetwork(ctx context.Context, accountID, userID, networkID string) error {
	ok, err := m.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, modules.Networks, operations.Delete)
	if err != nil {
		return status.NewPermissionValidationError(err)
	}
	if !ok {
		return status.NewPermissionDeniedError()
	}

	network, err := m.store.GetNetworkByID(ctx, store.LockingStrengthUpdate, accountID, networkID)
	if err != nil {
		return fmt.Errorf("failed to get network: %w", err)
	}

	var eventsToStore []func()
	var affectedData *networkAffectedPeersData
	err = m.store.ExecuteInTransaction(ctx, func(transaction store.Store) error {
		resources, err := transaction.GetNetworkResourcesByNetID(ctx, store.LockingStrengthUpdate, accountID, networkID)
		if err != nil {
			return fmt.Errorf("failed to get resources in network: %w", err)
		}

		var resourceGroupIDs []string
		for _, resource := range resources {
			groups, err := transaction.GetResourceGroups(ctx, store.LockingStrengthNone, accountID, resource.ID)
			if err == nil {
				for _, g := range groups {
					resourceGroupIDs = append(resourceGroupIDs, g.ID)
				}
			}

			event, err := m.resourcesManager.DeleteResourceInTransaction(ctx, transaction, accountID, userID, networkID, resource.ID)
			if err != nil {
				return fmt.Errorf("failed to delete resource: %w", err)
			}
			eventsToStore = append(eventsToStore, event...)
		}

		netRouters, err := transaction.GetNetworkRoutersByNetID(ctx, store.LockingStrengthUpdate, accountID, networkID)
		if err != nil {
			return fmt.Errorf("failed to get routers in network: %w", err)
		}

		var routerPeerGroups []string
		var directPeerIDs []string
		for _, router := range netRouters {
			routerPeerGroups = append(routerPeerGroups, router.PeerGroups...)
			if router.Peer != "" {
				directPeerIDs = append(directPeerIDs, router.Peer)
			}

			event, err := m.routersManager.DeleteRouterInTransaction(ctx, transaction, accountID, userID, networkID, router.ID)
			if err != nil {
				return fmt.Errorf("failed to delete router: %w", err)
			}
			eventsToStore = append(eventsToStore, event)
		}

		// load policies before deleting so group memberships are still present
		var policies []*nbTypes.Policy
		if len(resourceGroupIDs) > 0 {
			policies, err = transaction.GetAccountPolicies(ctx, store.LockingStrengthNone, accountID)
			if err != nil {
				log.WithContext(ctx).Errorf("failed to get policies for affected peers: %v", err)
			}
		}

		if len(resourceGroupIDs) > 0 || len(routerPeerGroups) > 0 || len(directPeerIDs) > 0 {
			affectedData = &networkAffectedPeersData{
				resourceGroupIDs: resourceGroupIDs,
				routerPeerGroups: routerPeerGroups,
				directPeerIDs:    directPeerIDs,
				policies:         policies,
			}
		}

		err = transaction.DeleteNetwork(ctx, accountID, networkID)
		if err != nil {
			return fmt.Errorf("failed to delete network: %w", err)
		}

		eventsToStore = append(eventsToStore, func() {
			m.accountManager.StoreEvent(ctx, userID, networkID, accountID, activity.NetworkDeleted, network.EventMeta())
		})

		err = transaction.IncrementNetworkSerial(ctx, accountID)
		if err != nil {
			return fmt.Errorf("failed to increment network serial: %w", err)
		}

		return nil
	})
	if err != nil {
		return fmt.Errorf("failed to delete network: %w", err)
	}

	for _, event := range eventsToStore {
		event()
	}

	if affectedData != nil {
		affectedPeerIDs := resolveNetworkAffectedPeers(ctx, m.store, accountID, affectedData)
		if len(affectedPeerIDs) > 0 {
			log.WithContext(ctx).Debugf("DeleteNetwork %s: updating %d affected peers: %v", networkID, len(affectedPeerIDs), affectedPeerIDs)
			go m.accountManager.UpdateAffectedPeers(ctx, accountID, affectedPeerIDs)
		} else {
			log.WithContext(ctx).Tracef("DeleteNetwork %s: no affected peers", networkID)
		}
	}

	return nil
}

// resolveNetworkAffectedPeers computes affected peer IDs from preloaded data outside the transaction.
func resolveNetworkAffectedPeers(ctx context.Context, s store.Store, accountID string, data *networkAffectedPeersData) []string {
	log.WithContext(ctx).Tracef("resolveNetworkAffectedPeers: routerPeerGroups=%v, resourceGroupIDs=%v, directPeerIDs=%v, policies=%d",
		data.routerPeerGroups, data.resourceGroupIDs, data.directPeerIDs, len(data.policies))
	groupSet := make(map[string]struct{})

	for _, gID := range data.routerPeerGroups {
		groupSet[gID] = struct{}{}
	}

	if len(data.resourceGroupIDs) > 0 {
		for _, gID := range data.resourceGroupIDs {
			groupSet[gID] = struct{}{}
		}
		collectPolicySourceGroups(data.policies, data.resourceGroupIDs, groupSet)
	}

	if len(groupSet) == 0 && len(data.directPeerIDs) == 0 {
		return nil
	}

	peerIDs := resolveGroupsAndDirectPeers(ctx, s, accountID, groupSet, data.directPeerIDs)

	log.WithContext(ctx).Tracef("resolveNetworkAffectedPeers: result %d peers: %v", len(peerIDs), peerIDs)
	return peerIDs
}

// collectPolicySourceGroups finds policies whose rules reference any of the destination group IDs
// and adds their source groups to the groupSet.
func collectPolicySourceGroups(policies []*nbTypes.Policy, destGroupIDs []string, groupSet map[string]struct{}) {
	destSet := make(map[string]struct{}, len(destGroupIDs))
	for _, gID := range destGroupIDs {
		destSet[gID] = struct{}{}
	}

	for _, policy := range policies {
		if policy == nil || !policy.Enabled {
			continue
		}
		for _, rule := range policy.Rules {
			if rule == nil || !rule.Enabled {
				continue
			}
			if ruleMatchesDestinations(rule, destSet) {
				for _, gID := range rule.Sources {
					groupSet[gID] = struct{}{}
				}
			}
		}
	}
}

// ruleMatchesDestinations checks if a policy rule references any of the destination groups.
func ruleMatchesDestinations(rule *nbTypes.PolicyRule, destSet map[string]struct{}) bool {
	for _, gID := range rule.Destinations {
		if _, ok := destSet[gID]; ok {
			return true
		}
	}
	return false
}

// resolveGroupsAndDirectPeers resolves group IDs and direct peer IDs into a deduplicated peer ID list.
func resolveGroupsAndDirectPeers(ctx context.Context, s store.Store, accountID string, groupSet map[string]struct{}, directPeerIDs []string) []string {
	groupIDs := make([]string, 0, len(groupSet))
	for gID := range groupSet {
		groupIDs = append(groupIDs, gID)
	}

	peerIDs, err := s.GetPeerIDsByGroups(ctx, accountID, groupIDs)
	if err != nil {
		log.WithContext(ctx).Errorf("failed to resolve peer IDs: %v", err)
		return nil
	}

	if len(directPeerIDs) == 0 {
		return peerIDs
	}

	seen := make(map[string]struct{}, len(peerIDs))
	for _, id := range peerIDs {
		seen[id] = struct{}{}
	}
	for _, id := range directPeerIDs {
		if _, exists := seen[id]; !exists {
			peerIDs = append(peerIDs, id)
			seen[id] = struct{}{}
		}
	}
	return peerIDs
}

func NewManagerMock() Manager {
	return &mockManager{}
}

func (m *mockManager) GetAllNetworks(ctx context.Context, accountID, userID string) ([]*types.Network, error) {
	return []*types.Network{}, nil
}

func (m *mockManager) CreateNetwork(ctx context.Context, userID string, network *types.Network) (*types.Network, error) {
	return network, nil
}

func (m *mockManager) GetNetwork(ctx context.Context, accountID, userID, networkID string) (*types.Network, error) {
	return &types.Network{}, nil
}

func (m *mockManager) UpdateNetwork(ctx context.Context, userID string, network *types.Network) (*types.Network, error) {
	return network, nil
}

func (m *mockManager) DeleteNetwork(ctx context.Context, accountID, userID, networkID string) error {
	return nil
}
