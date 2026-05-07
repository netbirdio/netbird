package resources

import (
	"context"
	"errors"
	"fmt"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy/service"
	"github.com/netbirdio/netbird/management/server/account"
	"github.com/netbirdio/netbird/management/server/activity"
	"github.com/netbirdio/netbird/management/server/groups"
	"github.com/netbirdio/netbird/management/server/networks/resources/types"
	"github.com/netbirdio/netbird/management/server/permissions"
	"github.com/netbirdio/netbird/management/server/permissions/modules"
	"github.com/netbirdio/netbird/management/server/permissions/operations"
	"github.com/netbirdio/netbird/management/server/store"
	nbtypes "github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/management/server/util"
	"github.com/netbirdio/netbird/shared/management/status"
)

type Manager interface {
	GetAllResourcesInNetwork(ctx context.Context, accountID, userID, networkID string) ([]*types.NetworkResource, error)
	GetAllResourcesInAccount(ctx context.Context, accountID, userID string) ([]*types.NetworkResource, error)
	GetAllResourceIDsInAccount(ctx context.Context, accountID, userID string) (map[string][]string, error)
	CreateResource(ctx context.Context, userID string, resource *types.NetworkResource) (*types.NetworkResource, error)
	GetResource(ctx context.Context, accountID, userID, networkID, resourceID string) (*types.NetworkResource, error)
	UpdateResource(ctx context.Context, userID string, resource *types.NetworkResource) (*types.NetworkResource, error)
	DeleteResource(ctx context.Context, accountID, userID, networkID, resourceID string) error
	DeleteResourceInTransaction(ctx context.Context, transaction store.Store, accountID, userID, networkID, resourceID string) ([]func(), error)
}

type managerImpl struct {
	store              store.Store
	permissionsManager permissions.Manager
	groupsManager      groups.Manager
	accountManager     account.Manager
	serviceManager     service.Manager
}

type mockManager struct {
}

func NewManager(store store.Store, permissionsManager permissions.Manager, groupsManager groups.Manager, accountManager account.Manager, reverseproxyManager service.Manager) Manager {
	return &managerImpl{
		store:              store,
		permissionsManager: permissionsManager,
		groupsManager:      groupsManager,
		accountManager:     accountManager,
		serviceManager:     reverseproxyManager,
	}
}

func (m *managerImpl) GetAllResourcesInNetwork(ctx context.Context, accountID, userID, networkID string) ([]*types.NetworkResource, error) {
	ok, err := m.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, modules.Networks, operations.Read)
	if err != nil {
		return nil, status.NewPermissionValidationError(err)
	}
	if !ok {
		return nil, status.NewPermissionDeniedError()
	}

	return m.store.GetNetworkResourcesByNetID(ctx, store.LockingStrengthNone, accountID, networkID)
}

func (m *managerImpl) GetAllResourcesInAccount(ctx context.Context, accountID, userID string) ([]*types.NetworkResource, error) {
	ok, err := m.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, modules.Networks, operations.Read)
	if err != nil {
		return nil, status.NewPermissionValidationError(err)
	}
	if !ok {
		return nil, status.NewPermissionDeniedError()
	}

	return m.store.GetNetworkResourcesByAccountID(ctx, store.LockingStrengthNone, accountID)
}

func (m *managerImpl) GetAllResourceIDsInAccount(ctx context.Context, accountID, userID string) (map[string][]string, error) {
	ok, err := m.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, modules.Networks, operations.Read)
	if err != nil {
		return nil, status.NewPermissionValidationError(err)
	}
	if !ok {
		return nil, status.NewPermissionDeniedError()
	}

	resources, err := m.store.GetNetworkResourcesByAccountID(ctx, store.LockingStrengthNone, accountID)
	if err != nil {
		return nil, fmt.Errorf("failed to get network resources: %w", err)
	}

	resourceMap := make(map[string][]string)
	for _, resource := range resources {
		resourceMap[resource.NetworkID] = append(resourceMap[resource.NetworkID], resource.ID)
	}

	return resourceMap, nil
}

func (m *managerImpl) CreateResource(ctx context.Context, userID string, resource *types.NetworkResource) (*types.NetworkResource, error) {
	ok, err := m.permissionsManager.ValidateUserPermissions(ctx, resource.AccountID, userID, modules.Networks, operations.Create)
	if err != nil {
		return nil, status.NewPermissionValidationError(err)
	}
	if !ok {
		return nil, status.NewPermissionDeniedError()
	}

	resource, err = types.NewNetworkResource(resource.AccountID, resource.NetworkID, resource.Name, resource.Description, resource.Address, resource.GroupIDs, resource.Enabled)
	if err != nil {
		return nil, fmt.Errorf("failed to create new network resource: %w", err)
	}

	var eventsToStore []func()
	var affectedData *resourceAffectedPeersData
	err = m.store.ExecuteInTransaction(ctx, func(transaction store.Store) error {
		_, err = transaction.GetNetworkResourceByName(ctx, store.LockingStrengthNone, resource.AccountID, resource.Name)
		if err == nil {
			return status.Errorf(status.InvalidArgument, "resource with name %s already exists", resource.Name)
		}

		network, err := transaction.GetNetworkByID(ctx, store.LockingStrengthUpdate, resource.AccountID, resource.NetworkID)
		if err != nil {
			return fmt.Errorf("failed to get network: %w", err)
		}

		err = transaction.SaveNetworkResource(ctx, resource)
		if err != nil {
			return fmt.Errorf("failed to save network resource: %w", err)
		}

		event := func() {
			m.accountManager.StoreEvent(ctx, userID, resource.ID, resource.AccountID, activity.NetworkResourceCreated, resource.EventMeta(network))
		}
		eventsToStore = append(eventsToStore, event)

		res := nbtypes.Resource{
			ID:   resource.ID,
			Type: nbtypes.ResourceType(resource.Type.String()),
		}
		for _, groupID := range resource.GroupIDs {
			event, err := m.groupsManager.AddResourceToGroupInTransaction(ctx, transaction, resource.AccountID, userID, groupID, &res)
			if err != nil {
				return fmt.Errorf("failed to add resource to group: %w", err)
			}
			eventsToStore = append(eventsToStore, event)
		}

		err = transaction.IncrementNetworkSerial(ctx, resource.AccountID)
		if err != nil {
			return fmt.Errorf("failed to increment network serial: %w", err)
		}

		affectedData, err = loadResourceAffectedPeersData(ctx, transaction, resource.AccountID, resource.NetworkID, resource.GroupIDs)
		if err != nil {
			log.WithContext(ctx).Errorf("failed to load affected peers data: %v", err)
		}

		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create network resource: %w", err)
	}

	for _, event := range eventsToStore {
		event()
	}

	if affectedPeerIDs := m.resolveResourceAffectedPeers(ctx, resource.AccountID, affectedData); len(affectedPeerIDs) > 0 {
		log.WithContext(ctx).Debugf("CreateResource %s: updating %d affected peers: %v", resource.ID, len(affectedPeerIDs), affectedPeerIDs)
		go m.accountManager.UpdateAffectedPeers(ctx, resource.AccountID, affectedPeerIDs)
	} else {
		log.WithContext(ctx).Tracef("CreateResource %s: no affected peers", resource.ID)
	}

	return resource, nil
}

func (m *managerImpl) GetResource(ctx context.Context, accountID, userID, networkID, resourceID string) (*types.NetworkResource, error) {
	ok, err := m.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, modules.Networks, operations.Read)
	if err != nil {
		return nil, status.NewPermissionValidationError(err)
	}
	if !ok {
		return nil, status.NewPermissionDeniedError()
	}

	resource, err := m.store.GetNetworkResourceByID(ctx, store.LockingStrengthNone, accountID, resourceID)
	if err != nil {
		return nil, fmt.Errorf("failed to get network resource: %w", err)
	}

	if resource.NetworkID != networkID {
		return nil, errors.New("resource not part of network")
	}

	return resource, nil
}

func (m *managerImpl) UpdateResource(ctx context.Context, userID string, resource *types.NetworkResource) (*types.NetworkResource, error) {
	ok, err := m.permissionsManager.ValidateUserPermissions(ctx, resource.AccountID, userID, modules.Networks, operations.Update)
	if err != nil {
		return nil, status.NewPermissionValidationError(err)
	}
	if !ok {
		return nil, status.NewPermissionDeniedError()
	}

	resourceType, domain, prefix, err := types.GetResourceType(resource.Address)
	if err != nil {
		return nil, fmt.Errorf("failed to get resource type: %w", err)
	}

	resource.Type = resourceType
	resource.Domain = domain
	resource.Prefix = prefix

	var eventsToStore []func()
	var affectedData *resourceAffectedPeersData
	err = m.store.ExecuteInTransaction(ctx, func(transaction store.Store) error {
		network, err := transaction.GetNetworkByID(ctx, store.LockingStrengthUpdate, resource.AccountID, resource.NetworkID)
		if err != nil {
			return fmt.Errorf("failed to get network: %w", err)
		}

		if network.ID != resource.NetworkID {
			return status.NewResourceNotPartOfNetworkError(resource.ID, resource.NetworkID)
		}

		_, err = transaction.GetNetworkResourceByID(ctx, store.LockingStrengthNone, resource.AccountID, resource.ID)
		if err != nil {
			return fmt.Errorf("failed to get network resource: %w", err)
		}

		oldResource, err := transaction.GetNetworkResourceByName(ctx, store.LockingStrengthNone, resource.AccountID, resource.Name)
		if err == nil && oldResource.ID != resource.ID {
			return status.Errorf(status.InvalidArgument, "new resource name already exists")
		}

		oldResource, err = transaction.GetNetworkResourceByID(ctx, store.LockingStrengthNone, resource.AccountID, resource.ID)
		if err != nil {
			return fmt.Errorf("failed to get network resource: %w", err)
		}

		oldGroups, err := m.groupsManager.GetResourceGroupsInTransaction(ctx, transaction, store.LockingStrengthNone, oldResource.AccountID, oldResource.ID)
		if err != nil {
			return fmt.Errorf("failed to get old resource groups: %w", err)
		}
		var oldGroupIDs []string
		for _, g := range oldGroups {
			oldGroupIDs = append(oldGroupIDs, g.ID)
		}

		err = transaction.SaveNetworkResource(ctx, resource)
		if err != nil {
			return fmt.Errorf("failed to save network resource: %w", err)
		}

		events, err := m.updateResourceGroups(ctx, transaction, userID, resource, oldResource)
		if err != nil {
			return fmt.Errorf("failed to update resource groups: %w", err)
		}

		eventsToStore = append(eventsToStore, events...)
		eventsToStore = append(eventsToStore, func() {
			m.accountManager.StoreEvent(ctx, userID, resource.ID, resource.AccountID, activity.NetworkResourceUpdated, resource.EventMeta(network))
		})

		affectedData, err = loadResourceAffectedPeersData(ctx, transaction, resource.AccountID, resource.NetworkID, append(resource.GroupIDs, oldGroupIDs...))
		if err != nil {
			log.WithContext(ctx).Errorf("failed to load affected peers data: %v", err)
		}

		err = transaction.IncrementNetworkSerial(ctx, resource.AccountID)
		if err != nil {
			return fmt.Errorf("failed to increment network serial: %w", err)
		}

		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to update network resource: %w", err)
	}

	for _, event := range eventsToStore {
		event()
	}

	// TODO: optimize to only reload reverse proxies that are affected by the resource update instead of all of them
	go func() {
		err := m.serviceManager.ReloadAllServicesForAccount(ctx, resource.AccountID)
		if err != nil {
			log.WithContext(ctx).Warnf("failed to reload all proxies for account: %v", err)
		}
	}()

	if affectedPeerIDs := m.resolveResourceAffectedPeers(ctx, resource.AccountID, affectedData); len(affectedPeerIDs) > 0 {
		log.WithContext(ctx).Debugf("UpdateResource %s: updating %d affected peers: %v", resource.ID, len(affectedPeerIDs), affectedPeerIDs)
		go m.accountManager.UpdateAffectedPeers(ctx, resource.AccountID, affectedPeerIDs)
	} else {
		log.WithContext(ctx).Tracef("UpdateResource %s: no affected peers", resource.ID)
	}

	return resource, nil
}

func (m *managerImpl) updateResourceGroups(ctx context.Context, transaction store.Store, userID string, newResource, oldResource *types.NetworkResource) ([]func(), error) {
	res := nbtypes.Resource{
		ID:   newResource.ID,
		Type: nbtypes.ResourceType(newResource.Type.String()),
	}

	oldResourceGroups, err := m.groupsManager.GetResourceGroupsInTransaction(ctx, transaction, store.LockingStrengthUpdate, oldResource.AccountID, oldResource.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to get resource groups: %w", err)
	}

	oldGroupsIds := make([]string, 0)
	for _, group := range oldResourceGroups {
		oldGroupsIds = append(oldGroupsIds, group.ID)
	}

	var eventsToStore []func()
	groupsToAdd := util.Difference(newResource.GroupIDs, oldGroupsIds)
	for _, groupID := range groupsToAdd {
		events, err := m.groupsManager.AddResourceToGroupInTransaction(ctx, transaction, newResource.AccountID, userID, groupID, &res)
		if err != nil {
			return nil, fmt.Errorf("failed to add resource to group: %w", err)
		}
		eventsToStore = append(eventsToStore, events)
	}

	groupsToRemove := util.Difference(oldGroupsIds, newResource.GroupIDs)
	for _, groupID := range groupsToRemove {
		events, err := m.groupsManager.RemoveResourceFromGroupInTransaction(ctx, transaction, newResource.AccountID, userID, groupID, res.ID)
		if err != nil {
			return nil, fmt.Errorf("failed to add resource to group: %w", err)
		}
		eventsToStore = append(eventsToStore, events)
	}

	return eventsToStore, nil
}

func (m *managerImpl) DeleteResource(ctx context.Context, accountID, userID, networkID, resourceID string) error {
	ok, err := m.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, modules.Networks, operations.Delete)
	if err != nil {
		return status.NewPermissionValidationError(err)
	}
	if !ok {
		return status.NewPermissionDeniedError()
	}

	serviceID, err := m.serviceManager.GetServiceIDByTargetID(ctx, accountID, resourceID)
	if err != nil {
		return fmt.Errorf("failed to check if resource is used by service: %w", err)
	}
	if serviceID != "" {
		return status.NewResourceInUseError(resourceID, serviceID)
	}

	var events []func()
	var affectedData *resourceAffectedPeersData
	err = m.store.ExecuteInTransaction(ctx, func(transaction store.Store) error {
		groups, err := m.groupsManager.GetResourceGroupsInTransaction(ctx, transaction, store.LockingStrengthNone, accountID, resourceID)
		if err != nil {
			return fmt.Errorf("failed to get resource groups: %w", err)
		}
		var resourceGroupIDs []string
		for _, g := range groups {
			resourceGroupIDs = append(resourceGroupIDs, g.ID)
		}

		affectedData, err = loadResourceAffectedPeersData(ctx, transaction, accountID, networkID, resourceGroupIDs)
		if err != nil {
			log.WithContext(ctx).Errorf("failed to load affected peers data: %v", err)
		}

		events, err = m.DeleteResourceInTransaction(ctx, transaction, accountID, userID, networkID, resourceID)
		if err != nil {
			return fmt.Errorf("failed to delete resource: %w", err)
		}

		err = transaction.IncrementNetworkSerial(ctx, accountID)
		if err != nil {
			return fmt.Errorf("failed to increment network serial: %w", err)
		}

		return nil
	})
	if err != nil {
		return fmt.Errorf("failed to delete network resource: %w", err)
	}

	for _, event := range events {
		event()
	}

	if affectedPeerIDs := m.resolveResourceAffectedPeers(ctx, accountID, affectedData); len(affectedPeerIDs) > 0 {
		log.WithContext(ctx).Debugf("DeleteResource %s: updating %d affected peers: %v", resourceID, len(affectedPeerIDs), affectedPeerIDs)
		go m.accountManager.UpdateAffectedPeers(ctx, accountID, affectedPeerIDs)
	} else {
		log.WithContext(ctx).Tracef("DeleteResource %s: no affected peers", resourceID)
	}

	return nil
}

func (m *managerImpl) DeleteResourceInTransaction(ctx context.Context, transaction store.Store, accountID, userID, networkID, resourceID string) ([]func(), error) {
	resource, err := transaction.GetNetworkResourceByID(ctx, store.LockingStrengthUpdate, accountID, resourceID)
	if err != nil {
		return nil, fmt.Errorf("failed to get network resource: %w", err)
	}

	network, err := transaction.GetNetworkByID(ctx, store.LockingStrengthUpdate, accountID, networkID)
	if err != nil {
		return nil, fmt.Errorf("failed to get network: %w", err)
	}

	if resource.NetworkID != networkID {
		return nil, errors.New("resource not part of network")
	}

	groups, err := m.groupsManager.GetResourceGroupsInTransaction(ctx, transaction, store.LockingStrengthUpdate, accountID, resourceID)
	if err != nil {
		return nil, fmt.Errorf("failed to get resource groups: %w", err)
	}

	var eventsToStore []func()

	for _, group := range groups {
		event, err := m.groupsManager.RemoveResourceFromGroupInTransaction(ctx, transaction, accountID, userID, group.ID, resourceID)
		if err != nil {
			return nil, fmt.Errorf("failed to remove resource from group: %w", err)
		}
		eventsToStore = append(eventsToStore, event)
	}

	err = transaction.DeleteNetworkResource(ctx, accountID, resourceID)
	if err != nil {
		return nil, fmt.Errorf("failed to delete network resource: %w", err)
	}

	eventsToStore = append(eventsToStore, func() {
		m.accountManager.StoreEvent(ctx, userID, resourceID, accountID, activity.NetworkResourceDeleted, resource.EventMeta(network))
	})

	return eventsToStore, nil
}

// resourceAffectedPeersData holds data loaded inside a transaction for affected peer resolution.
type resourceAffectedPeersData struct {
	resourceGroupIDs  []string
	policies          []*nbtypes.Policy
	routerPeerGroups  []string
	routerDirectPeers []string
}

// loadResourceAffectedPeersData loads the data needed to determine affected peers within a transaction.
func loadResourceAffectedPeersData(ctx context.Context, transaction store.Store, accountID, networkID string, resourceGroupIDs []string) (*resourceAffectedPeersData, error) {
	if len(resourceGroupIDs) == 0 {
		return nil, nil
	}

	policies, err := transaction.GetAccountPolicies(ctx, store.LockingStrengthNone, accountID)
	if err != nil {
		return nil, fmt.Errorf("failed to get policies: %w", err)
	}

	routers, err := transaction.GetNetworkRoutersByNetID(ctx, store.LockingStrengthNone, accountID, networkID)
	if err != nil {
		return nil, fmt.Errorf("failed to get routers: %w", err)
	}

	var routerPeerGroups []string
	var routerDirectPeers []string
	for _, router := range routers {
		if !router.Enabled {
			continue
		}
		routerPeerGroups = append(routerPeerGroups, router.PeerGroups...)
		if router.Peer != "" {
			routerDirectPeers = append(routerDirectPeers, router.Peer)
		}
	}

	return &resourceAffectedPeersData{
		resourceGroupIDs:  resourceGroupIDs,
		policies:          policies,
		routerPeerGroups:  routerPeerGroups,
		routerDirectPeers: routerDirectPeers,
	}, nil
}

// resolveResourceAffectedPeers computes affected peer IDs from preloaded data outside the transaction.
func (m *managerImpl) resolveResourceAffectedPeers(ctx context.Context, accountID string, data *resourceAffectedPeersData) []string {
	if data == nil {
		return nil
	}

	log.WithContext(ctx).Tracef("resolveResourceAffectedPeers: resourceGroupIDs=%v, routerPeerGroups=%v, routerDirectPeers=%v, policies=%d",
		data.resourceGroupIDs, data.routerPeerGroups, data.routerDirectPeers, len(data.policies))
	groupSet := make(map[string]struct{})
	var directPeerIDs []string

	destSet := make(map[string]struct{}, len(data.resourceGroupIDs))
	for _, gID := range data.resourceGroupIDs {
		destSet[gID] = struct{}{}
	}

	for _, policy := range data.policies {
		if policy == nil || !policy.Enabled {
			continue
		}
		for _, rule := range policy.Rules {
			if rule == nil || !rule.Enabled {
				continue
			}
			referencesResource := false
			for _, gID := range rule.Destinations {
				if _, ok := destSet[gID]; ok {
					referencesResource = true
					break
				}
			}
			if !referencesResource {
				continue
			}
			for _, gID := range rule.Sources {
				groupSet[gID] = struct{}{}
			}
			if rule.SourceResource.Type == nbtypes.ResourceTypePeer && rule.SourceResource.ID != "" {
				directPeerIDs = append(directPeerIDs, rule.SourceResource.ID)
			}
		}
	}

	for _, gID := range data.routerPeerGroups {
		groupSet[gID] = struct{}{}
	}
	directPeerIDs = append(directPeerIDs, data.routerDirectPeers...)

	if len(groupSet) == 0 && len(directPeerIDs) == 0 {
		return nil
	}

	groupIDs := make([]string, 0, len(groupSet))
	for gID := range groupSet {
		groupIDs = append(groupIDs, gID)
	}

	peerIDs, err := m.store.GetPeerIDsByGroups(ctx, accountID, groupIDs)
	if err != nil {
		log.WithContext(ctx).Errorf("failed to resolve peer IDs: %v", err)
		return nil
	}

	if len(directPeerIDs) > 0 {
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
	}

	log.WithContext(ctx).Tracef("resolveResourceAffectedPeers: result %d peers: %v", len(peerIDs), peerIDs)
	return peerIDs
}

func NewManagerMock() Manager {
	return &mockManager{}
}

func (m *mockManager) GetAllResourcesInNetwork(ctx context.Context, accountID, userID, networkID string) ([]*types.NetworkResource, error) {
	return []*types.NetworkResource{}, nil
}

func (m *mockManager) GetAllResourcesInAccount(ctx context.Context, accountID, userID string) ([]*types.NetworkResource, error) {
	return []*types.NetworkResource{}, nil
}

func (m *mockManager) GetAllResourceIDsInAccount(ctx context.Context, accountID, userID string) (map[string][]string, error) {
	return map[string][]string{}, nil
}

func (m *mockManager) CreateResource(ctx context.Context, userID string, resource *types.NetworkResource) (*types.NetworkResource, error) {
	return &types.NetworkResource{}, nil
}

func (m *mockManager) GetResource(ctx context.Context, accountID, userID, networkID, resourceID string) (*types.NetworkResource, error) {
	return &types.NetworkResource{}, nil
}

func (m *mockManager) UpdateResource(ctx context.Context, userID string, resource *types.NetworkResource) (*types.NetworkResource, error) {
	return &types.NetworkResource{}, nil
}

func (m *mockManager) DeleteResource(ctx context.Context, accountID, userID, networkID, resourceID string) error {
	return nil
}

func (m *mockManager) DeleteResourceInTransaction(ctx context.Context, transaction store.Store, accountID, userID, networkID, resourceID string) ([]func(), error) {
	return []func(){}, nil
}
