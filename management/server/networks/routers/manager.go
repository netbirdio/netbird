package routers

import (
	"context"
	"errors"
	"fmt"

	"github.com/rs/xid"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/management/server/account"
	"github.com/netbirdio/netbird/management/server/activity"
	"github.com/netbirdio/netbird/management/server/networks/routers/types"
	networkTypes "github.com/netbirdio/netbird/management/server/networks/types"
	"github.com/netbirdio/netbird/management/server/permissions"
	"github.com/netbirdio/netbird/management/server/permissions/modules"
	"github.com/netbirdio/netbird/management/server/permissions/operations"
	"github.com/netbirdio/netbird/management/server/store"
	nbtypes "github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/status"
)

type Manager interface {
	GetAllRoutersInNetwork(ctx context.Context, accountID, userID, networkID string) ([]*types.NetworkRouter, error)
	GetAllRoutersInAccount(ctx context.Context, accountID, userID string) (map[string][]*types.NetworkRouter, error)
	CreateRouter(ctx context.Context, userID string, router *types.NetworkRouter) (*types.NetworkRouter, error)
	GetRouter(ctx context.Context, accountID, userID, networkID, routerID string) (*types.NetworkRouter, error)
	UpdateRouter(ctx context.Context, userID string, router *types.NetworkRouter) (*types.NetworkRouter, error)
	DeleteRouter(ctx context.Context, accountID, userID, networkID, routerID string) error
	DeleteRouterInTransaction(ctx context.Context, transaction store.Store, accountID, userID, networkID, routerID string) (func(), error)
}

type managerImpl struct {
	store              store.Store
	permissionsManager permissions.Manager
	accountManager     account.Manager
}

type mockManager struct {
}

func NewManager(store store.Store, permissionsManager permissions.Manager, accountManager account.Manager) Manager {
	return &managerImpl{
		store:              store,
		permissionsManager: permissionsManager,
		accountManager:     accountManager,
	}
}

func (m *managerImpl) GetAllRoutersInNetwork(ctx context.Context, accountID, userID, networkID string) ([]*types.NetworkRouter, error) {
	ok, err := m.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, modules.Networks, operations.Read)
	if err != nil {
		return nil, status.NewPermissionValidationError(err)
	}
	if !ok {
		return nil, status.NewPermissionDeniedError()
	}

	return m.store.GetNetworkRoutersByNetID(ctx, store.LockingStrengthNone, accountID, networkID)
}

func (m *managerImpl) GetAllRoutersInAccount(ctx context.Context, accountID, userID string) (map[string][]*types.NetworkRouter, error) {
	ok, err := m.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, modules.Networks, operations.Read)
	if err != nil {
		return nil, status.NewPermissionValidationError(err)
	}
	if !ok {
		return nil, status.NewPermissionDeniedError()
	}

	routers, err := m.store.GetNetworkRoutersByAccountID(ctx, store.LockingStrengthNone, accountID)
	if err != nil {
		return nil, fmt.Errorf("failed to get network routers: %w", err)
	}

	routersMap := make(map[string][]*types.NetworkRouter)
	for _, router := range routers {
		routersMap[router.NetworkID] = append(routersMap[router.NetworkID], router)
	}

	return routersMap, nil
}

func (m *managerImpl) CreateRouter(ctx context.Context, userID string, router *types.NetworkRouter) (*types.NetworkRouter, error) {
	ok, err := m.permissionsManager.ValidateUserPermissions(ctx, router.AccountID, userID, modules.Networks, operations.Create)
	if err != nil {
		return nil, status.NewPermissionValidationError(err)
	}
	if !ok {
		return nil, status.NewPermissionDeniedError()
	}

	var network *networkTypes.Network
	var affectedData *routerAffectedPeersData
	err = m.store.ExecuteInTransaction(ctx, func(transaction store.Store) error {
		network, err = transaction.GetNetworkByID(ctx, store.LockingStrengthNone, router.AccountID, router.NetworkID)
		if err != nil {
			return fmt.Errorf("failed to get network: %w", err)
		}

		if network.ID != router.NetworkID {
			return status.NewNetworkNotFoundError(router.NetworkID)
		}

		router.ID = xid.New().String()

		seq, err := transaction.AllocateAccountSeqID(ctx, router.AccountID, nbtypes.AccountSeqEntityNetworkRouter)
		if err != nil {
			return fmt.Errorf("failed to allocate network router seq id: %w", err)
		}
		router.AccountSeqID = seq

		err = transaction.SaveNetworkRouter(ctx, router)
		if err != nil {
			return fmt.Errorf("failed to create network router: %w", err)
		}

		err = transaction.IncrementNetworkSerial(ctx, router.AccountID)
		if err != nil {
			return fmt.Errorf("failed to increment network serial: %w", err)
		}

		affectedData, err = loadRouterAffectedPeersData(ctx, transaction, router.AccountID, router.NetworkID, router.PeerGroups, router.Peer)
		if err != nil {
			log.WithContext(ctx).Errorf("failed to load affected peers data: %v", err)
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	m.accountManager.StoreEvent(ctx, userID, router.ID, router.AccountID, activity.NetworkRouterCreated, router.EventMeta(network))

	if affectedPeerIDs := m.resolveRouterAffectedPeers(ctx, router.AccountID, affectedData); len(affectedPeerIDs) > 0 {
		log.WithContext(ctx).Debugf("CreateRouter %s: updating %d affected peers: %v", router.ID, len(affectedPeerIDs), affectedPeerIDs)
		go m.accountManager.UpdateAffectedPeers(ctx, router.AccountID, affectedPeerIDs)
	} else {
		log.WithContext(ctx).Tracef("CreateRouter %s: no affected peers", router.ID)
	}

	return router, nil
}

func (m *managerImpl) GetRouter(ctx context.Context, accountID, userID, networkID, routerID string) (*types.NetworkRouter, error) {
	ok, err := m.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, modules.Networks, operations.Read)
	if err != nil {
		return nil, status.NewPermissionValidationError(err)
	}
	if !ok {
		return nil, status.NewPermissionDeniedError()
	}

	router, err := m.store.GetNetworkRouterByID(ctx, store.LockingStrengthNone, accountID, routerID)
	if err != nil {
		return nil, fmt.Errorf("failed to get network router: %w", err)
	}

	if router.NetworkID != networkID {
		return nil, errors.New("router not part of network")
	}

	return router, nil
}

func (m *managerImpl) UpdateRouter(ctx context.Context, userID string, router *types.NetworkRouter) (*types.NetworkRouter, error) {
	ok, err := m.permissionsManager.ValidateUserPermissions(ctx, router.AccountID, userID, modules.Networks, operations.Update)
	if err != nil {
		return nil, status.NewPermissionValidationError(err)
	}
	if !ok {
		return nil, status.NewPermissionDeniedError()
	}

	var network *networkTypes.Network
	var affectedData *routerAffectedPeersData
	err = m.store.ExecuteInTransaction(ctx, func(transaction store.Store) error {
		var txErr error
		network, affectedData, txErr = m.updateRouterInTransaction(ctx, transaction, router)
		return txErr
	})
	if err != nil {
		return nil, err
	}

	m.accountManager.StoreEvent(ctx, userID, router.ID, router.AccountID, activity.NetworkRouterUpdated, router.EventMeta(network))

	if affectedPeerIDs := m.resolveRouterAffectedPeers(ctx, router.AccountID, affectedData); len(affectedPeerIDs) > 0 {
		log.WithContext(ctx).Debugf("UpdateRouter %s: updating %d affected peers: %v", router.ID, len(affectedPeerIDs), affectedPeerIDs)
		go m.accountManager.UpdateAffectedPeers(ctx, router.AccountID, affectedPeerIDs)
	} else {
		log.WithContext(ctx).Tracef("UpdateRouter %s: no affected peers", router.ID)
	}

	return router, nil
}

func (m *managerImpl) updateRouterInTransaction(ctx context.Context, transaction store.Store, router *types.NetworkRouter) (*networkTypes.Network, *routerAffectedPeersData, error) {
	network, err := transaction.GetNetworkByID(ctx, store.LockingStrengthNone, router.AccountID, router.NetworkID)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get network: %w", err)
	}

	if network.ID != router.NetworkID {
		return nil, nil, status.NewRouterNotPartOfNetworkError(router.ID, router.NetworkID)
	}

	allPeerGroups := router.PeerGroups
	var directPeers []string
	if router.Peer != "" {
		directPeers = append(directPeers, router.Peer)
	}
	oldRouter, err := transaction.GetNetworkRouterByID(ctx, store.LockingStrengthNone, router.AccountID, router.ID)
	if err == nil {
		router.AccountSeqID = oldRouter.AccountSeqID
		allPeerGroups = append(allPeerGroups, oldRouter.PeerGroups...)
		if oldRouter.Peer != "" {
			directPeers = append(directPeers, oldRouter.Peer)
		}
	} else if e, ok := status.FromError(err); ok && e.Type() == status.NotFound {
		seq, allocErr := transaction.AllocateAccountSeqID(ctx, router.AccountID, nbtypes.AccountSeqEntityNetworkRouter)
		if allocErr != nil {
			return nil, nil, fmt.Errorf("failed to allocate network router seq id: %w", allocErr)
		}
		router.AccountSeqID = seq
	} else {
		return nil, nil, fmt.Errorf("failed to get existing network router: %w", err)
	}

	if err = transaction.SaveNetworkRouter(ctx, router); err != nil {
		return nil, nil, fmt.Errorf("failed to update network router: %w", err)
	}

	if err = transaction.IncrementNetworkSerial(ctx, router.AccountID); err != nil {
		return nil, nil, fmt.Errorf("failed to increment network serial: %w", err)
	}

	affectedData, err := loadRouterAffectedPeersData(ctx, transaction, router.AccountID, router.NetworkID, allPeerGroups, directPeers...)
	if err != nil {
		log.WithContext(ctx).Errorf("failed to load affected peers data: %v", err)
	}

	return network, affectedData, nil
}

func (m *managerImpl) DeleteRouter(ctx context.Context, accountID, userID, networkID, routerID string) error {
	ok, err := m.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, modules.Networks, operations.Delete)
	if err != nil {
		return status.NewPermissionValidationError(err)
	}
	if !ok {
		return status.NewPermissionDeniedError()
	}

	var event func()
	var affectedData *routerAffectedPeersData
	err = m.store.ExecuteInTransaction(ctx, func(transaction store.Store) error {
		router, err := transaction.GetNetworkRouterByID(ctx, store.LockingStrengthNone, accountID, routerID)
		if err != nil {
			return fmt.Errorf("failed to get router: %w", err)
		}

		// load before delete so group memberships are still present
		affectedData, err = loadRouterAffectedPeersData(ctx, transaction, accountID, networkID, router.PeerGroups, router.Peer)
		if err != nil {
			log.WithContext(ctx).Errorf("failed to load affected peers data: %v", err)
		}

		event, err = m.DeleteRouterInTransaction(ctx, transaction, accountID, userID, networkID, routerID)
		if err != nil {
			return fmt.Errorf("failed to delete network router: %w", err)
		}

		err = transaction.IncrementNetworkSerial(ctx, accountID)
		if err != nil {
			return fmt.Errorf("failed to increment network serial: %w", err)
		}

		return nil
	})
	if err != nil {
		return err
	}

	event()

	if affectedPeerIDs := m.resolveRouterAffectedPeers(ctx, accountID, affectedData); len(affectedPeerIDs) > 0 {
		log.WithContext(ctx).Debugf("DeleteRouter %s: updating %d affected peers: %v", routerID, len(affectedPeerIDs), affectedPeerIDs)
		go m.accountManager.UpdateAffectedPeers(ctx, accountID, affectedPeerIDs)
	} else {
		log.WithContext(ctx).Tracef("DeleteRouter %s: no affected peers", routerID)
	}

	return nil
}

func (m *managerImpl) DeleteRouterInTransaction(ctx context.Context, transaction store.Store, accountID, userID, networkID, routerID string) (func(), error) {
	network, err := transaction.GetNetworkByID(ctx, store.LockingStrengthNone, accountID, networkID)
	if err != nil {
		return nil, fmt.Errorf("failed to get network: %w", err)
	}

	router, err := transaction.GetNetworkRouterByID(ctx, store.LockingStrengthUpdate, accountID, routerID)
	if err != nil {
		return nil, fmt.Errorf("failed to get network router: %w", err)
	}

	if router.NetworkID != networkID {
		return nil, status.NewRouterNotPartOfNetworkError(routerID, networkID)
	}

	err = transaction.DeleteNetworkRouter(ctx, accountID, routerID)
	if err != nil {
		return nil, fmt.Errorf("failed to delete network router: %w", err)
	}

	event := func() {
		m.accountManager.StoreEvent(ctx, userID, routerID, accountID, activity.NetworkRouterDeleted, router.EventMeta(network))
	}

	return event, nil
}

// routerAffectedPeersData holds data loaded inside a transaction for affected peer resolution.
type routerAffectedPeersData struct {
	routerPeerGroups []string
	directPeerIDs    []string
	resourceGroupIDs []string
	policies         []*nbtypes.Policy
}

// loadRouterAffectedPeersData loads the data needed to determine affected peers within a transaction.
func loadRouterAffectedPeersData(ctx context.Context, transaction store.Store, accountID, networkID string, routerPeerGroups []string, directPeers ...string) (*routerAffectedPeersData, error) {
	var directPeerIDs []string
	for _, p := range directPeers {
		if p != "" {
			directPeerIDs = append(directPeerIDs, p)
		}
	}

	if len(routerPeerGroups) == 0 && len(directPeerIDs) == 0 {
		return &routerAffectedPeersData{}, nil
	}

	resources, err := transaction.GetNetworkResourcesByNetID(ctx, store.LockingStrengthNone, accountID, networkID)
	if err != nil {
		return nil, fmt.Errorf("failed to get network resources: %w", err)
	}

	var resourceGroupIDs []string
	for _, resource := range resources {
		if !resource.Enabled {
			continue
		}
		groups, err := transaction.GetResourceGroups(ctx, store.LockingStrengthNone, accountID, resource.ID)
		if err != nil {
			return nil, fmt.Errorf("failed to get groups for resource %s: %w", resource.ID, err)
		}
		for _, g := range groups {
			resourceGroupIDs = append(resourceGroupIDs, g.ID)
		}
	}

	var policies []*nbtypes.Policy
	if len(resourceGroupIDs) > 0 {
		policies, err = transaction.GetAccountPolicies(ctx, store.LockingStrengthNone, accountID)
		if err != nil {
			return nil, fmt.Errorf("failed to get policies: %w", err)
		}
	}

	return &routerAffectedPeersData{
		routerPeerGroups: routerPeerGroups,
		directPeerIDs:    directPeerIDs,
		resourceGroupIDs: resourceGroupIDs,
		policies:         policies,
	}, nil
}

// resolveRouterAffectedPeers computes affected peer IDs from preloaded data outside the transaction.
func (m *managerImpl) resolveRouterAffectedPeers(ctx context.Context, accountID string, data *routerAffectedPeersData) []string {
	if data == nil {
		return nil
	}

	log.WithContext(ctx).Tracef("resolveRouterAffectedPeers: routerPeerGroups=%v, directPeerIDs=%v, resourceGroupIDs=%v, policies=%d",
		data.routerPeerGroups, data.directPeerIDs, data.resourceGroupIDs, len(data.policies))
	groupSet := make(map[string]struct{})

	for _, gID := range data.routerPeerGroups {
		groupSet[gID] = struct{}{}
	}

	if len(data.resourceGroupIDs) > 0 {
		collectPolicySourceGroups(data.policies, data.resourceGroupIDs, groupSet)
	}

	if len(groupSet) == 0 && len(data.directPeerIDs) == 0 {
		return nil
	}

	peerIDs := resolveGroupsAndDirectPeers(ctx, m.store, accountID, groupSet, data.directPeerIDs)

	log.WithContext(ctx).Tracef("resolveRouterAffectedPeers: result %d peers: %v", len(peerIDs), peerIDs)
	return peerIDs
}

// collectPolicySourceGroups finds policies whose rules reference any of the destination group IDs
// and adds their source groups to the groupSet.
func collectPolicySourceGroups(policies []*nbtypes.Policy, destGroupIDs []string, groupSet map[string]struct{}) {
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

func ruleMatchesDestinations(rule *nbtypes.PolicyRule, destSet map[string]struct{}) bool {
	for _, gID := range rule.Destinations {
		if _, ok := destSet[gID]; ok {
			return true
		}
	}
	return false
}

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

func (m *mockManager) GetAllRoutersInNetwork(ctx context.Context, accountID, userID, networkID string) ([]*types.NetworkRouter, error) {
	return []*types.NetworkRouter{}, nil
}

func (m *mockManager) GetAllRoutersInAccount(ctx context.Context, accountID, userID string) (map[string][]*types.NetworkRouter, error) {
	return map[string][]*types.NetworkRouter{}, nil
}

func (m *mockManager) CreateRouter(ctx context.Context, userID string, router *types.NetworkRouter) (*types.NetworkRouter, error) {
	return router, nil
}

func (m *mockManager) GetRouter(ctx context.Context, accountID, userID, networkID, routerID string) (*types.NetworkRouter, error) {
	return &types.NetworkRouter{}, nil
}

func (m *mockManager) UpdateRouter(ctx context.Context, userID string, router *types.NetworkRouter) (*types.NetworkRouter, error) {
	return router, nil
}

func (m *mockManager) DeleteRouter(ctx context.Context, accountID, userID, networkID, routerID string) error {
	return nil
}

func (m *mockManager) DeleteRouterInTransaction(ctx context.Context, transaction store.Store, accountID, userID, networkID, routerID string) (func(), error) {
	return func() {}, nil
}
