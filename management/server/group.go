package server

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/rs/xid"
	log "github.com/sirupsen/logrus"

	nbdns "github.com/netbirdio/netbird/dns"
	"github.com/netbirdio/netbird/management/server/activity"
	"github.com/netbirdio/netbird/management/server/affectedpeers"
	routerTypes "github.com/netbirdio/netbird/management/server/networks/routers/types"
	"github.com/netbirdio/netbird/management/server/permissions/modules"
	"github.com/netbirdio/netbird/management/server/permissions/operations"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/management/server/util"
	"github.com/netbirdio/netbird/route"
	"github.com/netbirdio/netbird/shared/management/status"
)

type GroupLinkError struct {
	Resource string
	Name     string
}

func (e *GroupLinkError) Error() string {
	return fmt.Sprintf("group has been linked to %s: %s", e.Resource, e.Name)
}

// CheckGroupPermissions validates if a user has the necessary permissions to view groups
func (am *DefaultAccountManager) CheckGroupPermissions(ctx context.Context, accountID, userID string) error {
	allowed, _, err := am.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, modules.Groups, operations.Read)
	if err != nil {
		return err
	}

	if !allowed {
		return status.NewPermissionDeniedError()
	}

	return nil
}

// GetGroup returns a specific group by groupID in an account
func (am *DefaultAccountManager) GetGroup(ctx context.Context, accountID, groupID, userID string) (*types.Group, error) {
	if err := am.CheckGroupPermissions(ctx, accountID, userID); err != nil {
		return nil, err
	}
	return am.Store.GetGroupByID(ctx, store.LockingStrengthNone, accountID, groupID)
}

// GetAllGroups returns all groups in an account
func (am *DefaultAccountManager) GetAllGroups(ctx context.Context, accountID, userID string) ([]*types.Group, error) {
	if err := am.CheckGroupPermissions(ctx, accountID, userID); err != nil {
		return nil, err
	}
	return am.Store.GetAccountGroups(ctx, store.LockingStrengthNone, accountID)
}

// GetGroupByName filters all groups in an account by name and returns the one with the most peers
func (am *DefaultAccountManager) GetGroupByName(ctx context.Context, groupName, accountID, userID string) (*types.Group, error) {
	if err := am.CheckGroupPermissions(ctx, accountID, userID); err != nil {
		return nil, err
	}
	return am.Store.GetGroupByName(ctx, store.LockingStrengthNone, accountID, groupName)
}

// CreateGroup object of the peers
func (am *DefaultAccountManager) CreateGroup(ctx context.Context, accountID, userID string, newGroup *types.Group) error {
	allowed, ctx, err := am.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, modules.Groups, operations.Create)
	if err != nil {
		return status.NewPermissionValidationError(err)
	}
	if !allowed {
		return status.NewPermissionDeniedError()
	}

	var eventsToStore []func()
	var snap *affectedpeers.Snapshot
	change := affectedpeers.Change{ChangedGroupIDs: []string{newGroup.ID}}

	err = am.Store.ExecuteInTransaction(ctx, func(transaction store.Store) error {
		if err = validateNewGroup(ctx, transaction, accountID, newGroup); err != nil {
			return err
		}

		newGroup.AccountID = accountID

		events := am.prepareGroupEvents(ctx, transaction, accountID, userID, newGroup)
		eventsToStore = append(eventsToStore, events...)

		if err := transaction.CreateGroup(ctx, newGroup); err != nil {
			return status.Errorf(status.Internal, "failed to create group: %v", err)
		}

		for _, peerID := range newGroup.Peers {
			if err := transaction.AddPeerToGroup(ctx, accountID, peerID, newGroup.ID); err != nil {
				return status.Errorf(status.Internal, "failed to add peer %s to group %s: %v", peerID, newGroup.ID, err)
			}
		}

		snap, err = affectedpeers.Load(ctx, transaction, accountID, change)
		if err != nil {
			return err
		}

		return transaction.IncrementNetworkSerial(ctx, accountID)
	})
	if err != nil {
		return err
	}

	for _, storeEvent := range eventsToStore {
		storeEvent()
	}

	am.ExpandAndUpdateAffected(ctx, accountID, snap, change)

	return nil
}

// UpdateGroup object of the peers
func (am *DefaultAccountManager) UpdateGroup(ctx context.Context, accountID, userID string, newGroup *types.Group) error {
	allowed, ctx, err := am.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, modules.Groups, operations.Update)
	if err != nil {
		return status.NewPermissionValidationError(err)
	}
	if !allowed {
		return status.NewPermissionDeniedError()
	}

	var eventsToStore []func()
	var snap *affectedpeers.Snapshot
	change := affectedpeers.Change{ChangedGroupIDs: []string{newGroup.ID}}

	err = am.Store.ExecuteInTransaction(ctx, func(transaction store.Store) error {
		if err = validateNewGroup(ctx, transaction, accountID, newGroup); err != nil {
			return err
		}

		newGroup.AccountID = accountID

		events := am.prepareGroupEvents(ctx, transaction, accountID, userID, newGroup)
		eventsToStore = append(eventsToStore, events...)

		oldGroup, err := transaction.GetGroupByID(ctx, store.LockingStrengthNone, accountID, newGroup.ID)
		if err != nil {
			return status.Errorf(status.NotFound, "group with ID %s not found", newGroup.ID)
		}

		peersToAdd := util.Difference(newGroup.Peers, oldGroup.Peers)
		peersToRemove := util.Difference(oldGroup.Peers, newGroup.Peers)
		if err = syncGroupMembership(ctx, transaction, accountID, newGroup.ID, peersToAdd, peersToRemove); err != nil {
			return err
		}

		if err = transaction.UpdateGroup(ctx, newGroup); err != nil {
			return err
		}

		if err = am.reconcileIPv6ForGroupChanges(ctx, transaction, accountID, []string{newGroup.ID}); err != nil {
			return err
		}

		// A membership change does not alter which entities reference the group, so
		// the dependency walk runs once against the post-change snapshot. The new
		// members are already in the snapshot's index; the removed members are
		// carried separately and folded in only when the group is linked.
		if len(peersToRemove) > 0 {
			change.RemovedPeersByGroup = map[string][]string{newGroup.ID: peersToRemove}
		}
		if snap, err = affectedpeers.Load(ctx, transaction, accountID, change); err != nil {
			return err
		}

		return transaction.IncrementNetworkSerial(ctx, accountID)
	})
	if err != nil {
		return err
	}

	for _, storeEvent := range eventsToStore {
		storeEvent()
	}

	am.ExpandAndUpdateAffected(ctx, accountID, snap, change)

	return nil
}

// syncGroupMembership applies the peer membership delta for a group within a transaction.
func syncGroupMembership(ctx context.Context, transaction store.Store, accountID, groupID string, peersToAdd, peersToRemove []string) error {
	for _, peerID := range peersToAdd {
		if err := transaction.AddPeerToGroup(ctx, accountID, peerID, groupID); err != nil {
			return status.Errorf(status.Internal, "failed to add peer %s to group %s: %v", peerID, groupID, err)
		}
	}
	for _, peerID := range peersToRemove {
		if err := transaction.RemovePeerFromGroup(ctx, peerID, groupID); err != nil {
			return status.Errorf(status.Internal, "failed to remove peer %s from group %s: %v", peerID, groupID, err)
		}
	}
	return nil
}

// CreateGroups adds new groups to the account.
// Note: This function does not acquire the global lock.
// It is the caller's responsibility to ensure proper locking is in place before invoking this method.
// This method will not create group peer membership relations. Use AddPeerToGroup or RemovePeerFromGroup methods for that.
func (am *DefaultAccountManager) CreateGroups(ctx context.Context, accountID, userID string, groups []*types.Group) error {
	allowed, ctx, err := am.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, modules.Groups, operations.Create)
	if err != nil {
		return status.NewPermissionValidationError(err)
	}
	if !allowed {
		return status.NewPermissionDeniedError()
	}

	var eventsToStore []func()
	var snaps []*affectedpeers.Snapshot
	var changes []affectedpeers.Change

	var globalErr error
	createdCount := 0
	for _, newGroup := range groups {
		change := affectedpeers.Change{ChangedGroupIDs: []string{newGroup.ID}}
		var snap *affectedpeers.Snapshot
		err = am.Store.ExecuteInTransaction(ctx, func(transaction store.Store) error {
			if err = validateNewGroup(ctx, transaction, accountID, newGroup); err != nil {
				return err
			}

			newGroup.AccountID = accountID

			if err = transaction.CreateGroup(ctx, newGroup); err != nil {
				return err
			}

			err = transaction.IncrementNetworkSerial(ctx, accountID)
			if err != nil {
				return err
			}

			events := am.prepareGroupEvents(ctx, transaction, accountID, userID, newGroup)
			eventsToStore = append(eventsToStore, events...)

			snap, err = affectedpeers.Load(ctx, transaction, accountID, change)
			return err
		})
		if err != nil {
			log.WithContext(ctx).Errorf("failed to update group %s: %v", newGroup.ID, err)
			if createdCount == 0 {
				return err
			}
			globalErr = errors.Join(globalErr, err)
			// continue updating other groups
			continue
		}
		createdCount++
		snaps = append(snaps, snap)
		changes = append(changes, change)
	}

	for _, storeEvent := range eventsToStore {
		storeEvent()
	}

	go am.dispatchAffected(ctx, accountID, snaps, changes)

	return globalErr
}

// UpdateGroups updates groups in the account.
// Note: This function does not acquire the global lock.
// It is the caller's responsibility to ensure proper locking is in place before invoking this method.
// This method will not create group peer membership relations. Use AddPeerToGroup or RemovePeerFromGroup methods for that.
func (am *DefaultAccountManager) UpdateGroups(ctx context.Context, accountID, userID string, groups []*types.Group) error {
	allowed, ctx, err := am.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, modules.Groups, operations.Update)
	if err != nil {
		return status.NewPermissionValidationError(err)
	}
	if !allowed {
		return status.NewPermissionDeniedError()
	}

	var eventsToStore []func()
	var snaps []*affectedpeers.Snapshot
	var changes []affectedpeers.Change

	var globalErr error
	for _, newGroup := range groups {
		change := affectedpeers.Change{ChangedGroupIDs: []string{newGroup.ID}}
		events, snap, err := am.updateSingleGroup(ctx, accountID, userID, newGroup, change)
		if err != nil {
			log.WithContext(ctx).Errorf("failed to update group %s: %v", newGroup.ID, err)
			if len(groups) == 1 {
				return err
			}
			globalErr = errors.Join(globalErr, err)
			continue
		}
		eventsToStore = append(eventsToStore, events...)
		snaps = append(snaps, snap)
		changes = append(changes, change)
	}

	for _, storeEvent := range eventsToStore {
		storeEvent()
	}

	go am.dispatchAffected(ctx, accountID, snaps, changes)

	return globalErr
}

func (am *DefaultAccountManager) updateSingleGroup(ctx context.Context, accountID, userID string, newGroup *types.Group, change affectedpeers.Change) ([]func(), *affectedpeers.Snapshot, error) {
	var events []func()
	var snap *affectedpeers.Snapshot
	err := am.Store.ExecuteInTransaction(ctx, func(transaction store.Store) error {
		if err := validateNewGroup(ctx, transaction, accountID, newGroup); err != nil {
			return err
		}

		newGroup.AccountID = accountID

		if err := transaction.UpdateGroup(ctx, newGroup); err != nil {
			return err
		}

		if err := am.reconcileIPv6ForGroupChanges(ctx, transaction, accountID, []string{newGroup.ID}); err != nil {
			return err
		}

		if err := transaction.IncrementNetworkSerial(ctx, accountID); err != nil {
			return err
		}

		events = am.prepareGroupEvents(ctx, transaction, accountID, userID, newGroup)

		var err error
		snap, err = affectedpeers.Load(ctx, transaction, accountID, change)
		return err
	})
	return events, snap, err
}

// prepareGroupEvents prepares a list of event functions to be stored.
func (am *DefaultAccountManager) prepareGroupEvents(ctx context.Context, transaction store.Store, accountID, userID string, newGroup *types.Group) []func() {
	var eventsToStore []func()

	addedPeers := make([]string, 0)
	removedPeers := make([]string, 0)

	oldGroup, err := transaction.GetGroupByID(ctx, store.LockingStrengthNone, accountID, newGroup.ID)
	if err == nil && oldGroup != nil {
		addedPeers = util.Difference(newGroup.Peers, oldGroup.Peers)
		removedPeers = util.Difference(oldGroup.Peers, newGroup.Peers)

		if oldGroup.Name != newGroup.Name {
			eventsToStore = append(eventsToStore, func() {
				meta := map[string]any{
					"old_name": oldGroup.Name,
					"new_name": newGroup.Name,
				}
				am.StoreEvent(ctx, userID, newGroup.ID, accountID, activity.GroupUpdated, meta)
			})
		}
	} else {
		addedPeers = append(addedPeers, newGroup.Peers...)
		eventsToStore = append(eventsToStore, func() {
			am.StoreEvent(ctx, userID, newGroup.ID, accountID, activity.GroupCreated, newGroup.EventMeta())
		})
	}

	modifiedPeers := slices.Concat(addedPeers, removedPeers)
	peers, err := transaction.GetPeersByIDs(ctx, store.LockingStrengthNone, accountID, modifiedPeers)
	if err != nil {
		log.WithContext(ctx).Debugf("failed to get peers for group events: %v", err)
		return nil
	}

	settings, err := transaction.GetAccountSettings(ctx, store.LockingStrengthNone, accountID)
	if err != nil {
		log.WithContext(ctx).Debugf("failed to get account settings for group events: %v", err)
		return nil
	}
	dnsDomain := am.networkMapController.GetDNSDomain(settings)

	for _, peerID := range addedPeers {
		peer, ok := peers[peerID]
		if !ok {
			log.WithContext(ctx).Debugf("skipped adding peer: %s GroupAddedToPeer activity: peer not found in store", peerID)
			continue
		}

		eventsToStore = append(eventsToStore, func() {
			meta := map[string]any{
				"group": newGroup.Name, "group_id": newGroup.ID,
				"peer_ip": peer.IP.String(), "peer_fqdn": peer.FQDN(dnsDomain),
			}
			am.StoreEvent(ctx, userID, peer.ID, accountID, activity.GroupAddedToPeer, meta)
		})
	}

	for _, peerID := range removedPeers {
		peer, ok := peers[peerID]
		if !ok {
			log.WithContext(ctx).Debugf("skipped adding peer: %s GroupRemovedFromPeer activity: peer not found in store", peerID)
			continue
		}

		eventsToStore = append(eventsToStore, func() {
			meta := map[string]any{
				"group": newGroup.Name, "group_id": newGroup.ID,
				"peer_ip": peer.IP.String(), "peer_fqdn": peer.FQDN(dnsDomain),
			}
			am.StoreEvent(ctx, userID, peer.ID, accountID, activity.GroupRemovedFromPeer, meta)
		})
	}

	return eventsToStore
}

// DeleteGroup object of the peers.
func (am *DefaultAccountManager) DeleteGroup(ctx context.Context, accountID, userID, groupID string) error {
	return am.DeleteGroups(ctx, accountID, userID, []string{groupID})
}

// DeleteGroups deletes groups from an account.
// Note: This function does not acquire the global lock.
// It is the caller's responsibility to ensure proper locking is in place before invoking this method.
//
// If an error occurs while deleting a group, the function skips it and continues deleting other groups.
// Errors are collected and returned at the end.
func (am *DefaultAccountManager) DeleteGroups(ctx context.Context, accountID, userID string, groupIDs []string) error {
	allowed, ctx, err := am.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, modules.Groups, operations.Delete)
	if err != nil {
		return status.NewPermissionValidationError(err)
	}
	if !allowed {
		return status.NewPermissionDeniedError()
	}

	var allErrors error
	var groupIDsToDelete []string
	var deletedGroups []*types.Group
	var snap *affectedpeers.Snapshot
	var change affectedpeers.Change

	extraSettings, err := am.settingsManager.GetExtraSettings(ctx, accountID)
	if err != nil {
		return err
	}

	err = am.Store.ExecuteInTransaction(ctx, func(transaction store.Store) error {
		deletedGroups, allErrors = collectDeletableGroups(ctx, transaction, accountID, userID, groupIDs, extraSettings.FlowGroups)
		for _, group := range deletedGroups {
			groupIDsToDelete = append(groupIDsToDelete, group.ID)
		}

		if len(groupIDsToDelete) == 0 {
			return allErrors
		}

		// Delete: compute affected peers from the PRE-delete state. The groups,
		// their members and the entities referencing them still exist, so a plain
		// Load+Expand captures everyone — no removed-peer folding needed.
		change = affectedpeers.Change{ChangedGroupIDs: groupIDsToDelete}
		if snap, err = affectedpeers.Load(ctx, transaction, accountID, change); err != nil {
			return err
		}

		if err = transaction.DeleteGroups(ctx, accountID, groupIDsToDelete); err != nil {
			return err
		}

		if err = am.reconcileIPv6ForGroupChanges(ctx, transaction, accountID, groupIDsToDelete); err != nil {
			return err
		}

		return transaction.IncrementNetworkSerial(ctx, accountID)
	})
	if err != nil {
		return err
	}

	for _, group := range deletedGroups {
		am.StoreEvent(ctx, userID, group.ID, accountID, activity.GroupDeleted, group.EventMeta())
	}

	am.ExpandAndUpdateAffected(ctx, accountID, snap, change)

	return allErrors
}

// collectDeletableGroups loads and validates each group for deletion, returning
// the groups that may be deleted and the joined validation errors for the rest.
func collectDeletableGroups(ctx context.Context, transaction store.Store, accountID, userID string, groupIDs, flowGroups []string) ([]*types.Group, error) {
	var deletable []*types.Group
	var allErrors error
	for _, groupID := range groupIDs {
		group, err := transaction.GetGroupByID(ctx, store.LockingStrengthNone, accountID, groupID)
		if err != nil {
			allErrors = errors.Join(allErrors, err)
			continue
		}
		if err = validateDeleteGroup(ctx, transaction, group, userID, flowGroups); err != nil {
			allErrors = errors.Join(allErrors, err)
			continue
		}
		deletable = append(deletable, group)
	}
	return deletable, allErrors
}

// GroupAddPeer appends peer to the group
func (am *DefaultAccountManager) GroupAddPeer(ctx context.Context, accountID, groupID, peerID string) error {
	var snap *affectedpeers.Snapshot
	change := affectedpeers.Change{ChangedGroupIDs: []string{groupID}}

	err := am.Store.ExecuteInTransaction(ctx, func(transaction store.Store) error {
		if err := transaction.AddPeerToGroup(ctx, accountID, peerID, groupID); err != nil {
			return err
		}

		if err := am.reconcileIPv6ForGroupChanges(ctx, transaction, accountID, []string{groupID}); err != nil {
			return err
		}

		var err error
		if snap, err = affectedpeers.Load(ctx, transaction, accountID, change); err != nil {
			return err
		}

		return transaction.IncrementNetworkSerial(ctx, accountID)
	})
	if err != nil {
		return err
	}

	am.ExpandAndUpdateAffected(ctx, accountID, snap, change)

	return nil
}

// GroupAddResource appends resource to the group
func (am *DefaultAccountManager) GroupAddResource(ctx context.Context, accountID, groupID string, resource types.Resource) error {
	var group *types.Group
	var snap *affectedpeers.Snapshot
	var err error
	change := affectedpeers.Change{ChangedGroupIDs: []string{groupID}}

	err = am.Store.ExecuteInTransaction(ctx, func(transaction store.Store) error {
		group, err = transaction.GetGroupByID(context.Background(), store.LockingStrengthUpdate, accountID, groupID)
		if err != nil {
			return err
		}

		if updated := group.AddResource(resource); !updated {
			return nil
		}

		if err = transaction.UpdateGroup(ctx, group); err != nil {
			return err
		}

		if snap, err = affectedpeers.Load(ctx, transaction, accountID, change); err != nil {
			return err
		}

		return transaction.IncrementNetworkSerial(ctx, accountID)
	})
	if err != nil {
		return err
	}

	am.ExpandAndUpdateAffected(ctx, accountID, snap, change)

	return nil
}

// GroupDeletePeer removes peer from the group
func (am *DefaultAccountManager) GroupDeletePeer(ctx context.Context, accountID, groupID, peerID string) error {
	var snap *affectedpeers.Snapshot
	change := affectedpeers.Change{
		ChangedGroupIDs:     []string{groupID},
		RemovedPeersByGroup: map[string][]string{groupID: {peerID}},
	}

	err := am.Store.ExecuteInTransaction(ctx, func(transaction store.Store) error {
		if err := transaction.RemovePeerFromGroup(ctx, peerID, groupID); err != nil {
			return err
		}

		if err := am.reconcileIPv6ForGroupChanges(ctx, transaction, accountID, []string{groupID}); err != nil {
			return err
		}

		// The removed peer is carried in change.RemovedPeersByGroup and folded in
		// only when the group is linked, so loading post-removal is correct.
		var err error
		if snap, err = affectedpeers.Load(ctx, transaction, accountID, change); err != nil {
			return err
		}

		return transaction.IncrementNetworkSerial(ctx, accountID)
	})
	if err != nil {
		return err
	}

	am.ExpandAndUpdateAffected(ctx, accountID, snap, change)

	return nil
}

// GroupDeleteResource removes resource from the group
func (am *DefaultAccountManager) GroupDeleteResource(ctx context.Context, accountID, groupID string, resource types.Resource) error {
	var group *types.Group
	var snap *affectedpeers.Snapshot
	var err error
	change := affectedpeers.Change{ChangedGroupIDs: []string{groupID}}

	err = am.Store.ExecuteInTransaction(ctx, func(transaction store.Store) error {
		group, err = transaction.GetGroupByID(context.Background(), store.LockingStrengthUpdate, accountID, groupID)
		if err != nil {
			return err
		}

		if updated := group.RemoveResource(resource); !updated {
			return nil
		}

		// Load before persisting the removal, so the snapshot still maps the group
		// to the resource and the bridge can reach its routing peers.
		if snap, err = affectedpeers.Load(ctx, transaction, accountID, change); err != nil {
			return err
		}

		if err = transaction.UpdateGroup(ctx, group); err != nil {
			return err
		}

		return transaction.IncrementNetworkSerial(ctx, accountID)
	})
	if err != nil {
		return err
	}

	am.ExpandAndUpdateAffected(ctx, accountID, snap, change)

	return nil
}

// validateNewGroup validates the new group for existence and required fields.
func validateNewGroup(ctx context.Context, transaction store.Store, accountID string, newGroup *types.Group) error {
	if newGroup.ID == "" && newGroup.Issued != types.GroupIssuedAPI {
		return status.Errorf(status.InvalidArgument, "%s group without ID set", newGroup.Issued)
	}

	if newGroup.ID == "" && newGroup.Issued == types.GroupIssuedAPI {
		existingGroup, err := transaction.GetGroupByName(ctx, store.LockingStrengthNone, accountID, newGroup.Name)
		if err != nil {
			if s, ok := status.FromError(err); !ok || s.Type() != status.NotFound {
				return err
			}
		}

		// Prevent duplicate groups for API-issued groups.
		// Integration or JWT groups can be duplicated as they are coming from the IdP that we don't have control of.
		if existingGroup != nil {
			return status.Errorf(status.AlreadyExists, "group with name %s already exists", newGroup.Name)
		}

		newGroup.ID = xid.New().String()
	}

	return nil
}

func validateDeleteGroup(ctx context.Context, transaction store.Store, group *types.Group, userID string, flowGroups []string) error {
	// disable a deleting integration group if the initiator is not an admin service user
	if group.Issued == types.GroupIssuedIntegration {
		executingUser, err := transaction.GetUserByUserID(ctx, store.LockingStrengthNone, userID)
		if err != nil {
			return status.Errorf(status.Internal, "failed to get user")
		}
		if executingUser.Role != types.UserRoleAdmin || !executingUser.IsServiceUser {
			return status.Errorf(status.PermissionDenied, "only service users with admin power can delete integration group")
		}
	}

	if group.IsGroupAll() {
		return status.Errorf(status.InvalidArgument, "deleting group ALL is not allowed")
	}

	if len(group.Resources) > 0 {
		return &GroupLinkError{"network resource", group.Resources[0].ID}
	}

	if slices.Contains(flowGroups, group.ID) {
		return &GroupLinkError{"settings", "traffic event logging"}
	}

	if isLinked, linkedRoute := isGroupLinkedToRoute(ctx, transaction, group.AccountID, group.ID); isLinked {
		return &GroupLinkError{"route", string(linkedRoute.NetID)}
	}

	if isLinked, linkedDns := isGroupLinkedToDns(ctx, transaction, group.AccountID, group.ID); isLinked {
		return &GroupLinkError{"name server groups", linkedDns.Name}
	}

	if isLinked, linkedPolicy := isGroupLinkedToPolicy(ctx, transaction, group.AccountID, group.ID); isLinked {
		return &GroupLinkError{"policy", linkedPolicy.Name}
	}

	if isLinked, linkedSetupKey := isGroupLinkedToSetupKey(ctx, transaction, group.AccountID, group.ID); isLinked {
		return &GroupLinkError{"setup key", linkedSetupKey.Name}
	}

	if isLinked, linkedUser := isGroupLinkedToUser(ctx, transaction, group.AccountID, group.ID); isLinked {
		return &GroupLinkError{"user", linkedUser.Id}
	}

	if isLinked, linkedRouter := isGroupLinkedToNetworkRouter(ctx, transaction, group.AccountID, group.ID); isLinked {
		return &GroupLinkError{"network router", linkedRouter.ID}
	}

	return checkGroupLinkedToSettings(ctx, transaction, group)
}

// checkGroupLinkedToSettings verifies if a group is linked to any settings in the account.
func checkGroupLinkedToSettings(ctx context.Context, transaction store.Store, group *types.Group) error {
	dnsSettings, err := transaction.GetAccountDNSSettings(ctx, store.LockingStrengthNone, group.AccountID)
	if err != nil {
		return status.Errorf(status.Internal, "failed to get DNS settings")
	}

	if slices.Contains(dnsSettings.DisabledManagementGroups, group.ID) {
		return &GroupLinkError{"disabled DNS management groups", group.Name}
	}

	settings, err := transaction.GetAccountSettings(ctx, store.LockingStrengthNone, group.AccountID)
	if err != nil {
		return status.Errorf(status.Internal, "failed to get account settings")
	}

	if settings.Extra != nil && slices.Contains(settings.Extra.IntegratedValidatorGroups, group.ID) {
		return &GroupLinkError{"integrated validator", group.Name}
	}

	return nil
}

// isGroupLinkedToRoute checks if a group is linked to any route in the account.
func isGroupLinkedToRoute(ctx context.Context, transaction store.Store, accountID string, groupID string) (bool, *route.Route) {
	routes, err := transaction.GetAccountRoutes(ctx, store.LockingStrengthNone, accountID)
	if err != nil {
		log.WithContext(ctx).Errorf("error retrieving routes while checking group linkage: %v", err)
		return false, nil
	}

	for _, r := range routes {
		isLinked := slices.Contains(r.Groups, groupID) ||
			slices.Contains(r.PeerGroups, groupID) ||
			slices.Contains(r.AccessControlGroups, groupID)
		if isLinked {
			return true, r
		}
	}

	return false, nil
}

// isGroupLinkedToPolicy checks if a group is linked to any policy in the account.
func isGroupLinkedToPolicy(ctx context.Context, transaction store.Store, accountID string, groupID string) (bool, *types.Policy) {
	policies, err := transaction.GetAccountPolicies(ctx, store.LockingStrengthNone, accountID)
	if err != nil {
		log.WithContext(ctx).Errorf("error retrieving policies while checking group linkage: %v", err)
		return false, nil
	}

	for _, policy := range policies {
		for _, rule := range policy.Rules {
			if slices.Contains(rule.Sources, groupID) || slices.Contains(rule.Destinations, groupID) {
				return true, policy
			}
		}
	}
	return false, nil
}

// isGroupLinkedToDns checks if a group is linked to any nameserver group in the account.
func isGroupLinkedToDns(ctx context.Context, transaction store.Store, accountID string, groupID string) (bool, *nbdns.NameServerGroup) {
	nameServerGroups, err := transaction.GetAccountNameServerGroups(ctx, store.LockingStrengthNone, accountID)
	if err != nil {
		log.WithContext(ctx).Errorf("error retrieving name server groups while checking group linkage: %v", err)
		return false, nil
	}

	for _, dns := range nameServerGroups {
		for _, g := range dns.Groups {
			if g == groupID {
				return true, dns
			}
		}
	}

	return false, nil
}

// isGroupLinkedToSetupKey checks if a group is linked to any setup key in the account.
func isGroupLinkedToSetupKey(ctx context.Context, transaction store.Store, accountID string, groupID string) (bool, *types.SetupKey) {
	setupKeys, err := transaction.GetAccountSetupKeys(ctx, store.LockingStrengthNone, accountID)
	if err != nil {
		log.WithContext(ctx).Errorf("error retrieving setup keys while checking group linkage: %v", err)
		return false, nil
	}

	for _, setupKey := range setupKeys {
		if slices.Contains(setupKey.AutoGroups, groupID) {
			return true, setupKey
		}
	}
	return false, nil
}

// isGroupLinkedToUser checks if a group is linked to any user in the account.
func isGroupLinkedToUser(ctx context.Context, transaction store.Store, accountID string, groupID string) (bool, *types.User) {
	users, err := transaction.GetAccountUsers(ctx, store.LockingStrengthNone, accountID)
	if err != nil {
		log.WithContext(ctx).Errorf("error retrieving users while checking group linkage: %v", err)
		return false, nil
	}

	for _, user := range users {
		if slices.Contains(user.AutoGroups, groupID) {
			return true, user
		}
	}
	return false, nil
}

// isGroupLinkedToNetworkRouter checks if a group is linked to any network router in the account.
func isGroupLinkedToNetworkRouter(ctx context.Context, transaction store.Store, accountID string, groupID string) (bool, *routerTypes.NetworkRouter) {
	routers, err := transaction.GetNetworkRoutersByAccountID(ctx, store.LockingStrengthNone, accountID)
	if err != nil {
		log.WithContext(ctx).Errorf("error retrieving network routers while checking group linkage: %v", err)
		return false, nil
	}

	for _, router := range routers {
		if slices.Contains(router.PeerGroups, groupID) {
			return true, router
		}
	}
	return false, nil
}

// areGroupChangesAffectPeers checks if any changes to the specified groups will affect peers.
// It fetches each collection once and checks all groupIDs against them in memory.
func areGroupChangesAffectPeers(ctx context.Context, transaction store.Store, accountID string, groupIDs []string) (bool, error) {
	if len(groupIDs) == 0 {
		return false, nil
	}

	groupSet := make(map[string]struct{}, len(groupIDs))
	for _, id := range groupIDs {
		groupSet[id] = struct{}{}
	}

	if affected, err := dnsSettingsReferenceGroups(ctx, transaction, accountID, groupSet); affected || err != nil {
		return affected, err
	}
	if affected, err := nameServersReferenceGroups(ctx, transaction, accountID, groupSet); affected || err != nil {
		return affected, err
	}
	if affected, err := policiesReferenceGroups(ctx, transaction, accountID, groupSet); affected || err != nil {
		return affected, err
	}
	if affected, err := routesReferenceGroups(ctx, transaction, accountID, groupSet); affected || err != nil {
		return affected, err
	}
	if affected, err := networkRoutersReferenceGroups(ctx, transaction, accountID, groupSet); affected || err != nil {
		return affected, err
	}

	return false, nil
}

func dnsSettingsReferenceGroups(ctx context.Context, transaction store.Store, accountID string, groupSet map[string]struct{}) (bool, error) {
	dnsSettings, err := transaction.GetAccountDNSSettings(ctx, store.LockingStrengthNone, accountID)
	if err != nil {
		return false, err
	}
	return anyInSet(dnsSettings.DisabledManagementGroups, groupSet), nil
}

func nameServersReferenceGroups(ctx context.Context, transaction store.Store, accountID string, groupSet map[string]struct{}) (bool, error) {
	nameServerGroups, err := transaction.GetAccountNameServerGroups(ctx, store.LockingStrengthNone, accountID)
	if err != nil {
		return false, err
	}
	for _, ns := range nameServerGroups {
		if anyInSet(ns.Groups, groupSet) {
			return true, nil
		}
	}
	return false, nil
}

func policiesReferenceGroups(ctx context.Context, transaction store.Store, accountID string, groupSet map[string]struct{}) (bool, error) {
	policies, err := transaction.GetAccountPolicies(ctx, store.LockingStrengthNone, accountID)
	if err != nil {
		return false, err
	}
	for _, policy := range policies {
		for _, rule := range policy.Rules {
			if anyInSet(rule.Sources, groupSet) || anyInSet(rule.Destinations, groupSet) {
				return true, nil
			}
		}
	}
	return false, nil
}

func routesReferenceGroups(ctx context.Context, transaction store.Store, accountID string, groupSet map[string]struct{}) (bool, error) {
	routes, err := transaction.GetAccountRoutes(ctx, store.LockingStrengthNone, accountID)
	if err != nil {
		return false, err
	}
	for _, r := range routes {
		if anyInSet(r.Groups, groupSet) || anyInSet(r.PeerGroups, groupSet) || anyInSet(r.AccessControlGroups, groupSet) {
			return true, nil
		}
	}
	return false, nil
}

func networkRoutersReferenceGroups(ctx context.Context, transaction store.Store, accountID string, groupSet map[string]struct{}) (bool, error) {
	routers, err := transaction.GetNetworkRoutersByAccountID(ctx, store.LockingStrengthNone, accountID)
	if err != nil {
		return false, err
	}
	for _, router := range routers {
		if anyInSet(router.PeerGroups, groupSet) {
			return true, nil
		}
	}
	return false, nil
}

func anyInSet(ids []string, set map[string]struct{}) bool {
	for _, id := range ids {
		if _, ok := set[id]; ok {
			return true
		}
	}
	return false
}
