package server

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/rs/xid"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/management/server/activity"
	"github.com/netbirdio/netbird/management/server/permissions/modules"
	"github.com/netbirdio/netbird/management/server/permissions/operations"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/management/server/util"
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
	var affectedPeerIDs []string

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

		groupIDs, directPeerIDs := collectGroupChangeAffectedGroups(ctx, transaction, accountID, []string{newGroup.ID})
		affectedPeerIDs = am.resolvePeerIDs(ctx, transaction, accountID, groupIDs, directPeerIDs)

		return transaction.IncrementNetworkSerial(ctx, accountID)
	})
	if err != nil {
		return err
	}

	for _, storeEvent := range eventsToStore {
		storeEvent()
	}

	if len(affectedPeerIDs) > 0 {
		log.WithContext(ctx).Debugf("CreateGroup %s: updating %d affected peers: %v", newGroup.ID, len(affectedPeerIDs), affectedPeerIDs)
		am.UpdateAffectedPeers(ctx, accountID, affectedPeerIDs)
	} else {
		log.WithContext(ctx).Tracef("CreateGroup %s: no affected peers", newGroup.ID)
	}

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
	var affectedPeerIDs []string

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

		for _, peerID := range peersToAdd {
			if err := transaction.AddPeerToGroup(ctx, accountID, peerID, newGroup.ID); err != nil {
				return status.Errorf(status.Internal, "failed to add peer %s to group %s: %v", peerID, newGroup.ID, err)
			}
		}
		for _, peerID := range peersToRemove {
			if err := transaction.RemovePeerFromGroup(ctx, peerID, newGroup.ID); err != nil {
				return status.Errorf(status.Internal, "failed to remove peer %s from group %s: %v", peerID, newGroup.ID, err)
			}
		}

		if err = transaction.UpdateGroup(ctx, newGroup); err != nil {
			return err
		}

		if err = am.reconcileIPv6ForGroupChanges(ctx, transaction, accountID, []string{newGroup.ID}); err != nil {
			return err
		}

		groupIDs, directPeerIDs := collectGroupChangeAffectedGroups(ctx, transaction, accountID, []string{newGroup.ID})
		affectedPeerIDs = am.resolvePeerIDs(ctx, transaction, accountID, groupIDs, append(directPeerIDs, peersToRemove...))

		return transaction.IncrementNetworkSerial(ctx, accountID)
	})
	if err != nil {
		return err
	}

	for _, storeEvent := range eventsToStore {
		storeEvent()
	}

	if len(affectedPeerIDs) > 0 {
		log.WithContext(ctx).Debugf("UpdateGroup %s: updating %d affected peers: %v", newGroup.ID, len(affectedPeerIDs), affectedPeerIDs)
		am.UpdateAffectedPeers(ctx, accountID, affectedPeerIDs)
	} else {
		log.WithContext(ctx).Tracef("UpdateGroup %s: no affected peers", newGroup.ID)
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

	var globalErr error
	groupIDs := make([]string, 0, len(groups))
	for _, newGroup := range groups {
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

			groupIDs = append(groupIDs, newGroup.ID)

			events := am.prepareGroupEvents(ctx, transaction, accountID, userID, newGroup)
			eventsToStore = append(eventsToStore, events...)

			return nil
		})
		if err != nil {
			log.WithContext(ctx).Errorf("failed to update group %s: %v", newGroup.ID, err)
			if len(groupIDs) == 1 {
				return err
			}
			globalErr = errors.Join(globalErr, err)
			// continue updating other groups
		}
	}

	for _, storeEvent := range eventsToStore {
		storeEvent()
	}

	allGroupIDs, directPeerIDs := collectGroupChangeAffectedGroups(ctx, am.Store, accountID, groupIDs)
	affectedPeerIDs := am.resolvePeerIDs(ctx, am.Store, accountID, allGroupIDs, directPeerIDs)
	if len(affectedPeerIDs) > 0 {
		log.WithContext(ctx).Debugf("CreateGroups %v: updating %d affected peers: %v", groupIDs, len(affectedPeerIDs), affectedPeerIDs)
		am.UpdateAffectedPeers(ctx, accountID, affectedPeerIDs)
	} else {
		log.WithContext(ctx).Tracef("CreateGroups %v: no affected peers", groupIDs)
	}

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

	var globalErr error
	groupIDs := make([]string, 0, len(groups))
	for _, newGroup := range groups {
		events, err := am.updateSingleGroup(ctx, accountID, userID, newGroup)
		if err != nil {
			log.WithContext(ctx).Errorf("failed to update group %s: %v", newGroup.ID, err)
			if len(groups) == 1 {
				return err
			}
			globalErr = errors.Join(globalErr, err)
			continue
		}
		eventsToStore = append(eventsToStore, events...)
		groupIDs = append(groupIDs, newGroup.ID)
	}

	for _, storeEvent := range eventsToStore {
		storeEvent()
	}

	allGroupIDs, directPeerIDs := collectGroupChangeAffectedGroups(ctx, am.Store, accountID, groupIDs)
	affectedPeerIDs := am.resolvePeerIDs(ctx, am.Store, accountID, allGroupIDs, directPeerIDs)
	if len(affectedPeerIDs) > 0 {
		log.WithContext(ctx).Debugf("UpdateGroups %v: updating %d affected peers: %v", groupIDs, len(affectedPeerIDs), affectedPeerIDs)
		am.UpdateAffectedPeers(ctx, accountID, affectedPeerIDs)
	} else {
		log.WithContext(ctx).Tracef("UpdateGroups %v: no affected peers", groupIDs)
	}

	return globalErr
}

func (am *DefaultAccountManager) updateSingleGroup(ctx context.Context, accountID, userID string, newGroup *types.Group) ([]func(), error) {
	var events []func()
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
		return nil
	})
	return events, err
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

	extraSettings, err := am.settingsManager.GetExtraSettings(ctx, accountID)
	if err != nil {
		return err
	}

	err = am.Store.ExecuteInTransaction(ctx, func(transaction store.Store) error {
		for _, groupID := range groupIDs {
			group, err := transaction.GetGroupByID(ctx, store.LockingStrengthNone, accountID, groupID)
			if err != nil {
				allErrors = errors.Join(allErrors, err)
				continue
			}

			if err = validateDeleteGroup(ctx, transaction, group, userID, extraSettings.FlowGroups); err != nil {
				allErrors = errors.Join(allErrors, err)
				continue
			}

			groupIDsToDelete = append(groupIDsToDelete, groupID)
			deletedGroups = append(deletedGroups, group)
		}

		if len(groupIDsToDelete) == 0 {
			return allErrors
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

	return allErrors
}

// GroupAddPeer appends peer to the group
func (am *DefaultAccountManager) GroupAddPeer(ctx context.Context, accountID, groupID, peerID string) error {
	var affectedPeerIDs []string
	var err error

	err = am.Store.ExecuteInTransaction(ctx, func(transaction store.Store) error {
		if err = transaction.AddPeerToGroup(ctx, accountID, peerID, groupID); err != nil {
			return err
		}

		if err = am.reconcileIPv6ForGroupChanges(ctx, transaction, accountID, []string{groupID}); err != nil {
			return err
		}

		allGroupIDs, directPeerIDs := collectGroupChangeAffectedGroups(ctx, transaction, accountID, []string{groupID})
		affectedPeerIDs = am.resolvePeerIDs(ctx, transaction, accountID, allGroupIDs, directPeerIDs)

		return transaction.IncrementNetworkSerial(ctx, accountID)
	})
	if err != nil {
		return err
	}

	if len(affectedPeerIDs) > 0 {
		log.WithContext(ctx).Debugf("GroupAddPeer group=%s peer=%s: updating %d affected peers: %v", groupID, peerID, len(affectedPeerIDs), affectedPeerIDs)
		am.UpdateAffectedPeers(ctx, accountID, affectedPeerIDs)
	} else {
		log.WithContext(ctx).Tracef("GroupAddPeer group=%s peer=%s: no affected peers", groupID, peerID)
	}

	return nil
}

// GroupAddResource appends resource to the group
func (am *DefaultAccountManager) GroupAddResource(ctx context.Context, accountID, groupID string, resource types.Resource) error {
	var group *types.Group
	var affectedPeerIDs []string
	var err error

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

		allGroupIDs, directPeerIDs := collectGroupChangeAffectedGroups(ctx, transaction, accountID, []string{groupID})
		affectedPeerIDs = am.resolvePeerIDs(ctx, transaction, accountID, allGroupIDs, directPeerIDs)

		return transaction.IncrementNetworkSerial(ctx, accountID)
	})
	if err != nil {
		return err
	}

	if len(affectedPeerIDs) > 0 {
		log.WithContext(ctx).Debugf("GroupAddResource group=%s resource=%s: updating %d affected peers: %v", groupID, resource.ID, len(affectedPeerIDs), affectedPeerIDs)
		am.UpdateAffectedPeers(ctx, accountID, affectedPeerIDs)
	} else {
		log.WithContext(ctx).Tracef("GroupAddResource group=%s resource=%s: no affected peers", groupID, resource.ID)
	}

	return nil
}

// GroupDeletePeer removes peer from the group
func (am *DefaultAccountManager) GroupDeletePeer(ctx context.Context, accountID, groupID, peerID string) error {
	var affectedPeerIDs []string
	var err error

	err = am.Store.ExecuteInTransaction(ctx, func(transaction store.Store) error {
		// Resolve before removing, so the peer being removed is still included
		allGroupIDs, directPeerIDs := collectGroupChangeAffectedGroups(ctx, transaction, accountID, []string{groupID})
		affectedPeerIDs = am.resolvePeerIDs(ctx, transaction, accountID, allGroupIDs, directPeerIDs)

		if err = transaction.RemovePeerFromGroup(ctx, peerID, groupID); err != nil {
			return err
		}

		if err = am.reconcileIPv6ForGroupChanges(ctx, transaction, accountID, []string{groupID}); err != nil {
			return err
		}

		return transaction.IncrementNetworkSerial(ctx, accountID)
	})
	if err != nil {
		return err
	}

	if len(affectedPeerIDs) > 0 {
		log.WithContext(ctx).Debugf("GroupDeletePeer group=%s peer=%s: updating %d affected peers: %v", groupID, peerID, len(affectedPeerIDs), affectedPeerIDs)
		am.UpdateAffectedPeers(ctx, accountID, affectedPeerIDs)
	} else {
		log.WithContext(ctx).Tracef("GroupDeletePeer group=%s peer=%s: no affected peers", groupID, peerID)
	}

	return nil
}

// GroupDeleteResource removes resource from the group
func (am *DefaultAccountManager) GroupDeleteResource(ctx context.Context, accountID, groupID string, resource types.Resource) error {
	var group *types.Group
	var affectedPeerIDs []string
	var err error

	err = am.Store.ExecuteInTransaction(ctx, func(transaction store.Store) error {
		group, err = transaction.GetGroupByID(context.Background(), store.LockingStrengthUpdate, accountID, groupID)
		if err != nil {
			return err
		}

		if updated := group.RemoveResource(resource); !updated {
			return nil
		}

		if err = transaction.UpdateGroup(ctx, group); err != nil {
			return err
		}

		allGroupIDs, directPeerIDs := collectGroupChangeAffectedGroups(ctx, transaction, accountID, []string{groupID})
		affectedPeerIDs = am.resolvePeerIDs(ctx, transaction, accountID, allGroupIDs, directPeerIDs)

		return transaction.IncrementNetworkSerial(ctx, accountID)
	})
	if err != nil {
		return err
	}

	if len(affectedPeerIDs) > 0 {
		log.WithContext(ctx).Debugf("GroupDeleteResource group=%s resource=%s: updating %d affected peers: %v", groupID, resource.ID, len(affectedPeerIDs), affectedPeerIDs)
		am.UpdateAffectedPeers(ctx, accountID, affectedPeerIDs)
	} else {
		log.WithContext(ctx).Tracef("GroupDeleteResource group=%s resource=%s: no affected peers", groupID, resource.ID)
	}

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
