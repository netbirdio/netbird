package server

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/rs/xid"
	log "github.com/sirupsen/logrus"

	nbdns "github.com/netbirdio/netbird/dns"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/management/server/util"
	"github.com/netbirdio/netbird/route"

	"github.com/netbirdio/netbird/management/server/activity"
	"github.com/netbirdio/netbird/management/server/status"
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
	user, err := am.Store.GetUserByUserID(ctx, store.LockingStrengthShare, userID)
	if err != nil {
		return err
	}

	if user.AccountID != accountID {
		return status.NewUserNotPartOfAccountError()
	}

	if user.IsRegularUser() {
		return status.NewAdminPermissionError()
	}

	return nil
}

// GetGroup returns a specific group by groupID in an account
func (am *DefaultAccountManager) GetGroup(ctx context.Context, accountID, groupID, userID string) (*types.Group, error) {
	if err := am.CheckGroupPermissions(ctx, accountID, userID); err != nil {
		return nil, err
	}
	return am.Store.GetGroupByID(ctx, store.LockingStrengthShare, accountID, groupID)
}

// GetAllGroups returns all groups in an account
func (am *DefaultAccountManager) GetAllGroups(ctx context.Context, accountID, userID string) ([]*types.Group, error) {
	if err := am.CheckGroupPermissions(ctx, accountID, userID); err != nil {
		return nil, err
	}
	return am.Store.GetAccountGroups(ctx, store.LockingStrengthShare, accountID)
}

// GetGroupByName filters all groups in an account by name and returns the one with the most peers
func (am *DefaultAccountManager) GetGroupByName(ctx context.Context, groupName, accountID string) (*types.Group, error) {
	return am.Store.GetGroupByName(ctx, store.LockingStrengthShare, accountID, groupName)
}

// SaveGroup object of the peers
func (am *DefaultAccountManager) SaveGroup(ctx context.Context, accountID, userID string, newGroup *types.Group) error {
	unlock := am.Store.AcquireWriteLockByUID(ctx, accountID)
	defer unlock()
	return am.SaveGroups(ctx, accountID, userID, []*types.Group{newGroup})
}

// SaveGroups adds new groups to the account.
// Note: This function does not acquire the global lock.
// It is the caller's responsibility to ensure proper locking is in place before invoking this method.
func (am *DefaultAccountManager) SaveGroups(ctx context.Context, accountID, userID string, groups []*types.Group) error {
	user, err := am.Store.GetUserByUserID(ctx, store.LockingStrengthShare, userID)
	if err != nil {
		return err
	}

	if user.AccountID != accountID {
		return status.NewUserNotPartOfAccountError()
	}

	if user.IsRegularUser() {
		return status.NewAdminPermissionError()
	}

	var eventsToStore []func()
	var groupsToSave []*types.Group
	var updateAccountPeers bool

	err = am.Store.ExecuteInTransaction(ctx, func(transaction store.Store) error {
		groupIDs := make([]string, 0, len(groups))
		for _, newGroup := range groups {
			if err = validateNewGroup(ctx, transaction, accountID, newGroup); err != nil {
				return err
			}

			newGroup.AccountID = accountID
			groupsToSave = append(groupsToSave, newGroup)
			groupIDs = append(groupIDs, newGroup.ID)

			events := am.prepareGroupEvents(ctx, transaction, accountID, userID, newGroup)
			eventsToStore = append(eventsToStore, events...)
		}

		updateAccountPeers, err = areGroupChangesAffectPeers(ctx, transaction, accountID, groupIDs)
		if err != nil {
			return err
		}

		if err = transaction.IncrementNetworkSerial(ctx, store.LockingStrengthUpdate, accountID); err != nil {
			return err
		}

		return transaction.SaveGroups(ctx, store.LockingStrengthUpdate, groupsToSave)
	})
	if err != nil {
		return err
	}

	for _, storeEvent := range eventsToStore {
		storeEvent()
	}

	if updateAccountPeers {
		am.UpdateAccountPeers(ctx, accountID)
	}

	return nil
}

// prepareGroupEvents prepares a list of event functions to be stored.
func (am *DefaultAccountManager) prepareGroupEvents(ctx context.Context, transaction store.Store, accountID, userID string, newGroup *types.Group) []func() {
	var eventsToStore []func()

	addedPeers := make([]string, 0)
	removedPeers := make([]string, 0)

	oldGroup, err := transaction.GetGroupByID(ctx, store.LockingStrengthShare, accountID, newGroup.ID)
	if err == nil && oldGroup != nil {
		addedPeers = util.Difference(newGroup.Peers, oldGroup.Peers)
		removedPeers = util.Difference(oldGroup.Peers, newGroup.Peers)
	} else {
		addedPeers = append(addedPeers, newGroup.Peers...)
		eventsToStore = append(eventsToStore, func() {
			am.StoreEvent(ctx, userID, newGroup.ID, accountID, activity.GroupCreated, newGroup.EventMeta())
		})
	}

	modifiedPeers := slices.Concat(addedPeers, removedPeers)
	peers, err := transaction.GetPeersByIDs(ctx, store.LockingStrengthShare, accountID, modifiedPeers)
	if err != nil {
		log.WithContext(ctx).Debugf("failed to get peers for group events: %v", err)
		return nil
	}

	for _, peerID := range addedPeers {
		peer, ok := peers[peerID]
		if !ok {
			log.WithContext(ctx).Debugf("skipped adding peer: %s GroupAddedToPeer activity: peer not found in store", peerID)
			continue
		}

		eventsToStore = append(eventsToStore, func() {
			meta := map[string]any{
				"group": newGroup.Name, "group_id": newGroup.ID,
				"peer_ip": peer.IP.String(), "peer_fqdn": peer.FQDN(am.GetDNSDomain()),
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
				"peer_ip": peer.IP.String(), "peer_fqdn": peer.FQDN(am.GetDNSDomain()),
			}
			am.StoreEvent(ctx, userID, peer.ID, accountID, activity.GroupRemovedFromPeer, meta)
		})
	}

	return eventsToStore
}

// DeleteGroup object of the peers.
func (am *DefaultAccountManager) DeleteGroup(ctx context.Context, accountID, userID, groupID string) error {
	unlock := am.Store.AcquireWriteLockByUID(ctx, accountID)
	defer unlock()
	return am.DeleteGroups(ctx, accountID, userID, []string{groupID})
}

// DeleteGroups deletes groups from an account.
// Note: This function does not acquire the global lock.
// It is the caller's responsibility to ensure proper locking is in place before invoking this method.
//
// If an error occurs while deleting a group, the function skips it and continues deleting other groups.
// Errors are collected and returned at the end.
func (am *DefaultAccountManager) DeleteGroups(ctx context.Context, accountID, userID string, groupIDs []string) error {
	user, err := am.Store.GetUserByUserID(ctx, store.LockingStrengthShare, userID)
	if err != nil {
		return err
	}

	if user.AccountID != accountID {
		return status.NewUserNotPartOfAccountError()
	}

	if user.IsRegularUser() {
		return status.NewAdminPermissionError()
	}

	var allErrors error
	var groupIDsToDelete []string
	var deletedGroups []*types.Group

	err = am.Store.ExecuteInTransaction(ctx, func(transaction store.Store) error {
		for _, groupID := range groupIDs {
			group, err := transaction.GetGroupByID(ctx, store.LockingStrengthUpdate, accountID, groupID)
			if err != nil {
				allErrors = errors.Join(allErrors, err)
				continue
			}

			if err := validateDeleteGroup(ctx, transaction, group, userID); err != nil {
				allErrors = errors.Join(allErrors, err)
				continue
			}

			groupIDsToDelete = append(groupIDsToDelete, groupID)
			deletedGroups = append(deletedGroups, group)
		}

		if err = transaction.IncrementNetworkSerial(ctx, store.LockingStrengthUpdate, accountID); err != nil {
			return err
		}

		return transaction.DeleteGroups(ctx, store.LockingStrengthUpdate, accountID, groupIDsToDelete)
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
	unlock := am.Store.AcquireWriteLockByUID(ctx, accountID)
	defer unlock()

	var group *types.Group
	var updateAccountPeers bool
	var err error

	err = am.Store.ExecuteInTransaction(ctx, func(transaction store.Store) error {
		group, err = transaction.GetGroupByID(context.Background(), store.LockingStrengthUpdate, accountID, groupID)
		if err != nil {
			return err
		}

		if updated := group.AddPeer(peerID); !updated {
			return nil
		}

		updateAccountPeers, err = areGroupChangesAffectPeers(ctx, transaction, accountID, []string{groupID})
		if err != nil {
			return err
		}

		if err = transaction.IncrementNetworkSerial(ctx, store.LockingStrengthUpdate, accountID); err != nil {
			return err
		}

		return transaction.SaveGroup(ctx, store.LockingStrengthUpdate, group)
	})
	if err != nil {
		return err
	}

	if updateAccountPeers {
		am.UpdateAccountPeers(ctx, accountID)
	}

	return nil
}

// GroupAddResource appends resource to the group
func (am *DefaultAccountManager) GroupAddResource(ctx context.Context, accountID, groupID string, resource types.Resource) error {
	unlock := am.Store.AcquireWriteLockByUID(ctx, accountID)
	defer unlock()

	var group *types.Group
	var updateAccountPeers bool
	var err error

	err = am.Store.ExecuteInTransaction(ctx, func(transaction store.Store) error {
		group, err = transaction.GetGroupByID(context.Background(), store.LockingStrengthUpdate, accountID, groupID)
		if err != nil {
			return err
		}

		if updated := group.AddResource(resource); !updated {
			return nil
		}

		updateAccountPeers, err = areGroupChangesAffectPeers(ctx, transaction, accountID, []string{groupID})
		if err != nil {
			return err
		}

		if err = transaction.IncrementNetworkSerial(ctx, store.LockingStrengthUpdate, accountID); err != nil {
			return err
		}

		return transaction.SaveGroup(ctx, store.LockingStrengthUpdate, group)
	})
	if err != nil {
		return err
	}

	if updateAccountPeers {
		am.UpdateAccountPeers(ctx, accountID)
	}

	return nil
}

// GroupDeletePeer removes peer from the group
func (am *DefaultAccountManager) GroupDeletePeer(ctx context.Context, accountID, groupID, peerID string) error {
	unlock := am.Store.AcquireWriteLockByUID(ctx, accountID)
	defer unlock()

	var group *types.Group
	var updateAccountPeers bool
	var err error

	err = am.Store.ExecuteInTransaction(ctx, func(transaction store.Store) error {
		group, err = transaction.GetGroupByID(context.Background(), store.LockingStrengthUpdate, accountID, groupID)
		if err != nil {
			return err
		}

		if updated := group.RemovePeer(peerID); !updated {
			return nil
		}

		updateAccountPeers, err = areGroupChangesAffectPeers(ctx, transaction, accountID, []string{groupID})
		if err != nil {
			return err
		}

		if err = transaction.IncrementNetworkSerial(ctx, store.LockingStrengthUpdate, accountID); err != nil {
			return err
		}

		return transaction.SaveGroup(ctx, store.LockingStrengthUpdate, group)
	})
	if err != nil {
		return err
	}

	if updateAccountPeers {
		am.UpdateAccountPeers(ctx, accountID)
	}

	return nil
}

// GroupDeleteResource removes resource from the group
func (am *DefaultAccountManager) GroupDeleteResource(ctx context.Context, accountID, groupID string, resource types.Resource) error {
	unlock := am.Store.AcquireWriteLockByUID(ctx, accountID)
	defer unlock()

	var group *types.Group
	var updateAccountPeers bool
	var err error

	err = am.Store.ExecuteInTransaction(ctx, func(transaction store.Store) error {
		group, err = transaction.GetGroupByID(context.Background(), store.LockingStrengthUpdate, accountID, groupID)
		if err != nil {
			return err
		}

		if updated := group.RemoveResource(resource); !updated {
			return nil
		}

		updateAccountPeers, err = areGroupChangesAffectPeers(ctx, transaction, accountID, []string{groupID})
		if err != nil {
			return err
		}

		if err = transaction.IncrementNetworkSerial(ctx, store.LockingStrengthUpdate, accountID); err != nil {
			return err
		}

		return transaction.SaveGroup(ctx, store.LockingStrengthUpdate, group)
	})
	if err != nil {
		return err
	}

	if updateAccountPeers {
		am.UpdateAccountPeers(ctx, accountID)
	}

	return nil
}

// validateNewGroup validates the new group for existence and required fields.
func validateNewGroup(ctx context.Context, transaction store.Store, accountID string, newGroup *types.Group) error {
	if newGroup.ID == "" && newGroup.Issued != types.GroupIssuedAPI {
		return status.Errorf(status.InvalidArgument, "%s group without ID set", newGroup.Issued)
	}

	if newGroup.ID == "" && newGroup.Issued == types.GroupIssuedAPI {
		existingGroup, err := transaction.GetGroupByName(ctx, store.LockingStrengthShare, accountID, newGroup.Name)
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

	for _, peerID := range newGroup.Peers {
		_, err := transaction.GetPeerByID(ctx, store.LockingStrengthShare, accountID, peerID)
		if err != nil {
			return status.Errorf(status.InvalidArgument, "peer with ID \"%s\" not found", peerID)
		}
	}

	return nil
}

func validateDeleteGroup(ctx context.Context, transaction store.Store, group *types.Group, userID string) error {
	// disable a deleting integration group if the initiator is not an admin service user
	if group.Issued == types.GroupIssuedIntegration {
		executingUser, err := transaction.GetUserByUserID(ctx, store.LockingStrengthShare, userID)
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

	return checkGroupLinkedToSettings(ctx, transaction, group)
}

// checkGroupLinkedToSettings verifies if a group is linked to any settings in the account.
func checkGroupLinkedToSettings(ctx context.Context, transaction store.Store, group *types.Group) error {
	dnsSettings, err := transaction.GetAccountDNSSettings(ctx, store.LockingStrengthShare, group.AccountID)
	if err != nil {
		return status.Errorf(status.Internal, "failed to get DNS settings")
	}

	if slices.Contains(dnsSettings.DisabledManagementGroups, group.ID) {
		return &GroupLinkError{"disabled DNS management groups", group.Name}
	}

	settings, err := transaction.GetAccountSettings(ctx, store.LockingStrengthShare, group.AccountID)
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
	routes, err := transaction.GetAccountRoutes(ctx, store.LockingStrengthShare, accountID)
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
	policies, err := transaction.GetAccountPolicies(ctx, store.LockingStrengthShare, accountID)
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
	nameServerGroups, err := transaction.GetAccountNameServerGroups(ctx, store.LockingStrengthShare, accountID)
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
	setupKeys, err := transaction.GetAccountSetupKeys(ctx, store.LockingStrengthShare, accountID)
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
	users, err := transaction.GetAccountUsers(ctx, store.LockingStrengthShare, accountID)
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

// areGroupChangesAffectPeers checks if any changes to the specified groups will affect peers.
func areGroupChangesAffectPeers(ctx context.Context, transaction store.Store, accountID string, groupIDs []string) (bool, error) {
	if len(groupIDs) == 0 {
		return false, nil
	}

	dnsSettings, err := transaction.GetAccountDNSSettings(ctx, store.LockingStrengthShare, accountID)
	if err != nil {
		return false, err
	}

	for _, groupID := range groupIDs {
		if slices.Contains(dnsSettings.DisabledManagementGroups, groupID) {
			return true, nil
		}
		if linked, _ := isGroupLinkedToDns(ctx, transaction, accountID, groupID); linked {
			return true, nil
		}
		if linked, _ := isGroupLinkedToPolicy(ctx, transaction, accountID, groupID); linked {
			return true, nil
		}
		if linked, _ := isGroupLinkedToRoute(ctx, transaction, accountID, groupID); linked {
			return true, nil
		}
	}

	return false, nil
}

func (am *DefaultAccountManager) anyGroupHasPeers(account *types.Account, groupIDs []string) bool {
	for _, groupID := range groupIDs {
		if group, exists := account.Groups[groupID]; exists && group.HasPeers() {
			return true
		}
	}
	return false
}

// anyGroupHasPeersOrResources checks if any of the given groups in the account have peers or resources.
func anyGroupHasPeersOrResources(ctx context.Context, transaction store.Store, accountID string, groupIDs []string) (bool, error) {
	groups, err := transaction.GetGroupsByIDs(ctx, store.LockingStrengthShare, accountID, groupIDs)
	if err != nil {
		return false, err
	}

	for _, group := range groups {
		if group.HasPeers() || group.HasResources() {
			return true, nil
		}
	}

	return false, nil
}
