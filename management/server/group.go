package server

import (
	"context"
	"errors"
	"fmt"
	"slices"

	nbdns "github.com/netbirdio/netbird/dns"
	"github.com/netbirdio/netbird/route"
	"github.com/rs/xid"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/management/server/activity"
	nbgroup "github.com/netbirdio/netbird/management/server/group"
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
	settings, err := am.Store.GetAccountSettings(ctx, LockingStrengthShare, accountID)
	if err != nil {
		return err
	}

	user, err := am.Store.GetUserByUserID(ctx, LockingStrengthShare, userID)
	if err != nil {
		return err
	}

	if user.AccountID != accountID {
		return status.NewUserNotPartOfAccountError()
	}

	if user.IsRegularUser() && settings.RegularUsersViewBlocked {
		return status.NewAdminPermissionError()
	}

	return nil
}

// GetGroup returns a specific group by groupID in an account
func (am *DefaultAccountManager) GetGroup(ctx context.Context, accountID, groupID, userID string) (*nbgroup.Group, error) {
	if err := am.CheckGroupPermissions(ctx, accountID, userID); err != nil {
		return nil, err
	}
	return am.Store.GetGroupByID(ctx, LockingStrengthShare, accountID, groupID)
}

// GetAllGroups returns all groups in an account
func (am *DefaultAccountManager) GetAllGroups(ctx context.Context, accountID, userID string) ([]*nbgroup.Group, error) {
	if err := am.CheckGroupPermissions(ctx, accountID, userID); err != nil {
		return nil, err
	}
	return am.Store.GetAccountGroups(ctx, LockingStrengthShare, accountID)
}

// GetGroupByName filters all groups in an account by name and returns the one with the most peers
func (am *DefaultAccountManager) GetGroupByName(ctx context.Context, groupName, accountID string) (*nbgroup.Group, error) {
	return am.Store.GetGroupByName(ctx, LockingStrengthShare, accountID, groupName)
}

// SaveGroup object of the peers
func (am *DefaultAccountManager) SaveGroup(ctx context.Context, accountID, userID string, newGroup *nbgroup.Group) error {
	unlock := am.Store.AcquireWriteLockByUID(ctx, accountID)
	defer unlock()
	return am.SaveGroups(ctx, accountID, userID, []*nbgroup.Group{newGroup})
}

// SaveGroups adds new groups to the account.
// Note: This function does not acquire the global lock.
// It is the caller's responsibility to ensure proper locking is in place before invoking this method.
func (am *DefaultAccountManager) SaveGroups(ctx context.Context, accountID, userID string, newGroups []*nbgroup.Group) error {
	user, err := am.Store.GetUserByUserID(ctx, LockingStrengthShare, userID)
	if err != nil {
		return err
	}

	if user.AccountID != accountID {
		return status.NewUserNotPartOfAccountError()
	}

	var (
		eventsToStore []func()
		groupsToSave  []*nbgroup.Group
	)

	for _, newGroup := range newGroups {
		if newGroup.ID == "" && newGroup.Issued != nbgroup.GroupIssuedAPI {
			return status.Errorf(status.InvalidArgument, "%s group without ID set", newGroup.Issued)
		}

		if newGroup.ID == "" && newGroup.Issued == nbgroup.GroupIssuedAPI {
			existingGroup, err := am.Store.GetGroupByName(ctx, LockingStrengthShare, accountID, newGroup.Name)
			if err != nil {
				s, ok := status.FromError(err)
				if !ok || s.ErrorType != status.NotFound {
					return err
				}
			}

			// Avoid duplicate groups only for the API issued groups.
			// Integration or JWT groups can be duplicated as they are coming from the IdP that we don't have control of.
			if existingGroup != nil {
				return status.Errorf(status.AlreadyExists, "group with name %s already exists", newGroup.Name)
			}

			newGroup.ID = xid.New().String()
		}

		for _, peerID := range newGroup.Peers {
			if _, err = am.Store.GetPeerByID(ctx, LockingStrengthShare, accountID, peerID); err != nil {
				return status.Errorf(status.InvalidArgument, "peer with ID \"%s\" not found", peerID)
			}
		}

		newGroup.AccountID = accountID
		groupsToSave = append(groupsToSave, newGroup)

		events := am.prepareGroupEvents(ctx, userID, accountID, newGroup)
		eventsToStore = append(eventsToStore, events...)
	}

	newGroupIDs := make([]string, 0, len(newGroups))
	for _, newGroup := range newGroups {
		newGroupIDs = append(newGroupIDs, newGroup.ID)
	}

	updateAccountPeers, err := am.areGroupChangesAffectPeers(ctx, accountID, newGroupIDs)
	if err != nil {
		return err
	}

	err = am.Store.ExecuteInTransaction(ctx, func(transaction Store) error {
		if err = transaction.IncrementNetworkSerial(ctx, LockingStrengthUpdate, accountID); err != nil {
			return err
		}

		if err = transaction.SaveGroups(ctx, LockingStrengthUpdate, groupsToSave); err != nil {
			return fmt.Errorf("failed to save groups: %w", err)
		}
		return nil
	})
	if err != nil {
		return err
	}

	for _, storeEvent := range eventsToStore {
		storeEvent()
	}

	if updateAccountPeers {
		am.updateAccountPeers(ctx, accountID)
	}

	return nil
}

// prepareGroupEvents prepares a list of event functions to be stored.
func (am *DefaultAccountManager) prepareGroupEvents(ctx context.Context, userID string, accountID string, newGroup *nbgroup.Group) []func() {
	var eventsToStore []func()

	addedPeers := make([]string, 0)
	removedPeers := make([]string, 0)

	oldGroup, err := am.Store.GetGroupByID(ctx, LockingStrengthShare, accountID, newGroup.ID)
	if err == nil && oldGroup != nil {
		addedPeers = difference(newGroup.Peers, oldGroup.Peers)
		removedPeers = difference(oldGroup.Peers, newGroup.Peers)
	} else {
		addedPeers = append(addedPeers, newGroup.Peers...)
		eventsToStore = append(eventsToStore, func() {
			am.StoreEvent(ctx, userID, newGroup.ID, accountID, activity.GroupCreated, newGroup.EventMeta())
		})
	}

	for _, peerID := range addedPeers {
		peer, err := am.Store.GetPeerByID(ctx, LockingStrengthShare, accountID, peerID)
		if err != nil {
			log.WithContext(ctx).Errorf("peer %s not found under account %s while saving group", peerID, accountID)
			continue
		}

		peerCopy := peer // copy to avoid closure issues
		eventsToStore = append(eventsToStore, func() {
			am.StoreEvent(ctx, userID, peerCopy.ID, accountID, activity.GroupAddedToPeer,
				map[string]any{
					"group": newGroup.Name, "group_id": newGroup.ID, "peer_ip": peerCopy.IP.String(),
					"peer_fqdn": peerCopy.FQDN(am.GetDNSDomain()),
				})
		})
	}

	for _, peerID := range removedPeers {
		peer, err := am.Store.GetPeerByID(ctx, LockingStrengthShare, accountID, peerID)
		if err != nil {
			log.WithContext(ctx).Errorf("peer %s not found under account %s while saving group", peerID, accountID)
			continue
		}

		peerCopy := peer // copy to avoid closure issues
		eventsToStore = append(eventsToStore, func() {
			am.StoreEvent(ctx, userID, peerCopy.ID, accountID, activity.GroupRemovedFromPeer,
				map[string]any{
					"group": newGroup.Name, "group_id": newGroup.ID, "peer_ip": peerCopy.IP.String(),
					"peer_fqdn": peerCopy.FQDN(am.GetDNSDomain()),
				})
		})
	}

	return eventsToStore
}

// difference returns the elements in `a` that aren't in `b`.
func difference(a, b []string) []string {
	mb := make(map[string]struct{}, len(b))
	for _, x := range b {
		mb[x] = struct{}{}
	}
	var diff []string
	for _, x := range a {
		if _, found := mb[x]; !found {
			diff = append(diff, x)
		}
	}
	return diff
}

// DeleteGroup object of the peers.
func (am *DefaultAccountManager) DeleteGroup(ctx context.Context, accountID, userID, groupID string) error {
	user, err := am.Store.GetUserByUserID(ctx, LockingStrengthShare, userID)
	if err != nil {
		return err
	}

	if user.AccountID != accountID {
		return status.NewUserNotPartOfAccountError()
	}

	group, err := am.Store.GetGroupByID(ctx, LockingStrengthShare, accountID, groupID)
	if err != nil {
		return err
	}

	if group.Name == "All" {
		return status.Errorf(status.InvalidArgument, "deleting group ALL is not allowed")
	}

	if err = am.validateDeleteGroup(ctx, group, userID); err != nil {
		return err
	}

	err = am.Store.ExecuteInTransaction(ctx, func(transaction Store) error {
		if err = transaction.IncrementNetworkSerial(ctx, LockingStrengthUpdate, accountID); err != nil {
			return err
		}

		if err = transaction.DeleteGroup(ctx, LockingStrengthUpdate, accountID, groupID); err != nil {
			return fmt.Errorf("failed to delete group: %w", err)
		}
		return nil
	})
	if err != nil {
		return err
	}

	am.StoreEvent(ctx, userID, groupID, accountID, activity.GroupDeleted, group.EventMeta())

	return nil
}

// DeleteGroups deletes groups from an account.
func (am *DefaultAccountManager) DeleteGroups(ctx context.Context, accountID, userID string, groupIDs []string) error {
	user, err := am.Store.GetUserByUserID(ctx, LockingStrengthShare, userID)
	if err != nil {
		return err
	}

	if user.AccountID != accountID {
		return status.NewUserNotPartOfAccountError()
	}

	var (
		allErrors        error
		groupIDsToDelete []string
		deletedGroups    []*nbgroup.Group
	)

	for _, groupID := range groupIDs {
		group, err := am.Store.GetGroupByID(ctx, LockingStrengthShare, accountID, groupID)
		if err != nil {
			continue
		}

		if err := am.validateDeleteGroup(ctx, group, userID); err != nil {
			allErrors = errors.Join(allErrors, fmt.Errorf("failed to delete group %s: %w", groupID, err))
			continue
		}

		groupIDsToDelete = append(groupIDsToDelete, groupID)
		deletedGroups = append(deletedGroups, group)
	}

	err = am.Store.ExecuteInTransaction(ctx, func(transaction Store) error {
		if err = transaction.IncrementNetworkSerial(ctx, LockingStrengthUpdate, accountID); err != nil {
			return err
		}

		if err = transaction.DeleteGroups(ctx, LockingStrengthUpdate, accountID, groupIDsToDelete); err != nil {
			return fmt.Errorf("failed to delete group: %w", err)
		}
		return nil
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
	group, err := am.Store.GetGroupByID(ctx, LockingStrengthShare, accountID, groupID)
	if err != nil {
		return err
	}

	add := true
	for _, itemID := range group.Peers {
		if itemID == peerID {
			add = false
			break
		}
	}
	if add {
		group.Peers = append(group.Peers, peerID)
	}

	updateAccountPeers, err := am.areGroupChangesAffectPeers(ctx, accountID, []string{groupID})
	if err != nil {
		return err
	}

	err = am.Store.ExecuteInTransaction(ctx, func(transaction Store) error {
		if err = transaction.IncrementNetworkSerial(ctx, LockingStrengthUpdate, accountID); err != nil {
			return err
		}

		if err = transaction.SaveGroup(ctx, LockingStrengthUpdate, group); err != nil {
			return fmt.Errorf("failed to save group: %w", err)
		}
		return nil
	})
	if err != nil {
		return err
	}

	if updateAccountPeers {
		am.updateAccountPeers(ctx, accountID)
	}

	return nil
}

// GroupDeletePeer removes peer from the group
func (am *DefaultAccountManager) GroupDeletePeer(ctx context.Context, accountID, groupID, peerID string) error {
	group, err := am.Store.GetGroupByID(ctx, LockingStrengthShare, accountID, groupID)
	if err != nil {
		return err
	}

	updated := false
	for i, itemID := range group.Peers {
		if itemID == peerID {
			group.Peers = append(group.Peers[:i], group.Peers[i+1:]...)
			updated = true
			break
		}
	}

	if !updated {
		return nil
	}

	updateAccountPeers, err := am.areGroupChangesAffectPeers(ctx, accountID, []string{groupID})
	if err != nil {
		return err
	}

	err = am.Store.ExecuteInTransaction(ctx, func(transaction Store) error {
		if err = transaction.IncrementNetworkSerial(ctx, LockingStrengthUpdate, accountID); err != nil {
			return err
		}

		if err = transaction.SaveGroup(ctx, LockingStrengthUpdate, group); err != nil {
			return fmt.Errorf("failed to save group: %w", err)
		}
		return nil
	})
	if err != nil {
		return err
	}

	if updateAccountPeers {
		am.updateAccountPeers(ctx, accountID)
	}

	return nil
}

func (am *DefaultAccountManager) validateDeleteGroup(ctx context.Context, group *nbgroup.Group, userID string) error {
	// disable a deleting integration group if the initiator is not an admin service user
	if group.Issued == nbgroup.GroupIssuedIntegration {
		executingUser, err := am.Store.GetUserByUserID(ctx, LockingStrengthShare, userID)
		if err != nil {
			return status.Errorf(status.NotFound, "user not found")
		}
		if executingUser.Role != UserRoleAdmin || !executingUser.IsServiceUser {
			return status.Errorf(status.PermissionDenied, "only service users with admin power can delete integration group")
		}
	}

	if isLinked, linkedRoute := am.isGroupLinkedToRoute(ctx, group.AccountID, group.ID); isLinked {
		return &GroupLinkError{"route", string(linkedRoute.NetID)}
	}

	if isLinked, linkedDns := am.isGroupLinkedToDns(ctx, group.AccountID, group.ID); isLinked {
		return &GroupLinkError{"name server groups", linkedDns.Name}
	}

	if isLinked, linkedPolicy := am.isGroupLinkedToPolicy(ctx, group.AccountID, group.ID); isLinked {
		return &GroupLinkError{"policy", linkedPolicy.Name}
	}

	if isLinked, linkedSetupKey := am.isGroupLinkedToSetupKey(ctx, group.AccountID, group.ID); isLinked {
		return &GroupLinkError{"setup key", linkedSetupKey.Name}
	}

	if isLinked, linkedUser := am.isGroupLinkedToUser(ctx, group.AccountID, group.ID); isLinked {
		return &GroupLinkError{"user", linkedUser.Id}
	}

	dnsSettings, err := am.Store.GetAccountDNSSettings(ctx, LockingStrengthShare, group.AccountID)
	if err != nil {
		return err
	}

	if slices.Contains(dnsSettings.DisabledManagementGroups, group.ID) {
		return &GroupLinkError{"disabled DNS management groups", group.Name}
	}

	settings, err := am.Store.GetAccountSettings(ctx, LockingStrengthShare, group.AccountID)
	if err != nil {
		return err
	}

	if settings.Extra != nil {
		if slices.Contains(settings.Extra.IntegratedValidatorGroups, group.ID) {
			return &GroupLinkError{"integrated validator", group.Name}
		}
	}

	return nil
}

// isGroupLinkedToRoute checks if a group is linked to any route in the account.
func (am *DefaultAccountManager) isGroupLinkedToRoute(ctx context.Context, accountID string, groupID string) (bool, *route.Route) {
	routes, err := am.Store.GetAccountRoutes(ctx, LockingStrengthShare, accountID)
	if err != nil {
		log.WithContext(ctx).Errorf("error retrieving routes while checking group linkage: %v", err)
		return false, nil
	}

	for _, r := range routes {
		if slices.Contains(r.Groups, groupID) || slices.Contains(r.PeerGroups, groupID) {
			return true, r
		}
	}

	return false, nil
}

// isGroupLinkedToPolicy checks if a group is linked to any policy in the account.
func (am *DefaultAccountManager) isGroupLinkedToPolicy(ctx context.Context, accountID string, groupID string) (bool, *Policy) {
	policies, err := am.Store.GetAccountPolicies(ctx, LockingStrengthShare, accountID)
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
func (am *DefaultAccountManager) isGroupLinkedToDns(ctx context.Context, accountID string, groupID string) (bool, *nbdns.NameServerGroup) {
	nameServerGroups, err := am.Store.GetAccountNameServerGroups(ctx, LockingStrengthShare, accountID)
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
func (am *DefaultAccountManager) isGroupLinkedToSetupKey(ctx context.Context, accountID string, groupID string) (bool, *SetupKey) {
	setupKeys, err := am.Store.GetAccountSetupKeys(ctx, LockingStrengthShare, accountID)
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
func (am *DefaultAccountManager) isGroupLinkedToUser(ctx context.Context, accountID string, groupID string) (bool, *User) {
	users, err := am.Store.GetAccountUsers(ctx, LockingStrengthShare, accountID)
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
func (am *DefaultAccountManager) areGroupChangesAffectPeers(ctx context.Context, accountID string, groupIDs []string) (bool, error) {
	if len(groupIDs) == 0 {
		return false, nil
	}

	dnsSettings, err := am.Store.GetAccountDNSSettings(ctx, LockingStrengthShare, accountID)
	if err != nil {
		return false, err
	}

	for _, groupID := range groupIDs {
		if slices.Contains(dnsSettings.DisabledManagementGroups, groupID) {
			return true, nil
		}
		if linked, _ := am.isGroupLinkedToDns(ctx, accountID, groupID); linked {
			return true, nil
		}
		if linked, _ := am.isGroupLinkedToPolicy(ctx, accountID, groupID); linked {
			return true, nil
		}
		if linked, _ := am.isGroupLinkedToRoute(ctx, accountID, groupID); linked {
			return true, nil
		}
	}

	return false, nil
}

// isGroupLinkedToRoute checks if a group is linked to any route in the account.
func isGroupLinkedToRoute(routes map[route.ID]*route.Route, groupID string) (bool, *route.Route) {
	for _, r := range routes {
		if slices.Contains(r.Groups, groupID) || slices.Contains(r.PeerGroups, groupID) {
			return true, r
		}
	}
	return false, nil
}

// isGroupLinkedToPolicy checks if a group is linked to any policy in the account.
func isGroupLinkedToPolicy(policies []*Policy, groupID string) (bool, *Policy) {
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
func isGroupLinkedToDns(nameServerGroups map[string]*nbdns.NameServerGroup, groupID string) (bool, *nbdns.NameServerGroup) {
	for _, dns := range nameServerGroups {
		for _, g := range dns.Groups {
			if g == groupID {
				return true, dns
			}
		}
	}
	return false, nil
}

// anyGroupHasPeers checks if any of the given groups in the account have peers.
func anyGroupHasPeers(account *Account, groupIDs []string) bool {
	for _, groupID := range groupIDs {
		if group, exists := account.Groups[groupID]; exists && group.HasPeers() {
			return true
		}
	}
	return false
}

func areGroupChangesAffectPeers(account *Account, groupIDs []string) bool {
	for _, groupID := range groupIDs {
		if slices.Contains(account.DNSSettings.DisabledManagementGroups, groupID) {
			return true
		}
		if linked, _ := isGroupLinkedToDns(account.NameServerGroups, groupID); linked {
			return true
		}
		if linked, _ := isGroupLinkedToPolicy(account.Policies, groupID); linked {
			return true
		}
		if linked, _ := isGroupLinkedToRoute(account.Routes, groupID); linked {
			return true
		}
	}

	return false
}
