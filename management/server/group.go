package server

import (
	"context"
	"fmt"
	"slices"

	"github.com/netbirdio/netbird/dns"
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

// GetGroup object of the peers
func (am *DefaultAccountManager) GetGroup(ctx context.Context, accountID, groupID, userID string) (*nbgroup.Group, error) {
	unlock := am.Store.AcquireAccountWriteLock(ctx, accountID)
	defer unlock()

	account, err := am.Store.GetAccount(ctx, accountID)
	if err != nil {
		return nil, err
	}

	user, err := account.FindUser(userID)
	if err != nil {
		return nil, err
	}

	if !user.HasAdminPower() && !user.IsServiceUser && account.Settings.RegularUsersViewBlocked {
		return nil, status.Errorf(status.PermissionDenied, "groups are blocked for users")
	}

	group, ok := account.Groups[groupID]
	if ok {
		return group, nil
	}

	return nil, status.Errorf(status.NotFound, "group with ID %s not found", groupID)
}

// GetAllGroups returns all groups in an account
func (am *DefaultAccountManager) GetAllGroups(ctx context.Context, accountID string, userID string) ([]*nbgroup.Group, error) {
	unlock := am.Store.AcquireAccountWriteLock(ctx, accountID)
	defer unlock()

	account, err := am.Store.GetAccount(ctx, accountID)
	if err != nil {
		return nil, err
	}

	user, err := account.FindUser(userID)
	if err != nil {
		return nil, err
	}

	if !user.HasAdminPower() && !user.IsServiceUser && account.Settings.RegularUsersViewBlocked {
		return nil, status.Errorf(status.PermissionDenied, "groups are blocked for users")
	}

	groups := make([]*nbgroup.Group, 0, len(account.Groups))
	for _, item := range account.Groups {
		groups = append(groups, item)
	}

	return groups, nil
}

// GetGroupByName filters all groups in an account by name and returns the one with the most peers
func (am *DefaultAccountManager) GetGroupByName(ctx context.Context, groupName, accountID string) (*nbgroup.Group, error) {
	unlock := am.Store.AcquireAccountWriteLock(ctx, accountID)
	defer unlock()

	account, err := am.Store.GetAccount(ctx, accountID)
	if err != nil {
		return nil, err
	}

	matchingGroups := make([]*nbgroup.Group, 0)
	for _, group := range account.Groups {
		if group.Name == groupName {
			matchingGroups = append(matchingGroups, group)
		}
	}

	if len(matchingGroups) == 0 {
		return nil, status.Errorf(status.NotFound, "group with name %s not found", groupName)
	}

	maxPeers := -1
	var groupWithMostPeers *nbgroup.Group
	for i, group := range matchingGroups {
		if len(group.Peers) > maxPeers {
			maxPeers = len(group.Peers)
			groupWithMostPeers = matchingGroups[i]
		}
	}

	return groupWithMostPeers, nil
}

// SaveGroup object of the peers
func (am *DefaultAccountManager) SaveGroup(ctx context.Context, accountID, userID string, newGroup *nbgroup.Group) error {
	unlock := am.Store.AcquireAccountWriteLock(ctx, accountID)
	defer unlock()
	return am.SaveGroups(ctx, accountID, userID, []*nbgroup.Group{newGroup})
}

// SaveGroups adds new groups to the account.
// Note: This function does not acquire the global lock.
// It is the caller's responsibility to ensure proper locking is in place before invoking this method.
func (am *DefaultAccountManager) SaveGroups(ctx context.Context, accountID, userID string, newGroups []*nbgroup.Group) error {
	account, err := am.Store.GetAccount(ctx, accountID)
	if err != nil {
		return err
	}

	var eventsToStore []func()

	for _, newGroup := range newGroups {
		if newGroup.ID == "" && newGroup.Issued != nbgroup.GroupIssuedAPI {
			return status.Errorf(status.InvalidArgument, "%s group without ID set", newGroup.Issued)
		}

		if newGroup.ID == "" && newGroup.Issued == nbgroup.GroupIssuedAPI {
			existingGroup, err := account.FindGroupByName(newGroup.Name)
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
			if account.Peers[peerID] == nil {
				return status.Errorf(status.InvalidArgument, "peer with ID \"%s\" not found", peerID)
			}
		}

		oldGroup := account.Groups[newGroup.ID]
		account.Groups[newGroup.ID] = newGroup

		events := am.prepareGroupEvents(ctx, userID, accountID, newGroup, oldGroup, account)
		eventsToStore = append(eventsToStore, events...)
	}

	account.Network.IncSerial()
	if err = am.Store.SaveGroups(account.Id, account.Groups); err != nil {
		return err
	}

	am.updateAccountPeers(ctx, account)

	for _, storeEvent := range eventsToStore {
		storeEvent()
	}

	return nil
}

// prepareGroupEvents prepares a list of event functions to be stored.
func (am *DefaultAccountManager) prepareGroupEvents(ctx context.Context, userID string, accountID string, newGroup, oldGroup *nbgroup.Group, account *Account) []func() {
	var eventsToStore []func()

	addedPeers := make([]string, 0)
	removedPeers := make([]string, 0)

	if oldGroup != nil {
		addedPeers = difference(newGroup.Peers, oldGroup.Peers)
		removedPeers = difference(oldGroup.Peers, newGroup.Peers)
	} else {
		addedPeers = append(addedPeers, newGroup.Peers...)
		eventsToStore = append(eventsToStore, func() {
			am.StoreEvent(ctx, userID, newGroup.ID, accountID, activity.GroupCreated, newGroup.EventMeta())
		})
	}

	for _, p := range addedPeers {
		peer := account.Peers[p]
		if peer == nil {
			log.WithContext(ctx).Errorf("peer %s not found under account %s while saving group", p, accountID)
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

	for _, p := range removedPeers {
		peer := account.Peers[p]
		if peer == nil {
			log.WithContext(ctx).Errorf("peer %s not found under account %s while saving group", p, accountID)
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

// DeleteGroup object of the peers
func (am *DefaultAccountManager) DeleteGroup(ctx context.Context, accountId, userId, groupID string) error {
	unlock := am.Store.AcquireAccountWriteLock(ctx, accountId)
	defer unlock()

	account, err := am.Store.GetAccount(ctx, accountId)
	if err != nil {
		return err
	}

	g, ok := account.Groups[groupID]
	if !ok {
		return nil
	}

	// disable a deleting integration group if the initiator is not an admin service user
	if g.Issued == nbgroup.GroupIssuedIntegration {
		executingUser := account.Users[userId]
		if executingUser == nil {
			return status.Errorf(status.NotFound, "user not found")
		}
		if executingUser.Role != UserRoleAdmin || !executingUser.IsServiceUser {
			return status.Errorf(status.PermissionDenied, "only service users with admin power can delete integration group")
		}
	}

	if err := checkGroupLinks(account, groupID); err != nil {
		return err
	}

	delete(account.Groups, groupID)
	if err = am.Store.SaveAccount(ctx, account); err != nil {
		return err
	}
	am.StoreEvent(ctx, userId, groupID, accountId, activity.GroupDeleted, g.EventMeta())

	return nil
}

// ListGroups objects of the peers
func (am *DefaultAccountManager) ListGroups(ctx context.Context, accountID string) ([]*nbgroup.Group, error) {
	unlock := am.Store.AcquireAccountWriteLock(ctx, accountID)
	defer unlock()

	account, err := am.Store.GetAccount(ctx, accountID)
	if err != nil {
		return nil, err
	}

	groups := make([]*nbgroup.Group, 0, len(account.Groups))
	for _, item := range account.Groups {
		groups = append(groups, item)
	}

	return groups, nil
}

// GroupAddPeer appends peer to the group
func (am *DefaultAccountManager) GroupAddPeer(ctx context.Context, accountID, groupID, peerID string) error {
	unlock := am.Store.AcquireAccountWriteLock(ctx, accountID)
	defer unlock()

	account, err := am.Store.GetAccount(ctx, accountID)
	if err != nil {
		return err
	}

	group, ok := account.Groups[groupID]
	if !ok {
		return status.Errorf(status.NotFound, "group with ID %s not found", groupID)
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

	account.Network.IncSerial()
	if err = am.Store.SaveAccount(ctx, account); err != nil {
		return err
	}

	am.updateAccountPeers(ctx, account)

	return nil
}

// GroupDeletePeer removes peer from the group
func (am *DefaultAccountManager) GroupDeletePeer(ctx context.Context, accountID, groupID, peerID string) error {
	unlock := am.Store.AcquireAccountWriteLock(ctx, accountID)
	defer unlock()

	account, err := am.Store.GetAccount(ctx, accountID)
	if err != nil {
		return err
	}

	group, ok := account.Groups[groupID]
	if !ok {
		return status.Errorf(status.NotFound, "group with ID %s not found", groupID)
	}

	account.Network.IncSerial()
	for i, itemID := range group.Peers {
		if itemID == peerID {
			group.Peers = append(group.Peers[:i], group.Peers[i+1:]...)
			if err := am.Store.SaveAccount(ctx, account); err != nil {
				return err
			}
		}
	}

	am.updateAccountPeers(ctx, account)

	return nil
}

// checkGroupLinks checks if a group is linked to any route, DNS, policy, setup key, user, disabled management groups,
// or integrated validator groups.
// If the group is linked, it returns a GroupLinkError indicating the type of resource it is linked to and the name of that resource.
func checkGroupLinks(account *Account, groupID string) error {
	if isLinked, linkedRoute := isGroupLinkedToRoute(account, groupID); isLinked {
		return &GroupLinkError{"route", string(linkedRoute.NetID)}
	}

	if isLinked, linkedDns := isGroupLinkedToDns(account, groupID); isLinked {
		return &GroupLinkError{"name server groups", linkedDns.Name}
	}

	if isLinked, linkedPolicy := isGroupLinkedToPolicy(account, groupID); isLinked {
		return &GroupLinkError{"policy", linkedPolicy.Name}
	}

	if isLinked, linkedSetupKey := isGroupLinkedToSetupKey(account, groupID); isLinked {
		return &GroupLinkError{"setup key", linkedSetupKey.Name}
	}

	if isLinked, linkedUser := isGroupLinkedToUser(account, groupID); isLinked {
		return &GroupLinkError{"user", linkedUser.Id}
	}

	if slices.Contains(account.DNSSettings.DisabledManagementGroups, groupID) {
		return &GroupLinkError{"disabled DNS management groups", account.Groups[groupID].Name}
	}

	if account.Settings.Extra != nil {
		if slices.Contains(account.Settings.Extra.IntegratedValidatorGroups, groupID) {
			return &GroupLinkError{"integrated validator", account.Groups[groupID].Name}
		}
	}

	return nil
}

// isGroupLinkedToRoute checks if a group is linked to any route in the account.
func isGroupLinkedToRoute(account *Account, groupID string) (bool, *route.Route) {
	for _, r := range account.Routes {
		if slices.Contains(r.Groups, groupID) || slices.Contains(r.PeerGroups, groupID) {
			return true, r
		}
	}
	return false, nil
}

// isGroupLinkedToPolicy checks if a group is linked to any policy in the account.
func isGroupLinkedToPolicy(account *Account, groupID string) (bool, *Policy) {
	for _, policy := range account.Policies {
		for _, rule := range policy.Rules {
			if slices.Contains(rule.Sources, groupID) || slices.Contains(rule.Destinations, groupID) {
				return true, policy
			}
		}
	}
	return false, nil
}

// isGroupLinkedToDns checks if a group is linked to any nameserver group in the account.
func isGroupLinkedToDns(account *Account, groupID string) (bool, *dns.NameServerGroup) {
	for _, dns := range account.NameServerGroups {
		for _, g := range dns.Groups {
			if g == groupID {
				return true, dns
			}
		}
	}
	return false, nil
}

// isGroupLinkedToSetupKey checks if a group is linked to any setup key in the account.
func isGroupLinkedToSetupKey(account *Account, groupID string) (bool, *SetupKey) {
	for _, setupKey := range account.SetupKeys {
		if slices.Contains(setupKey.AutoGroups, groupID) {
			return true, setupKey
		}
	}
	return false, nil
}

// isGroupLinkedToUser checks if a group is linked to any user in the account.
func isGroupLinkedToUser(account *Account, groupID string) (bool, *User) {
	for _, user := range account.Users {
		if slices.Contains(user.AutoGroups, groupID) {
			return false, user
		}
	}
	return false, nil
}
