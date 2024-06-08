package server

import (
	"fmt"

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
func (am *DefaultAccountManager) GetGroup(accountID, groupID, userID string) (*nbgroup.Group, error) {
	unlock := am.Store.AcquireAccountWriteLock(accountID)
	defer unlock()

	account, err := am.Store.GetAccount(accountID)
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
func (am *DefaultAccountManager) GetAllGroups(accountID string, userID string) ([]*nbgroup.Group, error) {
	unlock := am.Store.AcquireAccountWriteLock(accountID)
	defer unlock()

	account, err := am.Store.GetAccount(accountID)
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
func (am *DefaultAccountManager) GetGroupByName(groupName, accountID string) (*nbgroup.Group, error) {
	unlock := am.Store.AcquireAccountWriteLock(accountID)
	defer unlock()

	account, err := am.Store.GetAccount(accountID)
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
func (am *DefaultAccountManager) SaveGroup(accountID, userID string, newGroup *nbgroup.Group) error {
	unlock := am.Store.AcquireAccountWriteLock(accountID)
	defer unlock()

	account, err := am.Store.GetAccount(accountID)
	if err != nil {
		return err
	}

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

		// avoid duplicate groups only for the API issued groups. Integration or JWT groups can be duplicated as they are
		// coming from the IdP that we don't have control of.
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

	oldGroup, exists := account.Groups[newGroup.ID]
	account.Groups[newGroup.ID] = newGroup

	// Determine peer difference for group.
	addedPeers := make([]string, 0)
	removedPeers := make([]string, 0)
	if exists {
		addedPeers = difference(newGroup.Peers, oldGroup.Peers)
		removedPeers = difference(oldGroup.Peers, newGroup.Peers)
	} else {
		addedPeers = append(addedPeers, newGroup.Peers...)
	}

	// Need to check whether IPv6 status has changed for all potentially affected peers.
	peersToUpdate := make([]string, 0)
	// If group previously had IPv6 enabled, need to check all old peers for changes in IPv6 status.
	if exists && oldGroup.IPv6Enabled {
		peersToUpdate = removedPeers
	}
	// If group IPv6 status changed, need to check all current peers, if it did not, but IPv6 is enabled, only check
	// added peers, otherwise check no peers (as group can not affect IPv6 state).
	if exists && oldGroup.IPv6Enabled != newGroup.IPv6Enabled {
		peersToUpdate = append(peersToUpdate, newGroup.Peers...)
	} else if newGroup.IPv6Enabled {
		peersToUpdate = append(peersToUpdate, addedPeers...)
	}

	_, err = am.updatePeerIPv6Status(account, userID, newGroup, peersToUpdate)
	if err != nil {
		return err
	}

	account.Network.IncSerial()
	if err = am.Store.SaveAccount(account); err != nil {
		return err
	}

	am.updateAccountPeers(account)

	// the following snippet tracks the activity and stores the group events in the event store.
	// It has to happen after all the operations have been successfully performed.
	if !exists {
		am.StoreEvent(userID, newGroup.ID, accountID, activity.GroupCreated, newGroup.EventMeta())
	}

	for _, p := range addedPeers {
		peer := account.Peers[p]
		if peer == nil {
			log.Errorf("peer %s not found under account %s while saving group", p, accountID)
			continue
		}
		am.StoreEvent(userID, peer.ID, accountID, activity.GroupAddedToPeer,
			map[string]any{
				"group": newGroup.Name, "group_id": newGroup.ID, "peer_ip": peer.IP.String(),
				"peer_fqdn": peer.FQDN(am.GetDNSDomain()),
			})
	}

	for _, p := range removedPeers {
		peer := account.Peers[p]
		if peer == nil {
			log.Errorf("peer %s not found under account %s while saving group", p, accountID)
			continue
		}
		am.StoreEvent(userID, peer.ID, accountID, activity.GroupRemovedFromPeer,
			map[string]any{
				"group": newGroup.Name, "group_id": newGroup.ID, "peer_ip": peer.IP.String(),
				"peer_fqdn": peer.FQDN(am.GetDNSDomain()),
			})
	}

	return nil
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
func (am *DefaultAccountManager) DeleteGroup(accountId, userId, groupID string) error {
	unlock := am.Store.AcquireAccountWriteLock(accountId)
	defer unlock()

	account, err := am.Store.GetAccount(accountId)
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

	// check route links
	for _, r := range account.Routes {
		for _, g := range r.Groups {
			if g == groupID {
				return &GroupLinkError{"route", string(r.NetID)}
			}
		}
		for _, g := range r.PeerGroups {
			if g == groupID {
				return &GroupLinkError{"route", string(r.NetID)}
			}
		}
	}

	// check DNS links
	for _, dns := range account.NameServerGroups {
		for _, g := range dns.Groups {
			if g == groupID {
				return &GroupLinkError{"name server groups", dns.Name}
			}
		}
	}

	// check ACL links
	for _, policy := range account.Policies {
		for _, rule := range policy.Rules {
			for _, src := range rule.Sources {
				if src == groupID {
					return &GroupLinkError{"policy", policy.Name}
				}
			}

			for _, dst := range rule.Destinations {
				if dst == groupID {
					return &GroupLinkError{"policy", policy.Name}
				}
			}
		}
	}

	// check setup key links
	for _, setupKey := range account.SetupKeys {
		for _, grp := range setupKey.AutoGroups {
			if grp == groupID {
				return &GroupLinkError{"setup key", setupKey.Name}
			}
		}
	}

	// check user links
	for _, user := range account.Users {
		for _, grp := range user.AutoGroups {
			if grp == groupID {
				return &GroupLinkError{"user", user.Id}
			}
		}
	}

	// check DisabledManagementGroups
	for _, disabledMgmGrp := range account.DNSSettings.DisabledManagementGroups {
		if disabledMgmGrp == groupID {
			return &GroupLinkError{"disabled DNS management groups", g.Name}
		}
	}

	// check integrated peer validator groups
	if account.Settings.Extra != nil {
		for _, integratedPeerValidatorGroups := range account.Settings.Extra.IntegratedValidatorGroups {
			if groupID == integratedPeerValidatorGroups {
				return &GroupLinkError{"integrated validator", g.Name}
			}
		}
	}

	delete(account.Groups, groupID)

	// Update IPv6 status of all group members if necessary.
	if g.IPv6Enabled {
		_, err = am.updatePeerIPv6Status(account, userId, g, g.Peers)
		if err != nil {
			return err
		}
	}

	account.Network.IncSerial()
	if err = am.Store.SaveAccount(account); err != nil {
		return err
	}

	am.StoreEvent(userId, groupID, accountId, activity.GroupDeleted, g.EventMeta())

	am.updateAccountPeers(account)

	return nil
}

// ListGroups objects of the peers
func (am *DefaultAccountManager) ListGroups(accountID string) ([]*nbgroup.Group, error) {
	unlock := am.Store.AcquireAccountWriteLock(accountID)
	defer unlock()

	account, err := am.Store.GetAccount(accountID)
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
// TODO Question for devs: Is this method dead code? I can't seem to find any usages outside of tests...
func (am *DefaultAccountManager) GroupAddPeer(accountID, groupID, peerID string) error {
	unlock := am.Store.AcquireAccountWriteLock(accountID)
	defer unlock()

	account, err := am.Store.GetAccount(accountID)
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

		if group.IPv6Enabled {
			// Update IPv6 status of added group member.
			_, err = am.updatePeerIPv6Status(account, "", group, []string{peerID})
			if err != nil {
				return err
			}
		}
	}

	account.Network.IncSerial()
	if err = am.Store.SaveAccount(account); err != nil {
		return err
	}

	am.updateAccountPeers(account)

	return nil
}

// GroupDeletePeer removes peer from the group
// TODO Question for devs: Same as above, this seems like dead code
func (am *DefaultAccountManager) GroupDeletePeer(accountID, groupID, peerID string) error {
	unlock := am.Store.AcquireAccountWriteLock(accountID)
	defer unlock()

	account, err := am.Store.GetAccount(accountID)
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

			if group.IPv6Enabled {
				// Update IPv6 status of deleted group member.
				_, err = am.updatePeerIPv6Status(account, "", group, []string{peerID})
				if err != nil {
					return err
				}
			}

			if err := am.Store.SaveAccount(account); err != nil {
				return err
			}
		}
	}

	am.updateAccountPeers(account)

	return nil
}

func (am *DefaultAccountManager) updatePeerIPv6Status(account *Account, userID string, group *nbgroup.Group, peersToUpdate []string) (bool, error) {
	updated := false
	for _, peer := range peersToUpdate {
		peerObj := account.GetPeer(peer)
		update, err := am.DeterminePeerV6(account, peerObj)
		if err != nil {
			return false, err
		}
		if update {
			updated = true
			account.UpdatePeer(peerObj)
			if peerObj.IP6 != nil {
				am.StoreEvent(userID, group.ID, account.Id, activity.PeerIPv6InheritEnabled, group.EventMeta())
			} else {
				am.StoreEvent(userID, group.ID, account.Id, activity.PeerIPv6InheritDisabled, group.EventMeta())
			}
		}
	}
	return updated, nil
}
