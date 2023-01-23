package server

import (
	"github.com/netbirdio/netbird/management/server/activity"
	"github.com/netbirdio/netbird/management/server/status"
	log "github.com/sirupsen/logrus"
)

// Group of the peers for ACL
type Group struct {
	// ID of the group
	ID string

	// Name visible in the UI
	Name string

	// Peers list of the group
	Peers []string
}

const (
	// UpdateGroupName indicates a name update operation
	UpdateGroupName GroupUpdateOperationType = iota
	// InsertPeersToGroup indicates insert peers to group operation
	InsertPeersToGroup
	// RemovePeersFromGroup indicates a remove peers from group operation
	RemovePeersFromGroup
	// UpdateGroupPeers indicates a replacement of group peers list
	UpdateGroupPeers
)

// GroupUpdateOperationType operation type
type GroupUpdateOperationType int

// GroupUpdateOperation operation object with type and values to be applied
type GroupUpdateOperation struct {
	Type   GroupUpdateOperationType
	Values []string
}

// EventMeta returns activity event meta related to the group
func (g *Group) EventMeta() map[string]any {
	return map[string]any{"name": g.Name}
}

func (g *Group) Copy() *Group {
	return &Group{
		ID:    g.ID,
		Name:  g.Name,
		Peers: g.Peers[:],
	}
}

// GetGroup object of the peers
func (am *DefaultAccountManager) GetGroup(accountID, groupID string) (*Group, error) {

	unlock := am.Store.AcquireAccountLock(accountID)
	defer unlock()

	account, err := am.Store.GetAccount(accountID)
	if err != nil {
		return nil, err
	}

	group, ok := account.Groups[groupID]
	if ok {
		return group, nil
	}

	return nil, status.Errorf(status.NotFound, "group with ID %s not found", groupID)
}

// SaveGroup object of the peers
func (am *DefaultAccountManager) SaveGroup(accountID, userID string, newGroup *Group) error {

	unlock := am.Store.AcquireAccountLock(accountID)
	defer unlock()

	account, err := am.Store.GetAccount(accountID)
	if err != nil {
		return err
	}
	oldGroup, exists := account.Groups[newGroup.ID]
	account.Groups[newGroup.ID] = newGroup

	account.Network.IncSerial()
	if err = am.Store.SaveAccount(account); err != nil {
		return err
	}

	addedPeers := make([]string, 0)
	removedPeers := make([]string, 0)
	if exists {
		addedPeers = difference(newGroup.Peers, oldGroup.Peers)
		removedPeers = difference(oldGroup.Peers, newGroup.Peers)
	} else {
		addedPeers = append(addedPeers, newGroup.Peers...)
		am.storeEvent(userID, newGroup.ID, accountID, activity.GroupCreated, newGroup.EventMeta())
	}

	for _, p := range addedPeers {
		peer := account.Peers[p]
		if peer == nil {
			log.Errorf("peer %s not found under account %s while saving group", p, accountID)
			continue
		}
		am.storeEvent(userID, peer.IP.String(), accountID, activity.GroupAddedToPeer,
			map[string]any{"group": newGroup.Name, "group_id": newGroup.ID, "peer_ip": peer.IP.String(),
				"peer_fqdn": peer.FQDN(am.GetDNSDomain())})
	}

	for _, p := range removedPeers {
		peer := account.Peers[p]
		if peer == nil {
			log.Errorf("peer %s not found under account %s while saving group", p, accountID)
			continue
		}
		am.storeEvent(userID, peer.IP.String(), accountID, activity.GroupRemovedFromPeer,
			map[string]any{"group": newGroup.Name, "group_id": newGroup.ID, "peer_ip": peer.IP.String(),
				"peer_fqdn": peer.FQDN(am.GetDNSDomain())})
	}

	return am.updateAccountPeers(account)
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

// UpdateGroup updates a group using a list of operations
func (am *DefaultAccountManager) UpdateGroup(accountID string,
	groupID string, operations []GroupUpdateOperation) (*Group, error) {

	unlock := am.Store.AcquireAccountLock(accountID)
	defer unlock()

	account, err := am.Store.GetAccount(accountID)
	if err != nil {
		return nil, err
	}

	groupToUpdate, ok := account.Groups[groupID]
	if !ok {
		return nil, status.Errorf(status.NotFound, "group with ID %s no longer exists", groupID)
	}

	group := groupToUpdate.Copy()

	for _, operation := range operations {
		switch operation.Type {
		case UpdateGroupName:
			group.Name = operation.Values[0]
		case UpdateGroupPeers:
			group.Peers = operation.Values
		case InsertPeersToGroup:
			sourceList := group.Peers
			resultList := removeFromList(sourceList, operation.Values)
			group.Peers = append(resultList, operation.Values...)
		case RemovePeersFromGroup:
			sourceList := group.Peers
			resultList := removeFromList(sourceList, operation.Values)
			group.Peers = resultList
		}
	}

	account.Groups[groupID] = group

	account.Network.IncSerial()
	if err = am.Store.SaveAccount(account); err != nil {
		return nil, err
	}

	err = am.updateAccountPeers(account)
	if err != nil {
		return nil, err
	}

	return group, nil
}

// DeleteGroup object of the peers
func (am *DefaultAccountManager) DeleteGroup(accountID, groupID string) error {

	unlock := am.Store.AcquireAccountLock(accountID)
	defer unlock()

	account, err := am.Store.GetAccount(accountID)
	if err != nil {
		return err
	}

	delete(account.Groups, groupID)

	account.Network.IncSerial()
	if err = am.Store.SaveAccount(account); err != nil {
		return err
	}

	return am.updateAccountPeers(account)
}

// ListGroups objects of the peers
func (am *DefaultAccountManager) ListGroups(accountID string) ([]*Group, error) {

	unlock := am.Store.AcquireAccountLock(accountID)
	defer unlock()

	account, err := am.Store.GetAccount(accountID)
	if err != nil {
		return nil, err
	}

	groups := make([]*Group, 0, len(account.Groups))
	for _, item := range account.Groups {
		groups = append(groups, item)
	}

	return groups, nil
}

// GroupAddPeer appends peer to the group
func (am *DefaultAccountManager) GroupAddPeer(accountID, groupID, peerKey string) error {

	unlock := am.Store.AcquireAccountLock(accountID)
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
		if itemID == peerKey {
			add = false
			break
		}
	}
	if add {
		group.Peers = append(group.Peers, peerKey)
	}

	account.Network.IncSerial()
	if err = am.Store.SaveAccount(account); err != nil {
		return err
	}

	return am.updateAccountPeers(account)
}

// GroupDeletePeer removes peer from the group
func (am *DefaultAccountManager) GroupDeletePeer(accountID, groupID, peerKey string) error {

	unlock := am.Store.AcquireAccountLock(accountID)
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
		if itemID == peerKey {
			group.Peers = append(group.Peers[:i], group.Peers[i+1:]...)
			if err := am.Store.SaveAccount(account); err != nil {
				return err
			}
		}
	}

	return am.updateAccountPeers(account)
}

// GroupListPeers returns list of the peers from the group
func (am *DefaultAccountManager) GroupListPeers(accountID, groupID string) ([]*Peer, error) {

	unlock := am.Store.AcquireAccountLock(accountID)
	defer unlock()

	account, err := am.Store.GetAccount(accountID)
	if err != nil {
		return nil, status.Errorf(status.NotFound, "account not found")
	}

	group, ok := account.Groups[groupID]
	if !ok {
		return nil, status.Errorf(status.NotFound, "group with ID %s not found", groupID)
	}

	peers := make([]*Peer, 0, len(account.Groups))
	for _, peerID := range group.Peers {
		p, ok := account.Peers[peerID]
		if ok {
			peers = append(peers, p)
		}
	}

	return peers, nil
}
