package server

// Group of the peers for ACL
type Group struct {
	// Name visible in the UI
	Name string
}

// GetGroup object of the peers
func (am *DefaultAccountManager) GetGroup(groupID string) (*Group, error) {
	return nil, nil
}

// UpdateGroup object of the peers
func (am *DefaultAccountManager) UpdateGroup(groupID *Group) error {
	return nil
}

// DeleteGroup object of the peers
func (am *DefaultAccountManager) DeleteGroup(groupID string) error {
	return nil
}

// ListGroups objects of the peers
func (am *DefaultAccountManager) ListGroups() ([]*Group, error) {
	return nil, nil
}

// GroupAddPeer appends peer to the group
func (am *DefaultAccountManager) GroupAddPeer(groupID, peerKey string) error {
	return nil
}

// GroupDeletePeer removes peer from the group
func (am *DefaultAccountManager) GroupDeletePeer(groupID, peerKey string) error {
	return nil
}

// GroupListPeers returns list of the peers from the group
func (am *DefaultAccountManager) GroupListPeers(groupID string) ([]*Peer, error) {
	return nil, nil
}
