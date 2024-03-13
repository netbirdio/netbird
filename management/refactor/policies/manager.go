package policies

import "github.com/netbirdio/netbird/management/refactor/peers"

type Manager interface {
	GetAccessiblePeersAndFirewallRules(peerID string) (peers []peers.Peer, firewallRules []*FirewallRule)
}

type DefaultManager struct {
	repository  repository
	peerManager peers.Manager
}

func NewDefaultManager(repository repository, peerManager peers.Manager) *DefaultManager {
	return &DefaultManager{
		repository:  repository,
		peerManager: peerManager,
	}
}

func (dm *DefaultManager) GetAccessiblePeersAndFirewallRules(peerID string) (peers []peers.Peer, firewallRules []*FirewallRule) {
	peer, err := dm.peerManager.GetPeerByID(peerID)
	if err != nil {
		return nil, nil
	}

	peers, err = dm.peerManager.GetNetworkPeersInAccount(peer.GetAccountID())

	return peers, nil
}
