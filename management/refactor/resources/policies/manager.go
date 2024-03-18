package policies

import (
	"github.com/netbirdio/netbird/management/refactor/resources/peers"
	"github.com/netbirdio/netbird/management/refactor/resources/peers/types"
)

type Manager interface {
	GetAccessiblePeersAndFirewallRules(peerID string) (peers []types.Peer, firewallRules []*FirewallRule)
}

type DefaultManager struct {
	repository  Repository
	peerManager peers.Manager
}

func NewDefaultManager(repository Repository, peerManager peers.Manager) *DefaultManager {
	return &DefaultManager{
		repository:  repository,
		peerManager: peerManager,
	}
}

func (dm *DefaultManager) GetAccessiblePeersAndFirewallRules(peerID string) (peers []types.Peer, firewallRules []*FirewallRule) {
	peer, err := dm.peerManager.GetPeerByID(peerID)
	if err != nil {
		return nil, nil
	}

	peers, err = dm.peerManager.GetNetworkPeersInAccount(peer.GetAccountID())

	return peers, nil
}
