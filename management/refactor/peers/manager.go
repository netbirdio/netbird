package peers

import (
	"github.com/netbirdio/netbird/management/refactor/settings"
)

type Manager interface {
	GetPeerByPubKey(pubKey string) (Peer, error)
	GetPeerByID(id string) (Peer, error)
	GetNetworkPeerByID(id string) (Peer, error)
	GetNetworkPeersInAccount(id string) ([]Peer, error)
}

type DefaultManager struct {
	repository      Repository
	settingsManager settings.Manager
}

func NewDefaultManager(repository Repository, settingsManager settings.Manager) *DefaultManager {
	return &DefaultManager{
		repository:      repository,
		settingsManager: settingsManager,
	}
}

func (dm *DefaultManager) GetNetworkPeerByID(id string) (Peer, error) {
	return dm.repository.FindPeerByID(id)
}

func (dm *DefaultManager) GetNetworkPeersInAccount(id string) ([]Peer, error) {
	defaultPeers, err := dm.repository.FindAllPeersInAccount(id)
	if err != nil {
		return nil, err
	}

	peers := make([]Peer, len(defaultPeers))
	for _, dp := range defaultPeers {
		peers = append(peers, dp)
	}

	return peers, nil
}

func (dm *DefaultManager) GetPeerByPubKey(pubKey string) (Peer, error) {
	return dm.repository.FindPeerByPubKey(pubKey)
}

func (dm *DefaultManager) GetPeerByID(id string) (Peer, error) {
	return dm.repository.FindPeerByID(id)
}
