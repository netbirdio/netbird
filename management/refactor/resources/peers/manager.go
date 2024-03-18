package peers

import (
	"github.com/netbirdio/netbird/management/refactor/resources/peers/types"
	"github.com/netbirdio/netbird/management/refactor/resources/settings"
)

type Manager interface {
	GetPeerByPubKey(pubKey string) (types.Peer, error)
	GetPeerByID(id string) (types.Peer, error)
	GetNetworkPeerByID(id string) (types.Peer, error)
	GetNetworkPeersInAccount(id string) ([]types.Peer, error)
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

func (dm *DefaultManager) GetNetworkPeerByID(id string) (types.Peer, error) {
	return dm.repository.FindPeerByID(id)
}

func (dm *DefaultManager) GetNetworkPeersInAccount(accountId string) ([]types.Peer, error) {
	defaultPeers, err := dm.repository.FindAllPeersInAccount(accountId)
	if err != nil {
		return nil, err
	}

	peers := make([]types.Peer, len(defaultPeers))
	for _, dp := range defaultPeers {
		peers = append(peers, dp)
	}

	return peers, nil
}

func (dm *DefaultManager) GetPeerByPubKey(pubKey string) (types.Peer, error) {
	return dm.repository.FindPeerByPubKey(pubKey)
}

func (dm *DefaultManager) GetPeerByID(id string) (types.Peer, error) {
	return dm.repository.FindPeerByID(id)
}
