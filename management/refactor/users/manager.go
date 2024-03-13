package users

import "github.com/netbirdio/netbird/management/refactor/peers"

type Manager interface {
	GetUser(id string) (User, error)
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

func (d DefaultManager) GetUser(id string) (User, error) {
	// TODO implement me
	panic("implement me")
}
