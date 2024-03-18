package users

import (
	"github.com/netbirdio/netbird/management/refactor/resources/peers"
	"github.com/netbirdio/netbird/management/refactor/resources/users/types"
)

type Manager interface {
	GetUser(id string) (types.User, error)
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

func (d DefaultManager) GetUser(id string) (types.User, error) {
	// TODO implement me
	panic("implement me")
}
