package network

import "github.com/netbirdio/netbird/management/refactor/resources/network/types"

type Manager interface {
	GetNetwork(accountID string) (types.Network, error)
}

type DefaultManager struct {
}

func NewDefaultManager() *DefaultManager {
	return &DefaultManager{}
}

func (d DefaultManager) GetNetwork(accountID string) (types.Network, error) {
	// TODO implement me
	panic("implement me")
}
