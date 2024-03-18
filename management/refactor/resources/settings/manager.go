package settings

import "github.com/netbirdio/netbird/management/refactor/resources/settings/types"

type Manager interface {
	GetSettings(accountID string) (types.Settings, error)
}

type DefaultManager struct {
	repository Repository
}

func NewDefaultManager(repository Repository) *DefaultManager {
	return &DefaultManager{
		repository: repository,
	}
}

func (dm *DefaultManager) GetSettings(accountID string) (types.Settings, error) {
	return dm.repository.FindSettings(accountID)
}
