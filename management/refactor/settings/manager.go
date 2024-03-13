package settings

type Manager interface {
	GetSettings(accountID string) (Settings, error)
}

type DefaultManager struct {
	repository repository
}

func NewDefaultManager(repository repository) *DefaultManager {
	return &DefaultManager{
		repository: repository,
	}
}

func (dm *DefaultManager) GetSettings(accountID string) (Settings, error) {
	return dm.repository.FindSettings(accountID)
}
