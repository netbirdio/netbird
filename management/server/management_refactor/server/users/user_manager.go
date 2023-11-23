package users

type UserManager interface {
	GetUser(userID string) (User, error)
}

type DefaultUserManager struct {
	repository UserRepository
}

func NewUserManager(repository UserRepository) *DefaultUserManager {
	return &DefaultUserManager{
		repository: repository,
	}
}

func (um *DefaultUserManager) GetUser(userID string) (User, error) {
	return um.repository.findUserByID(userID)
}
