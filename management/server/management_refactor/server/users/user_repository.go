package users

type UserRepository interface {
	findUserByID(userID string) (User, error)
}
