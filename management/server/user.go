package server

import (
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	UserRoleAdmin UserRole = "admin"
	UserRoleUser  UserRole = "user"
)

// UserRole is the role of the User
type UserRole string

// User represents a user of the system
type User struct {
	Id   string
	Role UserRole
}

func (u *User) Copy() *User {
	return &User{
		Id:   u.Id,
		Role: u.Role,
	}
}

// NewUser creates a new user
func NewUser(id string, role UserRole) *User {
	return &User{
		Id:   id,
		Role: role,
	}
}

// NewAdminUser creates a new user with role UserRoleAdmin
func NewAdminUser(id string) *User {
	return NewUser(id, UserRoleAdmin)
}

// GetOrCreateAccountByUser returns an existing account for a given user id or creates a new one if doesn't exist
func (am *AccountManager) GetOrCreateAccountByUser(userId string) (*Account, error) {
	am.mux.Lock()
	defer am.mux.Unlock()

	account, err := am.Store.GetUserAccount(userId)
	if err != nil {
		if s, ok := status.FromError(err); ok && s.Code() == codes.NotFound {
			account, _ = newAccount(userId)
			account.Users[userId] = NewAdminUser(userId)
			err = am.Store.SaveAccount(account)
			if err != nil {
				return nil, status.Errorf(codes.Internal, "failed creating account")
			}
		} else {
			// other error
			return nil, err
		}
	}

	return account, nil
}

// GetAccountByUser returns an existing account for a given user id, NotFound if account couldn't be found
func (am *AccountManager) GetAccountByUser(userId string) (*Account, error) {
	am.mux.Lock()
	defer am.mux.Unlock()

	return am.Store.GetUserAccount(userId)
}
