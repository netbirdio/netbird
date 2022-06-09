package server

import (
	"fmt"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/management/server/jwtclaims"
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

// NewRegularUser creates a new user with role UserRoleAdmin
func NewRegularUser(id string) *User {
	return NewUser(id, UserRoleUser)
}

// NewAdminUser creates a new user with role UserRoleAdmin
func NewAdminUser(id string) *User {
	return NewUser(id, UserRoleAdmin)
}

// GetOrCreateAccountByUser returns an existing account for a given user id or creates a new one if doesn't exist
func (am *DefaultAccountManager) GetOrCreateAccountByUser(userId, domain string) (*Account, error) {
	am.mux.Lock()
	defer am.mux.Unlock()

	lowerDomain := strings.ToLower(domain)

	account, err := am.Store.GetUserAccount(userId)
	if err != nil {
		if s, ok := status.FromError(err); ok && s.Code() == codes.NotFound {
			account = NewAccount(userId, lowerDomain)
			err = am.Store.SaveAccount(account)
			if err != nil {
				return nil, status.Errorf(codes.Internal, "failed creating account")
			}
		} else {
			// other error
			return nil, err
		}
	}

	if account.Domain != lowerDomain {
		account.Domain = lowerDomain
		err = am.Store.SaveAccount(account)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "failed updating account with domain")
		}
	}

	return account, nil
}

// GetAccountByUser returns an existing account for a given user id, NotFound if account couldn't be found
func (am *DefaultAccountManager) GetAccountByUser(userId string) (*Account, error) {
	am.mux.Lock()
	defer am.mux.Unlock()

	return am.Store.GetUserAccount(userId)
}

// IsUserAdmin flag for current user authenticated by JWT token
func (am *DefaultAccountManager) IsUserAdmin(claims jwtclaims.AuthorizationClaims) (bool, error) {
	account, err := am.GetAccountWithAuthorizationClaims(claims)
	if err != nil {
		return false, fmt.Errorf("get account: %v", err)
	}

	user, ok := account.Users[claims.UserId]
	if !ok {
		return false, fmt.Errorf("no such user")
	}

	return user.Role == UserRoleAdmin, nil
}
