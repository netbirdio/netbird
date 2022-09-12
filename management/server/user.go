package server

import (
	"fmt"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"strings"

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
	// AutoGroups is a list of Group IDs to auto-assign to peers registered by this user
	AutoGroups []string
}

// Copy the user
func (u *User) Copy() *User {
	var autoGroups []string
	for _, group := range u.AutoGroups {
		autoGroups = append(autoGroups, group)
	}
	return &User{
		Id:         u.Id,
		Role:       u.Role,
		AutoGroups: autoGroups,
	}
}

// NewUser creates a new user
func NewUser(id string, role UserRole) *User {
	return &User{
		Id:         id,
		Role:       role,
		AutoGroups: []string{},
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

// SaveUser saves updates a given user. If the user doesn't exit it will throw status.NotFound error.
// Only User.AutoGroups field is allowed to be updated for now.
func (am *DefaultAccountManager) SaveUser(accountID string, update *User) (*UserInfo, error) {
	am.mux.Lock()
	defer am.mux.Unlock()

	if update == nil {
		return nil, status.Errorf(codes.InvalidArgument, "provided user update is nil")
	}

	account, err := am.Store.GetAccount(accountID)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "account not found")
	}

	oldUser := account.Users[update.Id]
	if oldUser == nil {
		return nil, status.Errorf(codes.NotFound, "update not found")
	}

	// only auto groups, revoked status, and name can be updated for now
	newUser := oldUser.Copy()
	newUser.AutoGroups = update.AutoGroups

	if err = am.Store.SaveAccount(account); err != nil {
		return nil, err
	}

	if !isNil(am.idpManager) {
		userData, err := am.lookupUserInCache(newUser, accountID)
		if err != nil {
			return nil, err
		}
		return &UserInfo{
			ID:         newUser.Id,
			Role:       string(newUser.Role),
			AutoGroups: newUser.AutoGroups,
			Email:      userData.Email,
			Name:       userData.Name,
		}, nil
	}

	return &UserInfo{
		ID:         newUser.Id,
		Role:       string(newUser.Role),
		AutoGroups: newUser.AutoGroups,
	}, nil
}

// GetOrCreateAccountByUser returns an existing account for a given user id or creates a new one if doesn't exist
func (am *DefaultAccountManager) GetOrCreateAccountByUser(userId, domain string) (*Account, error) {
	am.mux.Lock()
	defer am.mux.Unlock()

	lowerDomain := strings.ToLower(domain)

	account, err := am.Store.GetUserAccount(userId)
	if err != nil {
		if s, ok := status.FromError(err); ok && s.Code() == codes.NotFound {
			account, err = am.newAccount(userId, lowerDomain)
			if err != nil {
				return nil, err
			}
			err = am.Store.SaveAccount(account)
			if err != nil {
				return nil, status.Errorf(codes.Internal, "failed creating account")
			}
		} else {
			// other error
			return nil, err
		}
	}

	userObj := account.Users[userId]

	if account.Domain != lowerDomain && userObj.Role == UserRoleAdmin {
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
