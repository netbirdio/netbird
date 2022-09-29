package server

import (
	"fmt"
	"github.com/netbirdio/netbird/management/server/idp"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"strings"

	"github.com/netbirdio/netbird/management/server/jwtclaims"
)

const (
	UserRoleAdmin   UserRole = "admin"
	UserRoleUser    UserRole = "user"
	UserRoleUnknown UserRole = "unknown"

	UserStatusActive   UserStatus = "active"
	UserStatusDisabled UserStatus = "disabled"
	UserStatusInvited  UserStatus = "invited"
)

// StrRoleToUserRole returns UserRole for a given strRole or UserRoleUnknown if the specified role is unknown
func StrRoleToUserRole(strRole string) UserRole {
	switch strings.ToLower(strRole) {
	case "admin":
		return UserRoleAdmin
	case "user":
		return UserRoleUser
	default:
		return UserRoleUnknown
	}
}

// UserStatus is the status of a User
type UserStatus string

// UserRole is the role of a User
type UserRole string

// User represents a user of the system
type User struct {
	Id   string
	Role UserRole
	// AutoGroups is a list of Group IDs to auto-assign to peers registered by this user
	AutoGroups []string
}

// toUserInfo converts a User object to a UserInfo object.
func (u *User) toUserInfo(userData *idp.UserData) (*UserInfo, error) {
	autoGroups := u.AutoGroups
	if autoGroups == nil {
		autoGroups = []string{}
	}

	if userData == nil {
		return &UserInfo{
			ID:         u.Id,
			Email:      "",
			Name:       "",
			Role:       string(u.Role),
			AutoGroups: u.AutoGroups,
			Status:     string(UserStatusActive),
		}, nil
	}
	if userData.ID != u.Id {
		return nil, fmt.Errorf("wrong UserData provided for user %s", u.Id)
	}

	userStatus := UserStatusInvited
	if userData.LoginsCount > 0 {
		userStatus = UserStatusActive
	}

	return &UserInfo{
		ID:         u.Id,
		Email:      userData.Email,
		Name:       userData.Name,
		Role:       string(u.Role),
		AutoGroups: autoGroups,
		Status:     string(userStatus),
	}, nil
}

// Copy the user
func (u *User) Copy() *User {
	autoGroups := []string{}
	autoGroups = append(autoGroups, u.AutoGroups...)
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

// CreateUser creates a new user under the given account. Effectively this is a user invite.
func (am *DefaultAccountManager) CreateUser(accountID string, invite *UserInfo) (*UserInfo, error) {
	am.mux.Lock()
	defer am.mux.Unlock()

	if am.idpManager == nil {
		return nil, status.Errorf(codes.FailedPrecondition, "user invite is not possible without enabled IDP manager")
	}

	if invite == nil {
		return nil, status.Errorf(codes.InvalidArgument, "provided user update is nil")
	}

	account, err := am.Store.GetAccount(accountID)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "account not found")
	}

	// check if the user is already registered with this email => reject
	// TODO check all accounts!
	user, err := am.lookupUserInCacheByEmail(invite.Email, accountID)
	if err != nil {
		return nil, err
	}

	if user != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "user with a given email is already registered")
	}

	idpUser, err := am.idpManager.CreateUser(invite.Email, invite.Name, accountID)
	if err != nil {
		return nil, err
	}

	role := StrRoleToUserRole(invite.Role)
	newUser := &User{
		Id:         idpUser.ID,
		Role:       role,
		AutoGroups: invite.AutoGroups,
	}
	account.Users[idpUser.ID] = newUser

	err = am.Store.SaveAccount(account)
	if err != nil {
		return nil, err
	}

	return newUser.toUserInfo(idpUser)

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

	for _, newGroupID := range update.AutoGroups {
		if _, ok := account.Groups[newGroupID]; !ok {
			return nil,
				status.Errorf(codes.InvalidArgument, "provided group ID %s in the user %s update doesn't exist",
					newGroupID, update.Id)
		}
	}

	oldUser := account.Users[update.Id]
	if oldUser == nil {
		return nil, status.Errorf(codes.NotFound, "update not found")
	}

	// only auto groups, revoked status, and name can be updated for now
	newUser := oldUser.Copy()
	newUser.AutoGroups = update.AutoGroups
	newUser.Role = update.Role

	account.Users[newUser.Id] = newUser

	if err = am.Store.SaveAccount(account); err != nil {
		return nil, err
	}

	if !isNil(am.idpManager) {
		userData, err := am.lookupUserInCache(newUser, accountID)
		if err != nil {
			return nil, err
		}
		return newUser.toUserInfo(userData)
	}
	return newUser.toUserInfo(nil)
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

// GetUsersFromAccount performs a batched request for users from IDP by account ID
func (am *DefaultAccountManager) GetUsersFromAccount(accountID string) ([]*UserInfo, error) {
	account, err := am.GetAccountById(accountID)
	if err != nil {
		return nil, err
	}

	queriedUsers := make([]*idp.UserData, 0)
	if !isNil(am.idpManager) {
		queriedUsers, err = am.lookupCache(account.Users, accountID)
		if err != nil {
			return nil, err
		}
	}

	userInfos := make([]*UserInfo, 0)

	// in case of self-hosted, or IDP doesn't return anything, we will return the locally stored userInfo
	if len(queriedUsers) == 0 {
		for _, user := range account.Users {
			info, err := user.toUserInfo(nil)
			if err != nil {
				return nil, err
			}
			userInfos = append(userInfos, info)
		}
		return userInfos, nil
	}

	for _, queriedUser := range queriedUsers {
		if localUser, contains := account.Users[queriedUser.ID]; contains {

			info, err := localUser.toUserInfo(queriedUser)
			if err != nil {
				return nil, err
			}
			userInfos = append(userInfos, info)
		}
	}

	return userInfos, nil
}
