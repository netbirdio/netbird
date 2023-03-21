package server

import (
	"fmt"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/management/server/activity"
	"github.com/netbirdio/netbird/management/server/idp"
	"github.com/netbirdio/netbird/management/server/jwtclaims"
	"github.com/netbirdio/netbird/management/server/status"
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
	PATs       map[string]*PersonalAccessToken
}

// IsAdmin returns true if user is an admin, false otherwise
func (u *User) IsAdmin() bool {
	return u.Role == UserRoleAdmin
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

	userStatus := UserStatusActive
	if userData.AppMetadata.WTPendingInvite != nil && *userData.AppMetadata.WTPendingInvite {
		userStatus = UserStatusInvited
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
	autoGroups := make([]string, len(u.AutoGroups))
	copy(autoGroups, u.AutoGroups)
	pats := make(map[string]*PersonalAccessToken, len(u.PATs))
	for k, v := range u.PATs {
		patCopy := new(PersonalAccessToken)
		*patCopy = *v
		pats[k] = patCopy
	}
	return &User{
		Id:         u.Id,
		Role:       u.Role,
		AutoGroups: autoGroups,
		PATs:       pats,
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
func (am *DefaultAccountManager) CreateUser(accountID, userID string, invite *UserInfo) (*UserInfo, error) {
	unlock := am.Store.AcquireAccountLock(accountID)
	defer unlock()

	if am.idpManager == nil {
		return nil, status.Errorf(status.PreconditionFailed, "IdP manager must be enabled to send user invites")
	}

	if invite == nil {
		return nil, fmt.Errorf("provided user update is nil")
	}

	account, err := am.Store.GetAccount(accountID)
	if err != nil {
		return nil, status.Errorf(status.NotFound, "account %s doesn't exist", accountID)
	}

	// check if the user is already registered with this email => reject
	user, err := am.lookupUserInCacheByEmail(invite.Email, accountID)
	if err != nil {
		return nil, err
	}

	if user != nil {
		return nil, status.Errorf(status.UserAlreadyExists, "user has an existing account")
	}

	users, err := am.idpManager.GetUserByEmail(invite.Email)
	if err != nil {
		return nil, err
	}

	if len(users) > 0 {
		return nil, status.Errorf(status.UserAlreadyExists, "user has an existing account")
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

	_, err = am.refreshCache(account.Id)
	if err != nil {
		return nil, err
	}

	am.storeEvent(userID, newUser.Id, accountID, activity.UserInvited, nil)

	return newUser.toUserInfo(idpUser)

}

// AddPATToUser takes the userID and the accountID the user belongs to and assigns a provided PersonalAccessToken to that user
func (am *DefaultAccountManager) AddPATToUser(accountID string, userID string, pat *PersonalAccessToken) error {
	unlock := am.Store.AcquireAccountLock(accountID)
	defer unlock()

	account, err := am.Store.GetAccount(accountID)
	if err != nil {
		return err
	}

	user := account.Users[userID]
	if user == nil {
		return status.Errorf(status.NotFound, "user not found")
	}

	user.PATs[pat.ID] = pat

	return am.Store.SaveAccount(account)
}

// DeletePAT deletes a specific PAT from a user
func (am *DefaultAccountManager) DeletePAT(accountID string, userID string, tokenID string) error {
	unlock := am.Store.AcquireAccountLock(accountID)
	defer unlock()

	account, err := am.Store.GetAccount(accountID)
	if err != nil {
		return err
	}

	user := account.Users[userID]
	if user == nil {
		return status.Errorf(status.NotFound, "user not found")
	}

	pat := user.PATs["tokenID"]
	if pat == nil {
		return status.Errorf(status.NotFound, "PAT not found")
	}

	err = am.Store.DeleteTokenID2UserIDIndex(pat.ID)
	if err != nil {
		return err
	}
	err = am.Store.DeleteHashedPAT2TokenIDIndex(pat.HashedToken)
	if err != nil {
		return err
	}
	delete(user.PATs, tokenID)

	return am.Store.SaveAccount(account)
}

// SaveUser saves updates a given user. If the user doesn't exit it will throw status.NotFound error.
// Only User.AutoGroups field is allowed to be updated for now.
func (am *DefaultAccountManager) SaveUser(accountID, userID string, update *User) (*UserInfo, error) {
	unlock := am.Store.AcquireAccountLock(accountID)
	defer unlock()

	if update == nil {
		return nil, status.Errorf(status.InvalidArgument, "provided user update is nil")
	}

	account, err := am.Store.GetAccount(accountID)
	if err != nil {
		return nil, err
	}

	for _, newGroupID := range update.AutoGroups {
		if _, ok := account.Groups[newGroupID]; !ok {
			return nil, status.Errorf(status.InvalidArgument, "provided group ID %s in the user %s update doesn't exist",
				newGroupID, update.Id)
		}
	}

	oldUser := account.Users[update.Id]
	if oldUser == nil {
		return nil, status.Errorf(status.NotFound, "update not found")
	}

	// only auto groups, revoked status, and name can be updated for now
	newUser := oldUser.Copy()
	newUser.AutoGroups = update.AutoGroups
	newUser.Role = update.Role

	account.Users[newUser.Id] = newUser

	if err = am.Store.SaveAccount(account); err != nil {
		return nil, err
	}

	defer func() {
		if oldUser.Role != newUser.Role {
			am.storeEvent(userID, oldUser.Id, accountID, activity.UserRoleUpdated, map[string]any{"role": newUser.Role})
		}

		removedGroups := difference(oldUser.AutoGroups, update.AutoGroups)
		addedGroups := difference(newUser.AutoGroups, oldUser.AutoGroups)
		for _, g := range removedGroups {
			group := account.GetGroup(g)
			if group != nil {
				am.storeEvent(userID, oldUser.Id, accountID, activity.GroupRemovedFromUser,
					map[string]any{"group": group.Name, "group_id": group.ID})
			} else {
				log.Errorf("group %s not found while saving user activity event of account %s", g, account.Id)
			}

		}

		for _, g := range addedGroups {
			group := account.GetGroup(g)
			if group != nil {
				am.storeEvent(userID, oldUser.Id, accountID, activity.GroupAddedToUser,
					map[string]any{"group": group.Name, "group_id": group.ID})
			} else {
				log.Errorf("group %s not found while saving user activity event of account %s", g, account.Id)
			}
		}
	}()

	if !isNil(am.idpManager) {
		userData, err := am.lookupUserInCache(newUser.Id, account)
		if err != nil {
			return nil, err
		}
		if userData == nil {
			return nil, status.Errorf(status.NotFound, "user %s not found in the IdP", newUser.Id)
		}
		return newUser.toUserInfo(userData)
	}
	return newUser.toUserInfo(nil)
}

// GetOrCreateAccountByUser returns an existing account for a given user id or creates a new one if doesn't exist
func (am *DefaultAccountManager) GetOrCreateAccountByUser(userID, domain string) (*Account, error) {
	unlock := am.Store.AcquireGlobalLock()
	defer unlock()

	lowerDomain := strings.ToLower(domain)

	account, err := am.Store.GetAccountByUser(userID)
	if err != nil {
		if s, ok := status.FromError(err); ok && s.Type() == status.NotFound {
			account, err = am.newAccount(userID, lowerDomain)
			if err != nil {
				return nil, err
			}
			err = am.Store.SaveAccount(account)
			if err != nil {
				return nil, err
			}
		} else {
			// other error
			return nil, err
		}
	}

	userObj := account.Users[userID]

	if account.Domain != lowerDomain && userObj.Role == UserRoleAdmin {
		account.Domain = lowerDomain
		err = am.Store.SaveAccount(account)
		if err != nil {
			return nil, status.Errorf(status.Internal, "failed updating account with domain")
		}
	}

	return account, nil
}

// IsUserAdmin flag for current user authenticated by JWT token
func (am *DefaultAccountManager) IsUserAdmin(claims jwtclaims.AuthorizationClaims) (bool, error) {
	account, _, err := am.GetAccountFromToken(claims)
	if err != nil {
		return false, fmt.Errorf("get account: %v", err)
	}

	user, ok := account.Users[claims.UserId]
	if !ok {
		return false, status.Errorf(status.NotFound, "user not found")
	}

	return user.Role == UserRoleAdmin, nil
}

// GetUsersFromAccount performs a batched request for users from IDP by account ID apply filter on what data to return
// based on provided user role.
func (am *DefaultAccountManager) GetUsersFromAccount(accountID, userID string) ([]*UserInfo, error) {
	account, err := am.Store.GetAccount(accountID)
	if err != nil {
		return nil, err
	}

	user, err := account.FindUser(userID)
	if err != nil {
		return nil, err
	}

	queriedUsers := make([]*idp.UserData, 0)
	if !isNil(am.idpManager) {
		users := make(map[string]struct{}, len(account.Users))
		for _, user := range account.Users {
			users[user.Id] = struct{}{}
		}
		queriedUsers, err = am.lookupCache(users, accountID)
		if err != nil {
			return nil, err
		}
	}

	userInfos := make([]*UserInfo, 0)

	// in case of self-hosted, or IDP doesn't return anything, we will return the locally stored userInfo
	if len(queriedUsers) == 0 {
		for _, accountUser := range account.Users {
			if !user.IsAdmin() && user.Id != accountUser.Id {
				// if user is not an admin then show only current user and do not show other users
				continue
			}
			info, err := accountUser.toUserInfo(nil)
			if err != nil {
				return nil, err
			}
			userInfos = append(userInfos, info)
		}
		return userInfos, nil
	}

	for _, queriedUser := range queriedUsers {
		if !user.IsAdmin() && user.Id != queriedUser.ID {
			// if user is not an admin then show only current user and do not show other users
			continue
		}
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
