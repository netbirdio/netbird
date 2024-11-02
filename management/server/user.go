package server

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/netbirdio/netbird/management/server/activity"
	nbgroup "github.com/netbirdio/netbird/management/server/group"
	"github.com/netbirdio/netbird/management/server/idp"
	"github.com/netbirdio/netbird/management/server/integration_reference"
	"github.com/netbirdio/netbird/management/server/jwtclaims"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/status"
	log "github.com/sirupsen/logrus"
)

const (
	UserRoleOwner        UserRole = "owner"
	UserRoleAdmin        UserRole = "admin"
	UserRoleUser         UserRole = "user"
	UserRoleUnknown      UserRole = "unknown"
	UserRoleBillingAdmin UserRole = "billing_admin"

	UserStatusActive   UserStatus = "active"
	UserStatusDisabled UserStatus = "disabled"
	UserStatusInvited  UserStatus = "invited"

	UserIssuedAPI         = "api"
	UserIssuedIntegration = "integration"
)

// StrRoleToUserRole returns UserRole for a given strRole or UserRoleUnknown if the specified role is unknown
func StrRoleToUserRole(strRole string) UserRole {
	switch strings.ToLower(strRole) {
	case "owner":
		return UserRoleOwner
	case "admin":
		return UserRoleAdmin
	case "user":
		return UserRoleUser
	case "billing_admin":
		return UserRoleBillingAdmin
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
	Id string `gorm:"primaryKey"`
	// AccountID is a reference to Account that this object belongs
	AccountID     string `json:"-" gorm:"index"`
	Role          UserRole
	IsServiceUser bool
	// NonDeletable indicates whether the service user can be deleted
	NonDeletable bool
	// ServiceUserName is only set if IsServiceUser is true
	ServiceUserName string
	// AutoGroups is a list of Group IDs to auto-assign to peers registered by this user
	AutoGroups []string                        `gorm:"serializer:json"`
	PATs       map[string]*PersonalAccessToken `gorm:"-"`
	PATsG      []PersonalAccessToken           `json:"-" gorm:"foreignKey:UserID;references:id"`
	// Blocked indicates whether the user is blocked. Blocked users can't use the system.
	Blocked bool
	// LastLogin is the last time the user logged in to IdP
	LastLogin time.Time
	// CreatedAt records the time the user was created
	CreatedAt time.Time

	// Issued of the user
	Issued string `gorm:"default:api"`

	IntegrationReference integration_reference.IntegrationReference `gorm:"embedded;embeddedPrefix:integration_ref_"`
}

// IsBlocked returns true if the user is blocked, false otherwise
func (u *User) IsBlocked() bool {
	return u.Blocked
}

func (u *User) LastDashboardLoginChanged(LastLogin time.Time) bool {
	return LastLogin.After(u.LastLogin) && !u.LastLogin.IsZero()
}

// HasAdminPower returns true if the user has admin or owner roles, false otherwise
func (u *User) HasAdminPower() bool {
	return u.Role == UserRoleAdmin || u.Role == UserRoleOwner
}

// IsAdminOrServiceUser checks if the user has admin power or is a service user.
func (u *User) IsAdminOrServiceUser() bool {
	return u.HasAdminPower() || u.IsServiceUser
}

// IsRegularUser checks if the user is a regular user.
func (u *User) IsRegularUser() bool {
	return !u.HasAdminPower() && !u.IsServiceUser
}

// ToUserInfo converts a User object to a UserInfo object.
func (u *User) ToUserInfo(userData *idp.UserData, settings *Settings) (*UserInfo, error) {
	autoGroups := u.AutoGroups
	if autoGroups == nil {
		autoGroups = []string{}
	}

	dashboardViewPermissions := "full"
	if !u.HasAdminPower() {
		dashboardViewPermissions = "limited"
		if settings.RegularUsersViewBlocked {
			dashboardViewPermissions = "blocked"
		}
	}

	if userData == nil {
		return &UserInfo{
			ID:            u.Id,
			Email:         "",
			Name:          u.ServiceUserName,
			Role:          string(u.Role),
			AutoGroups:    u.AutoGroups,
			Status:        string(UserStatusActive),
			IsServiceUser: u.IsServiceUser,
			IsBlocked:     u.Blocked,
			LastLogin:     u.LastLogin,
			Issued:        u.Issued,
			Permissions: UserPermissions{
				DashboardView: dashboardViewPermissions,
			},
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
		ID:            u.Id,
		Email:         userData.Email,
		Name:          userData.Name,
		Role:          string(u.Role),
		AutoGroups:    autoGroups,
		Status:        string(userStatus),
		IsServiceUser: u.IsServiceUser,
		IsBlocked:     u.Blocked,
		LastLogin:     u.LastLogin,
		Issued:        u.Issued,
		Permissions: UserPermissions{
			DashboardView: dashboardViewPermissions,
		},
	}, nil
}

// Copy the user
func (u *User) Copy() *User {
	autoGroups := make([]string, len(u.AutoGroups))
	copy(autoGroups, u.AutoGroups)
	pats := make(map[string]*PersonalAccessToken, len(u.PATs))
	for k, v := range u.PATs {
		pats[k] = v.Copy()
	}
	return &User{
		Id:                   u.Id,
		AccountID:            u.AccountID,
		Role:                 u.Role,
		AutoGroups:           autoGroups,
		IsServiceUser:        u.IsServiceUser,
		NonDeletable:         u.NonDeletable,
		ServiceUserName:      u.ServiceUserName,
		PATs:                 pats,
		Blocked:              u.Blocked,
		LastLogin:            u.LastLogin,
		CreatedAt:            u.CreatedAt,
		Issued:               u.Issued,
		IntegrationReference: u.IntegrationReference,
	}
}

// NewUser creates a new user
func NewUser(id string, role UserRole, isServiceUser bool, nonDeletable bool, serviceUserName string, autoGroups []string, issued string) *User {
	return &User{
		Id:              id,
		Role:            role,
		IsServiceUser:   isServiceUser,
		NonDeletable:    nonDeletable,
		ServiceUserName: serviceUserName,
		AutoGroups:      autoGroups,
		Issued:          issued,
		CreatedAt:       time.Now().UTC(),
	}
}

// NewRegularUser creates a new user with role UserRoleUser
func NewRegularUser(id string) *User {
	return NewUser(id, UserRoleUser, false, false, "", []string{}, UserIssuedAPI)
}

// NewAdminUser creates a new user with role UserRoleAdmin
func NewAdminUser(id string) *User {
	return NewUser(id, UserRoleAdmin, false, false, "", []string{}, UserIssuedAPI)
}

// NewOwnerUser creates a new user with role UserRoleOwner
func NewOwnerUser(id string) *User {
	return NewUser(id, UserRoleOwner, false, false, "", []string{}, UserIssuedAPI)
}

// createServiceUser creates a new service user under the given account.
func (am *DefaultAccountManager) createServiceUser(ctx context.Context, accountID string, initiatorUserID string, role UserRole, serviceUserName string, nonDeletable bool, autoGroups []string) (*UserInfo, error) {
	initiatorUser, err := am.Store.GetUserByUserID(ctx, LockingStrengthShare, initiatorUserID)
	if err != nil {
		return nil, err
	}

	if initiatorUser.AccountID != accountID {
		return nil, status.NewUserNotPartOfAccountError()
	}

	if !initiatorUser.HasAdminPower() {
		return nil, status.NewUnauthorizedToViewServiceUsersError()
	}

	if role == UserRoleOwner {
		return nil, status.NewServiceUserRoleInvalidError()
	}

	newUserID := uuid.New().String()
	newUser := NewUser(newUserID, role, true, nonDeletable, serviceUserName, autoGroups, UserIssuedAPI)
	newUser.AccountID = accountID
	log.WithContext(ctx).Debugf("New User: %v", newUser)

	if err = am.Store.SaveUser(ctx, LockingStrengthUpdate, newUser); err != nil {
		return nil, err
	}

	meta := map[string]any{"name": newUser.ServiceUserName}
	am.StoreEvent(ctx, initiatorUserID, newUser.Id, accountID, activity.ServiceUserCreated, meta)

	return &UserInfo{
		ID:            newUser.Id,
		Email:         "",
		Name:          newUser.ServiceUserName,
		Role:          string(newUser.Role),
		AutoGroups:    newUser.AutoGroups,
		Status:        string(UserStatusActive),
		IsServiceUser: true,
		LastLogin:     time.Time{},
		Issued:        UserIssuedAPI,
	}, nil
}

// CreateUser creates a new user under the given account. Effectively this is a user invite.
func (am *DefaultAccountManager) CreateUser(ctx context.Context, accountID, userID string, user *UserInfo) (*UserInfo, error) {
	if user.IsServiceUser {
		return am.createServiceUser(ctx, accountID, userID, StrRoleToUserRole(user.Role), user.Name, user.NonDeletable, user.AutoGroups)
	}
	return am.inviteNewUser(ctx, accountID, userID, user)
}

// inviteNewUser Invites a USer to a given account and creates reference in datastore
func (am *DefaultAccountManager) inviteNewUser(ctx context.Context, accountID, userID string, invite *UserInfo) (*UserInfo, error) {
	if am.idpManager == nil {
		return nil, status.Errorf(status.PreconditionFailed, "IdP manager must be enabled to send user invites")
	}

	if err := validateUserInvite(invite); err != nil {
		return nil, err
	}

	initiatorUser, err := am.Store.GetUserByUserID(ctx, LockingStrengthShare, userID)
	if err != nil {
		return nil, err
	}

	if initiatorUser.AccountID != accountID {
		return nil, status.NewUserNotPartOfAccountError()
	}

	inviterID := userID
	if initiatorUser.IsServiceUser {
		createdBy, err := am.Store.GetAccountCreatedBy(ctx, LockingStrengthShare, accountID)
		if err != nil {
			return nil, err
		}
		inviterID = createdBy
	}

	// inviterUser is the one who is inviting the new user
	inviterUser, err := am.lookupUserInCache(ctx, inviterID, accountID)
	if err != nil {
		return nil, status.Errorf(status.NotFound, "inviter user with ID %s doesn't exist in IdP", inviterID)
	}

	// check if the user is already registered with this email => reject
	user, err := am.lookupUserInCacheByEmail(ctx, invite.Email, accountID)
	if err != nil {
		return nil, err
	}

	if user != nil {
		return nil, status.Errorf(status.UserAlreadyExists, "can't invite a user with an existing NetBird account")
	}

	users, err := am.idpManager.GetUserByEmail(ctx, invite.Email)
	if err != nil {
		return nil, err
	}

	if len(users) > 0 {
		return nil, status.Errorf(status.UserAlreadyExists, "can't invite a user with an existing NetBird account")
	}

	idpUser, err := am.idpManager.CreateUser(ctx, invite.Email, invite.Name, accountID, inviterUser.Email)
	if err != nil {
		return nil, err
	}

	newUser := &User{
		Id:                   idpUser.ID,
		AccountID:            accountID,
		Role:                 StrRoleToUserRole(invite.Role),
		AutoGroups:           invite.AutoGroups,
		Issued:               invite.Issued,
		IntegrationReference: invite.IntegrationReference,
		CreatedAt:            time.Now().UTC(),
	}

	settings, err := am.Store.GetAccountSettings(ctx, LockingStrengthShare, accountID)
	if err != nil {
		return nil, err
	}

	if err = am.Store.SaveUser(ctx, LockingStrengthUpdate, newUser); err != nil {
		return nil, err
	}

	_, err = am.refreshCache(ctx, accountID)
	if err != nil {
		return nil, err
	}

	am.StoreEvent(ctx, userID, newUser.Id, accountID, activity.UserInvited, nil)

	return newUser.ToUserInfo(idpUser, settings)
}

func (am *DefaultAccountManager) GetUserByID(ctx context.Context, id string) (*User, error) {
	return am.Store.GetUserByUserID(ctx, LockingStrengthShare, id)
}

// GetUser looks up a user by provided authorization claims.
// It will also create an account if didn't exist for this user before.
func (am *DefaultAccountManager) GetUser(ctx context.Context, claims jwtclaims.AuthorizationClaims) (*User, error) {
	accountID, userID, err := am.GetAccountIDFromToken(ctx, claims)
	if err != nil {
		return nil, fmt.Errorf("failed to get account with token claims %v", err)
	}

	user, err := am.Store.GetUserByUserID(ctx, LockingStrengthShare, userID)
	if err != nil {
		return nil, err
	}

	// this code should be outside of the am.GetAccountIDFromToken(claims) because this method is called also by the gRPC
	// server when user authenticates a device. And we need to separate the Dashboard login event from the Device login event.
	newLogin := user.LastDashboardLoginChanged(claims.LastLogin)

	err = am.Store.SaveUserLastLogin(ctx, accountID, userID, claims.LastLogin)
	if err != nil {
		log.WithContext(ctx).Errorf("failed saving user last login: %v", err)
	}

	if newLogin {
		meta := map[string]any{"timestamp": claims.LastLogin}
		am.StoreEvent(ctx, claims.UserId, claims.UserId, accountID, activity.DashboardLogin, meta)
	}

	return user, nil
}

// ListUsers returns lists of all users under the account.
// It doesn't populate user information such as email or name.
func (am *DefaultAccountManager) ListUsers(ctx context.Context, accountID string) ([]*User, error) {
	return am.Store.GetAccountUsers(ctx, LockingStrengthShare, accountID)
}

func (am *DefaultAccountManager) deleteServiceUser(ctx context.Context, accountID string, initiatorUserID string, targetUser *User) error {
	if err := am.Store.DeleteUser(ctx, LockingStrengthUpdate, accountID, targetUser.Id); err != nil {
		return err
	}
	meta := map[string]any{"name": targetUser.ServiceUserName, "created_at": targetUser.CreatedAt}
	am.StoreEvent(ctx, initiatorUserID, targetUser.Id, accountID, activity.ServiceUserDeleted, meta)
	return nil
}

// DeleteUser deletes a user from the given account.
func (am *DefaultAccountManager) DeleteUser(ctx context.Context, accountID, initiatorUserID, targetUserID string) error {
	if initiatorUserID == targetUserID {
		return status.Errorf(status.InvalidArgument, "self deletion is not allowed")
	}

	initiatorUser, err := am.Store.GetUserByUserID(ctx, LockingStrengthShare, initiatorUserID)
	if err != nil {
		return err
	}

	if initiatorUser.AccountID != accountID {
		return status.NewUserNotPartOfAccountError()
	}

	if !initiatorUser.HasAdminPower() {
		return status.NewAdminPermissionError()
	}

	targetUser, err := am.Store.GetUserByUserID(ctx, LockingStrengthShare, targetUserID)
	if err != nil {
		return err
	}

	if targetUser.Role == UserRoleOwner {
		return status.NewOwnerDeletePermissionError()
	}

	// disable deleting integration user if the initiator is not admin service user
	if targetUser.Issued == UserIssuedIntegration && !initiatorUser.IsServiceUser {
		return status.Errorf(status.PermissionDenied, "only integration service user can delete this user")
	}

	// handle service user first and exit, no need to fetch extra data from IDP, etc
	if targetUser.IsServiceUser {
		if targetUser.NonDeletable {
			return status.Errorf(status.PermissionDenied, "service user is marked as non-deletable")
		}

		return am.deleteServiceUser(ctx, accountID, initiatorUserID, targetUser)
	}

	updateAccountPeers, err := am.deleteRegularUser(ctx, accountID, initiatorUserID, targetUserID)
	if err != nil {
		return err
	}

	if updateAccountPeers {
		am.updateAccountPeers(ctx, accountID)
	}

	return nil
}

// InviteUser resend invitations to users who haven't activated their accounts prior to the expiration period.
func (am *DefaultAccountManager) InviteUser(ctx context.Context, accountID string, initiatorUserID string, targetUserID string) error {
	if am.idpManager == nil {
		return status.Errorf(status.PreconditionFailed, "IdP manager must be enabled to send user invites")
	}

	initiatorUser, err := am.Store.GetUserByUserID(ctx, LockingStrengthShare, initiatorUserID)
	if err != nil {
		return err
	}

	if initiatorUser.AccountID != accountID {
		return status.NewUserNotPartOfAccountError()
	}

	// check if the user is already registered with this ID
	user, err := am.lookupUserInCache(ctx, targetUserID, accountID)
	if err != nil {
		return err
	}

	if user == nil {
		return status.Errorf(status.NotFound, "user account %s doesn't exist", targetUserID)
	}

	// check if user account is already invited and account is not activated
	pendingInvite := user.AppMetadata.WTPendingInvite
	if pendingInvite == nil || !*pendingInvite {
		return status.Errorf(status.PreconditionFailed, "can't invite a user with an activated NetBird account")
	}

	err = am.idpManager.InviteUserByID(ctx, user.ID)
	if err != nil {
		return err
	}

	am.StoreEvent(ctx, initiatorUserID, user.ID, accountID, activity.UserInvited, nil)

	return nil
}

// CreatePAT creates a new PAT for the given user
func (am *DefaultAccountManager) CreatePAT(ctx context.Context, accountID string, initiatorUserID string, targetUserID string, tokenName string, expiresIn int) (*PersonalAccessTokenGenerated, error) {
	if tokenName == "" {
		return nil, status.Errorf(status.InvalidArgument, "token name can't be empty")
	}

	if expiresIn < 1 || expiresIn > 365 {
		return nil, status.Errorf(status.InvalidArgument, "expiration has to be between 1 and 365")
	}

	initiatorUser, err := am.Store.GetUserByUserID(ctx, LockingStrengthShare, initiatorUserID)
	if err != nil {
		return nil, err
	}

	if initiatorUser.AccountID != accountID {
		return nil, status.NewUserNotPartOfAccountError()
	}

	if initiatorUserID != targetUserID && initiatorUser.IsRegularUser() {
		return nil, status.NewAdminPermissionError()
	}

	targetUser, err := am.Store.GetUserByUserID(ctx, LockingStrengthShare, initiatorUserID)
	if err != nil {
		return nil, err
	}

	pat, err := CreateNewPAT(tokenName, expiresIn, targetUserID, initiatorUser.Id)
	if err != nil {
		return nil, status.Errorf(status.Internal, "failed to create PAT: %v", err)
	}

	if err = am.Store.SavePAT(ctx, LockingStrengthUpdate, &pat.PersonalAccessToken); err != nil {
		return nil, err
	}

	meta := map[string]any{"name": pat.Name, "is_service_user": targetUser.IsServiceUser, "user_name": targetUser.ServiceUserName}
	am.StoreEvent(ctx, initiatorUserID, targetUserID, accountID, activity.PersonalAccessTokenCreated, meta)

	return pat, nil
}

// DeletePAT deletes a specific PAT from a user
func (am *DefaultAccountManager) DeletePAT(ctx context.Context, accountID string, initiatorUserID string, targetUserID string, tokenID string) error {
	initiatorUser, err := am.Store.GetUserByUserID(ctx, LockingStrengthShare, initiatorUserID)
	if err != nil {
		return err
	}

	if initiatorUser.AccountID != accountID {
		return status.NewUserNotPartOfAccountError()
	}

	if initiatorUserID != targetUserID && initiatorUser.IsRegularUser() {
		return status.NewAdminPermissionError()
	}

	pat, err := am.Store.GetPATByID(ctx, LockingStrengthShare, targetUserID, tokenID)
	if err != nil {
		return err
	}

	targetUser, err := am.Store.GetUserByUserID(ctx, LockingStrengthShare, targetUserID)
	if err != nil {
		return err
	}

	if err = am.Store.DeletePAT(ctx, LockingStrengthUpdate, targetUserID, tokenID); err != nil {
		return err
	}

	meta := map[string]any{"name": pat.Name, "is_service_user": targetUser.IsServiceUser, "user_name": targetUser.ServiceUserName}
	am.StoreEvent(ctx, initiatorUserID, targetUserID, accountID, activity.PersonalAccessTokenDeleted, meta)

	return nil
}

// GetPAT returns a specific PAT from a user
func (am *DefaultAccountManager) GetPAT(ctx context.Context, accountID string, initiatorUserID string, targetUserID string, tokenID string) (*PersonalAccessToken, error) {
	initiatorUser, err := am.Store.GetUserByUserID(ctx, LockingStrengthShare, initiatorUserID)
	if err != nil {
		return nil, err
	}

	if initiatorUser.AccountID != accountID {
		return nil, status.NewUserNotPartOfAccountError()
	}

	if initiatorUserID != targetUserID && initiatorUser.IsRegularUser() {
		return nil, status.NewAdminPermissionError()
	}

	return am.Store.GetPATByID(ctx, LockingStrengthShare, targetUserID, tokenID)
}

// GetAllPATs returns all PATs for a user
func (am *DefaultAccountManager) GetAllPATs(ctx context.Context, accountID string, initiatorUserID string, targetUserID string) ([]*PersonalAccessToken, error) {
	initiatorUser, err := am.Store.GetUserByUserID(ctx, LockingStrengthShare, initiatorUserID)
	if err != nil {
		return nil, err
	}

	if initiatorUser.AccountID != accountID {
		return nil, status.NewUserNotPartOfAccountError()
	}

	if initiatorUserID != targetUserID && initiatorUser.IsRegularUser() {
		return nil, status.NewAdminPermissionError()
	}

	return am.Store.GetUserPATs(ctx, LockingStrengthShare, targetUserID)
}

// SaveUser saves updates to the given user. If the user doesn't exist, it will throw status.NotFound error.
func (am *DefaultAccountManager) SaveUser(ctx context.Context, accountID, initiatorUserID string, update *User) (*UserInfo, error) {
	return am.SaveOrAddUser(ctx, accountID, initiatorUserID, update, false) // false means do not create user and throw status.NotFound
}

// SaveOrAddUser updates the given user. If addIfNotExists is set to true it will add user when no exist
// Only User.AutoGroups, User.Role, and User.Blocked fields are allowed to be updated for now.
func (am *DefaultAccountManager) SaveOrAddUser(ctx context.Context, accountID, initiatorUserID string, update *User, addIfNotExists bool) (*UserInfo, error) {
	if update == nil {
		return nil, status.Errorf(status.InvalidArgument, "provided user update is nil")
	}

	updatedUsers, err := am.SaveOrAddUsers(ctx, accountID, initiatorUserID, []*User{update}, addIfNotExists)
	if err != nil {
		return nil, err
	}

	if len(updatedUsers) == 0 {
		return nil, status.Errorf(status.Internal, "user was not updated")
	}

	return updatedUsers[0], nil
}

// SaveOrAddUsers updates existing users or adds new users to the account.
// Note: This function does not acquire the global lock.
// It is the caller's responsibility to ensure proper locking is in place before invoking this method.
func (am *DefaultAccountManager) SaveOrAddUsers(ctx context.Context, accountID, initiatorUserID string, updates []*User, addIfNotExists bool) ([]*UserInfo, error) {
	if len(updates) == 0 {
		return nil, nil //nolint:nilnil
	}

	account, err := am.Store.GetAccount(ctx, accountID)
	if err != nil {
		return nil, err
	}

	initiatorUser, err := account.FindUser(initiatorUserID)
	if err != nil {
		return nil, err
	}

	if !initiatorUser.HasAdminPower() || initiatorUser.IsBlocked() {
		return nil, status.Errorf(status.PermissionDenied, "only users with admin power are authorized to perform user update operations")
	}

	updatedUsers := make([]*UserInfo, 0, len(updates))
	var (
		expiredPeers  []*nbpeer.Peer
		userIDs       []string
		eventsToStore []func()
	)

	for _, update := range updates {
		if update == nil {
			return nil, status.Errorf(status.InvalidArgument, "provided user update is nil")
		}

		userIDs = append(userIDs, update.Id)

		oldUser := account.Users[update.Id]
		if oldUser == nil {
			if !addIfNotExists {
				return nil, status.Errorf(status.NotFound, "user to update doesn't exist: %s", update.Id)
			}
			// when addIfNotExists is set to true, the newUser will use all fields from the update input
			oldUser = update
		}

		if err := validateUserUpdate(account, initiatorUser, oldUser, update); err != nil {
			return nil, err
		}

		// only auto groups, revoked status, and integration reference can be updated for now
		newUser := oldUser.Copy()
		newUser.Role = update.Role
		newUser.Blocked = update.Blocked
		newUser.AutoGroups = update.AutoGroups
		// these two fields can't be set via API, only via direct call to the method
		newUser.Issued = update.Issued
		newUser.IntegrationReference = update.IntegrationReference

		transferredOwnerRole := handleOwnerRoleTransfer(account, initiatorUser, update)
		account.Users[newUser.Id] = newUser

		if !oldUser.IsBlocked() && update.IsBlocked() {
			// expire peers that belong to the user who's getting blocked
			blockedPeers, err := account.FindUserPeers(update.Id)
			if err != nil {
				return nil, err
			}
			expiredPeers = append(expiredPeers, blockedPeers...)
		}

		if update.AutoGroups != nil && account.Settings.GroupsPropagationEnabled {
			removedGroups := difference(oldUser.AutoGroups, update.AutoGroups)
			// need force update all auto groups in any case they will not be duplicated
			account.UserGroupsAddToPeers(oldUser.Id, update.AutoGroups...)
			account.UserGroupsRemoveFromPeers(oldUser.Id, removedGroups...)
		}

		events := am.prepareUserUpdateEvents(ctx, initiatorUser.Id, oldUser, newUser, account, transferredOwnerRole)
		eventsToStore = append(eventsToStore, events...)

		updatedUserInfo, err := getUserInfo(ctx, am, newUser, accountID)
		if err != nil {
			return nil, err
		}
		updatedUsers = append(updatedUsers, updatedUserInfo)
	}

	if len(expiredPeers) > 0 {
		if err := am.expireAndUpdatePeers(ctx, accountID, expiredPeers); err != nil {
			log.WithContext(ctx).Errorf("failed update expired peers: %s", err)
			return nil, err
		}
	}

	account.Network.IncSerial()
	if err = am.Store.SaveAccount(ctx, account); err != nil {
		return nil, err
	}

	if account.Settings.GroupsPropagationEnabled && areUsersLinkedToPeers(account, userIDs) {
		am.updateAccountPeers(ctx, accountID)
	}

	for _, storeEvent := range eventsToStore {
		storeEvent()
	}

	return updatedUsers, nil
}

// prepareUserUpdateEvents prepares a list user update events based on the changes between the old and new user data.
func (am *DefaultAccountManager) prepareUserUpdateEvents(ctx context.Context, initiatorUserID string, oldUser, newUser *User, account *Account, transferredOwnerRole bool) []func() {
	var eventsToStore []func()

	if oldUser.IsBlocked() != newUser.IsBlocked() {
		if newUser.IsBlocked() {
			eventsToStore = append(eventsToStore, func() {
				am.StoreEvent(ctx, initiatorUserID, oldUser.Id, account.Id, activity.UserBlocked, nil)
			})
		} else {
			eventsToStore = append(eventsToStore, func() {
				am.StoreEvent(ctx, initiatorUserID, oldUser.Id, account.Id, activity.UserUnblocked, nil)
			})
		}
	}

	switch {
	case transferredOwnerRole:
		eventsToStore = append(eventsToStore, func() {
			am.StoreEvent(ctx, initiatorUserID, oldUser.Id, account.Id, activity.TransferredOwnerRole, nil)
		})
	case oldUser.Role != newUser.Role:
		eventsToStore = append(eventsToStore, func() {
			am.StoreEvent(ctx, initiatorUserID, oldUser.Id, account.Id, activity.UserRoleUpdated, map[string]any{"role": newUser.Role})
		})
	}

	if newUser.AutoGroups != nil {
		removedGroups := difference(oldUser.AutoGroups, newUser.AutoGroups)
		addedGroups := difference(newUser.AutoGroups, oldUser.AutoGroups)
		for _, g := range removedGroups {
			group := account.GetGroup(g)
			if group != nil {
				eventsToStore = append(eventsToStore, func() {
					am.StoreEvent(ctx, initiatorUserID, oldUser.Id, account.Id, activity.GroupRemovedFromUser,
						map[string]any{"group": group.Name, "group_id": group.ID, "is_service_user": newUser.IsServiceUser, "user_name": newUser.ServiceUserName})
				})

			} else {
				log.WithContext(ctx).Errorf("group %s not found while saving user activity event of account %s", g, account.Id)
			}
		}
		for _, g := range addedGroups {
			group := account.GetGroup(g)
			if group != nil {
				eventsToStore = append(eventsToStore, func() {
					am.StoreEvent(ctx, initiatorUserID, oldUser.Id, account.Id, activity.GroupAddedToUser,
						map[string]any{"group": group.Name, "group_id": group.ID, "is_service_user": newUser.IsServiceUser, "user_name": newUser.ServiceUserName})
				})
			}
		}
	}

	return eventsToStore
}

func handleOwnerRoleTransfer(account *Account, initiatorUser, update *User) bool {
	if initiatorUser.Role == UserRoleOwner && initiatorUser.Id != update.Id && update.Role == UserRoleOwner {
		newInitiatorUser := initiatorUser.Copy()
		newInitiatorUser.Role = UserRoleAdmin
		account.Users[initiatorUser.Id] = newInitiatorUser
		return true
	}
	return false
}

// getUserInfo retrieves the UserInfo for a given User and Account.
// If the AccountManager has a non-nil idpManager and the User is not a service user,
// it will attempt to look up the UserData from the cache.
func getUserInfo(ctx context.Context, am *DefaultAccountManager, user *User, accountID string) (*UserInfo, error) {
	settings, err := am.Store.GetAccountSettings(ctx, LockingStrengthShare, accountID)
	if err != nil {
		return nil, err
	}

	if !isNil(am.idpManager) && !user.IsServiceUser {
		userData, err := am.lookupUserInCache(ctx, user.Id, accountID)
		if err != nil {
			return nil, err
		}
		return user.ToUserInfo(userData, settings)
	}
	return user.ToUserInfo(nil, settings)
}

// validateUserUpdate validates the update operation for a user.
func validateUserUpdate(account *Account, initiatorUser, oldUser, update *User) error {
	if initiatorUser.HasAdminPower() && initiatorUser.Id == update.Id && oldUser.Blocked != update.Blocked {
		return status.Errorf(status.PermissionDenied, "admins can't block or unblock themselves")
	}
	if initiatorUser.HasAdminPower() && initiatorUser.Id == update.Id && update.Role != initiatorUser.Role {
		return status.Errorf(status.PermissionDenied, "admins can't change their role")
	}
	if initiatorUser.Role == UserRoleAdmin && oldUser.Role == UserRoleOwner && update.Role != oldUser.Role {
		return status.Errorf(status.PermissionDenied, "only owners can remove owner role from their user")
	}
	if initiatorUser.Role == UserRoleAdmin && oldUser.Role == UserRoleOwner && update.IsBlocked() && !oldUser.IsBlocked() {
		return status.Errorf(status.PermissionDenied, "unable to block owner user")
	}
	if initiatorUser.Role == UserRoleAdmin && update.Role == UserRoleOwner && update.Role != oldUser.Role {
		return status.Errorf(status.PermissionDenied, "only owners can add owner role to other users")
	}
	if oldUser.IsServiceUser && update.Role == UserRoleOwner {
		return status.Errorf(status.PermissionDenied, "can't update a service user with owner role")
	}

	for _, newGroupID := range update.AutoGroups {
		group, ok := account.Groups[newGroupID]
		if !ok {
			return status.Errorf(status.InvalidArgument, "provided group ID %s in the user %s update doesn't exist",
				newGroupID, update.Id)
		}
		if group.Name == "All" {
			return status.Errorf(status.InvalidArgument, "can't add All group to the user")
		}
	}

	return nil
}

// GetOrCreateAccountByUser returns an existing account for a given user id or creates a new one if doesn't exist
func (am *DefaultAccountManager) GetOrCreateAccountByUser(ctx context.Context, userID, domain string) (*Account, error) {
	start := time.Now()
	unlock := am.Store.AcquireGlobalLock(ctx)
	defer unlock()
	log.WithContext(ctx).Debugf("Acquired global lock in %s for user %s", time.Since(start), userID)

	lowerDomain := strings.ToLower(domain)

	account, err := am.Store.GetAccountByUser(ctx, userID)
	if err != nil {
		if s, ok := status.FromError(err); ok && s.Type() == status.NotFound {
			account, err = am.newAccount(ctx, userID, lowerDomain)
			if err != nil {
				return nil, err
			}
			err = am.Store.SaveAccount(ctx, account)
			if err != nil {
				return nil, err
			}
		} else {
			// other error
			return nil, err
		}
	}

	userObj := account.Users[userID]

	if lowerDomain != "" && account.Domain != lowerDomain && userObj.Role == UserRoleOwner {
		account.Domain = lowerDomain
		err = am.Store.SaveAccount(ctx, account)
		if err != nil {
			return nil, status.Errorf(status.Internal, "failed updating account with domain")
		}
	}

	return account, nil
}

// GetUsersFromAccount performs a batched request for users from IDP by account ID apply filter on what data to return
// based on provided user role.
func (am *DefaultAccountManager) GetUsersFromAccount(ctx context.Context, accountID, userID string) ([]*UserInfo, error) {
	accountUsers, err := am.Store.GetAccountUsers(ctx, LockingStrengthShare, accountID)
	if err != nil {
		return nil, err
	}

	user, err := am.Store.GetUserByUserID(ctx, LockingStrengthShare, userID)
	if err != nil {
		return nil, err
	}

	if user.AccountID != accountID {
		return nil, status.NewUserNotPartOfAccountError()
	}

	queriedUsers := make([]*idp.UserData, 0)
	if !isNil(am.idpManager) {
		users := make(map[string]userLoggedInOnce, len(accountUsers))
		usersFromIntegration := make([]*idp.UserData, 0)
		for _, user := range accountUsers {
			if user.Issued == UserIssuedIntegration {
				key := user.IntegrationReference.CacheKey(accountID, user.Id)
				info, err := am.externalCacheManager.Get(am.ctx, key)
				if err != nil {
					log.WithContext(ctx).Infof("Get ExternalCache for key: %s, error: %s", key, err)
					users[user.Id] = true
					continue
				}
				usersFromIntegration = append(usersFromIntegration, info)
				continue
			}
			if !user.IsServiceUser {
				users[user.Id] = userLoggedInOnce(!user.LastLogin.IsZero())
			}
		}
		queriedUsers, err = am.lookupCache(ctx, users, accountID)
		if err != nil {
			return nil, err
		}
		log.WithContext(ctx).Debugf("Got %d users from ExternalCache for account %s", len(usersFromIntegration), accountID)
		log.WithContext(ctx).Debugf("Got %d users from InternalCache for account %s", len(queriedUsers), accountID)
		queriedUsers = append(queriedUsers, usersFromIntegration...)
	}

	userInfos := make([]*UserInfo, 0)

	settings, err := am.Store.GetAccountSettings(ctx, LockingStrengthShare, accountID)
	if err != nil {
		return nil, err
	}

	// in case of self-hosted, or IDP doesn't return anything, we will return the locally stored userInfo
	if len(queriedUsers) == 0 {
		for _, accountUser := range accountUsers {
			if user.IsRegularUser() && user.Id != accountUser.Id {
				// if user is not an admin then show only current user and do not show other users
				continue
			}
			info, err := accountUser.ToUserInfo(nil, settings)
			if err != nil {
				return nil, err
			}
			userInfos = append(userInfos, info)
		}
		return userInfos, nil
	}

	for _, localUser := range accountUsers {
		if user.IsRegularUser() && user.Id != localUser.Id {
			// if user is not an admin then show only current user and do not show other users
			continue
		}

		var info *UserInfo
		if queriedUser, contains := findUserInIDPUserdata(localUser.Id, queriedUsers); contains {
			info, err = localUser.ToUserInfo(queriedUser, settings)
			if err != nil {
				return nil, err
			}
		} else {
			name := ""
			if localUser.IsServiceUser {
				name = localUser.ServiceUserName
			}

			dashboardViewPermissions := "full"
			if !localUser.HasAdminPower() {
				dashboardViewPermissions = "limited"
				if settings.RegularUsersViewBlocked {
					dashboardViewPermissions = "blocked"
				}
			}

			info = &UserInfo{
				ID:            localUser.Id,
				Email:         "",
				Name:          name,
				Role:          string(localUser.Role),
				AutoGroups:    localUser.AutoGroups,
				Status:        string(UserStatusActive),
				IsServiceUser: localUser.IsServiceUser,
				NonDeletable:  localUser.NonDeletable,
				Permissions:   UserPermissions{DashboardView: dashboardViewPermissions},
			}
		}
		userInfos = append(userInfos, info)
	}

	return userInfos, nil
}

// expireAndUpdatePeers expires all peers of the given user and updates them in the account
func (am *DefaultAccountManager) expireAndUpdatePeers(ctx context.Context, accountID string, peers []*nbpeer.Peer) error {
	var peerIDs []string
	for _, peer := range peers {
		if peer.Status.LoginExpired {
			continue
		}
		peerIDs = append(peerIDs, peer.ID)
		peer.MarkLoginExpired(true)

		if err := am.Store.SavePeerStatus(ctx, LockingStrengthUpdate, accountID, peer.ID, *peer.Status); err != nil {
			return err
		}
		am.StoreEvent(
			ctx,
			peer.UserID, peer.ID, accountID,
			activity.PeerLoginExpired, peer.EventMeta(am.GetDNSDomain()),
		)
	}

	if len(peerIDs) != 0 {
		// this will trigger peer disconnect from the management service
		am.peersUpdateManager.CloseChannels(ctx, peerIDs)
		am.updateAccountPeers(ctx, accountID)
	}
	return nil
}

func (am *DefaultAccountManager) deleteUserFromIDP(ctx context.Context, targetUserID, accountID string) error {
	if am.userDeleteFromIDPEnabled {
		log.WithContext(ctx).Debugf("user %s deleted from IdP", targetUserID)
		err := am.idpManager.DeleteUser(ctx, targetUserID)
		if err != nil {
			return fmt.Errorf("failed to delete user %s from IdP: %s", targetUserID, err)
		}
	} else {
		err := am.idpManager.UpdateUserAppMetadata(ctx, targetUserID, idp.AppMetadata{})
		if err != nil {
			return fmt.Errorf("failed to remove user %s app metadata in IdP: %s", targetUserID, err)
		}
	}
	err := am.removeUserFromCache(ctx, accountID, targetUserID)
	if err != nil {
		log.WithContext(ctx).Errorf("remove user from account (%q) cache failed with error: %v", accountID, err)
	}
	return nil
}

func (am *DefaultAccountManager) getEmailAndNameOfTargetUser(ctx context.Context, accountId, initiatorId, targetId string) (string, string, error) {
	userInfos, err := am.GetUsersFromAccount(ctx, accountId, initiatorId)
	if err != nil {
		return "", "", err
	}
	for _, ui := range userInfos {
		if ui.ID == targetId {
			return ui.Email, ui.Name, nil
		}
	}

	return "", "", fmt.Errorf("user info not found for user: %s", targetId)
}

// DeleteRegularUsers deletes regular users from an account.
// If an error occurs while deleting the user, the function skips it and continues deleting other users.
// Errors are collected and returned at the end.
func (am *DefaultAccountManager) DeleteRegularUsers(ctx context.Context, accountID, initiatorUserID string, targetUserIDs []string) error {
	initiatorUser, err := am.Store.GetUserByUserID(ctx, LockingStrengthShare, initiatorUserID)
	if err != nil {
		return err
	}

	if !initiatorUser.HasAdminPower() {
		return status.NewAdminPermissionError()
	}

	var allErrors error
	var updateAccountPeers bool

	for _, targetUserID := range targetUserIDs {
		if initiatorUserID == targetUserID {
			allErrors = errors.Join(allErrors, errors.New("self deletion is not allowed"))
			continue
		}

		targetUser, err := am.Store.GetUserByUserID(ctx, LockingStrengthShare, targetUserID)
		if err != nil {
			allErrors = errors.Join(allErrors, err)
			continue
		}

		if targetUser.Role == UserRoleOwner {
			allErrors = errors.Join(allErrors, fmt.Errorf("unable to delete a user: %s with owner role", targetUserID))
			continue
		}

		// disable deleting integration user if the initiator is not admin service user
		if targetUser.Issued == UserIssuedIntegration && !initiatorUser.IsServiceUser {
			allErrors = errors.Join(allErrors, errors.New("only integration service user can delete this user"))
			continue
		}

		userHadPeers, err := am.deleteRegularUser(ctx, accountID, initiatorUserID, targetUserID)
		if err != nil {
			allErrors = errors.Join(allErrors, err)
			continue
		}

		if userHadPeers {
			updateAccountPeers = true
		}
	}

	if updateAccountPeers {
		am.updateAccountPeers(ctx, accountID)
	}

	return allErrors
}

// deleteRegularUser deletes a specified user and their related peers from the account.
func (am *DefaultAccountManager) deleteRegularUser(ctx context.Context, accountID, initiatorUserID, targetUserID string) (bool, error) {
	tuEmail, tuName, err := am.getEmailAndNameOfTargetUser(ctx, accountID, initiatorUserID, targetUserID)
	if err != nil {
		log.WithContext(ctx).Errorf("failed to resolve email address: %s", err)
		return false, err
	}

	if !isNil(am.idpManager) {
		// Delete if the user already exists in the IdP. Necessary in cases where a user account
		// was created where a user account was provisioned but the user did not sign in
		_, err = am.idpManager.GetUserDataByID(ctx, targetUserID, idp.AppMetadata{WTAccountID: accountID})
		if err == nil {
			err = am.deleteUserFromIDP(ctx, targetUserID, accountID)
			if err != nil {
				log.WithContext(ctx).Debugf("failed to delete user from IDP: %s", targetUserID)
				return false, err
			}
		} else {
			log.WithContext(ctx).Debugf("skipped deleting user %s from IDP, error: %v", targetUserID, err)
		}
	}

	var addPeerRemovedEvents []func()
	var updateAccountPeers bool
	var targetUser *User

	err = am.Store.ExecuteInTransaction(ctx, func(transaction Store) error {
		targetUser, err = transaction.GetUserByUserID(ctx, LockingStrengthShare, targetUserID)
		if err != nil {
			return fmt.Errorf("failed to get user to delete: %w", err)
		}

		userPeers, err := transaction.GetUserPeers(ctx, LockingStrengthShare, accountID, targetUserID)
		if err != nil {
			return fmt.Errorf("failed to get user peers: %w", err)
		}

		if len(userPeers) > 0 {
			updateAccountPeers = true
			addPeerRemovedEvents, err = deletePeers(ctx, am, transaction, accountID, targetUserID, userPeers)
			if err != nil {
				return fmt.Errorf("failed to delete user peers: %w", err)
			}
		}

		if err = transaction.DeleteUser(ctx, LockingStrengthUpdate, accountID, targetUserID); err != nil {
			return fmt.Errorf("failed to delete user: %s %w", targetUserID, err)
		}

		return nil
	})
	if err != nil {
		return false, err
	}

	for _, addPeerRemovedEvent := range addPeerRemovedEvents {
		addPeerRemovedEvent()
	}
	meta := map[string]any{"name": tuName, "email": tuEmail, "created_at": targetUser.CreatedAt}
	am.StoreEvent(ctx, initiatorUserID, targetUser.Id, accountID, activity.UserDeleted, meta)

	return updateAccountPeers, nil
}

// updateUserPeersInGroups updates the user's peers in the specified groups by adding or removing them.
func (am *DefaultAccountManager) updateUserPeersInGroups(accountGroups map[string]*nbgroup.Group, peers []*nbpeer.Peer, groupsToAdd,
	groupsToRemove []string) (groupsToUpdate []*nbgroup.Group, err error) {

	if len(groupsToAdd) == 0 && len(groupsToRemove) == 0 {
		return
	}

	userPeerIDMap := make(map[string]struct{}, len(peers))
	for _, peer := range peers {
		userPeerIDMap[peer.ID] = struct{}{}
	}

	for _, gid := range groupsToAdd {
		group, ok := accountGroups[gid]
		if !ok {
			return nil, errors.New("group not found")
		}
		addUserPeersToGroup(userPeerIDMap, group)
		groupsToUpdate = append(groupsToUpdate, group)
	}

	for _, gid := range groupsToRemove {
		group, ok := accountGroups[gid]
		if !ok {
			return nil, errors.New("group not found")
		}
		removeUserPeersFromGroup(userPeerIDMap, group)
		groupsToUpdate = append(groupsToUpdate, group)
	}

	return groupsToUpdate, nil
}

// addUserPeersToGroup adds the user's peers to the group.
func addUserPeersToGroup(userPeerIDs map[string]struct{}, group *nbgroup.Group) {
	groupPeers := make(map[string]struct{}, len(group.Peers))
	for _, pid := range group.Peers {
		groupPeers[pid] = struct{}{}
	}

	for pid := range userPeerIDs {
		groupPeers[pid] = struct{}{}
	}

	group.Peers = make([]string, 0, len(groupPeers))
	for pid := range groupPeers {
		group.Peers = append(group.Peers, pid)
	}
}

// removeUserPeersFromGroup removes user's peers from the group.
func removeUserPeersFromGroup(userPeerIDs map[string]struct{}, group *nbgroup.Group) {
	// skip removing peers from group All
	if group.Name == "All" {
		return
	}

	updatedPeers := make([]string, 0, len(group.Peers))
	for _, pid := range group.Peers {
		if _, found := userPeerIDs[pid]; !found {
			updatedPeers = append(updatedPeers, pid)
		}
	}

	group.Peers = updatedPeers
}

func findUserInIDPUserdata(userID string, userData []*idp.UserData) (*idp.UserData, bool) {
	for _, user := range userData {
		if user.ID == userID {
			return user, true
		}
	}
	return nil, false
}

// areUsersLinkedToPeers checks if any of the given userIDs are linked to any of the peers in the account.
func areUsersLinkedToPeers(account *Account, userIDs []string) bool {
	for _, peer := range account.Peers {
		if slices.Contains(userIDs, peer.UserID) {
			return true
		}
	}
	return false
}

func validateUserInvite(invite *UserInfo) error {
	if invite == nil {
		return fmt.Errorf("provided user update is nil")
	}

	invitedRole := StrRoleToUserRole(invite.Role)

	switch {
	case invite.Name == "":
		return status.Errorf(status.InvalidArgument, "name can't be empty")
	case invite.Email == "":
		return status.Errorf(status.InvalidArgument, "email can't be empty")
	case invitedRole == UserRoleOwner:
		return status.Errorf(status.InvalidArgument, "can't invite a user with owner role")
	default:
	}

	return nil
}
