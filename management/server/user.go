package server

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"

	nbcontext "github.com/netbirdio/netbird/management/server/context"
	"github.com/netbirdio/netbird/shared/auth"

	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/idp/dex"
	"github.com/netbirdio/netbird/management/server/activity"
	"github.com/netbirdio/netbird/management/server/idp"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/permissions/modules"
	"github.com/netbirdio/netbird/management/server/permissions/operations"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/management/server/users"
	"github.com/netbirdio/netbird/management/server/util"
	"github.com/netbirdio/netbird/shared/management/status"
)

// createServiceUser creates a new service user under the given account.
func (am *DefaultAccountManager) createServiceUser(ctx context.Context, accountID string, initiatorUserID string, role types.UserRole, serviceUserName string, nonDeletable bool, autoGroups []string) (*types.UserInfo, error) {
	allowed, err := am.permissionsManager.ValidateUserPermissions(ctx, accountID, initiatorUserID, modules.Users, operations.Create)
	if err != nil {
		return nil, status.NewPermissionValidationError(err)
	}
	if !allowed {
		return nil, status.NewPermissionDeniedError()
	}

	if role == types.UserRoleOwner {
		return nil, status.NewServiceUserRoleInvalidError()
	}

	newUserID := uuid.New().String()
	newUser := types.NewUser(newUserID, role, true, nonDeletable, serviceUserName, autoGroups, types.UserIssuedAPI, "", "")
	newUser.AccountID = accountID
	log.WithContext(ctx).Debugf("New User: %v", newUser)

	if err = am.Store.SaveUser(ctx, newUser); err != nil {
		return nil, err
	}

	meta := map[string]any{"name": newUser.ServiceUserName}
	am.StoreEvent(ctx, initiatorUserID, newUser.Id, accountID, activity.ServiceUserCreated, meta)

	return &types.UserInfo{
		ID:            newUser.Id,
		Email:         "",
		Name:          newUser.ServiceUserName,
		Role:          string(newUser.Role),
		AutoGroups:    newUser.AutoGroups,
		Status:        string(types.UserStatusActive),
		IsServiceUser: true,
		LastLogin:     time.Time{},
		Issued:        types.UserIssuedAPI,
	}, nil
}

// CreateUser creates a new user under the given account. Effectively this is a user invite.
func (am *DefaultAccountManager) CreateUser(ctx context.Context, accountID, userID string, user *types.UserInfo) (*types.UserInfo, error) {
	if user.IsServiceUser {
		return am.createServiceUser(ctx, accountID, userID, types.StrRoleToUserRole(user.Role), user.Name, user.NonDeletable, user.AutoGroups)
	}
	return am.inviteNewUser(ctx, accountID, userID, user)
}

// inviteNewUser Invites a USer to a given account and creates reference in datastore
func (am *DefaultAccountManager) inviteNewUser(ctx context.Context, accountID, userID string, invite *types.UserInfo) (*types.UserInfo, error) {
	if am.idpManager == nil {
		return nil, status.Errorf(status.PreconditionFailed, "IdP manager must be enabled to send user invites")
	}

	if err := validateUserInvite(invite); err != nil {
		return nil, err
	}

	allowed, err := am.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, modules.Users, operations.Create)
	if err != nil {
		return nil, status.NewPermissionValidationError(err)
	}
	if !allowed {
		return nil, status.NewPermissionDeniedError()
	}

	initiatorUser, err := am.Store.GetUserByUserID(ctx, store.LockingStrengthNone, userID)
	if err != nil {
		return nil, err
	}

	inviterID := userID
	if initiatorUser.IsServiceUser {
		createdBy, err := am.Store.GetAccountCreatedBy(ctx, store.LockingStrengthNone, accountID)
		if err != nil {
			return nil, err
		}
		inviterID = createdBy
	}

	var idpUser *idp.UserData
	if IsEmbeddedIdp(am.idpManager) {
		idpUser, err = am.createEmbeddedIdpUser(ctx, accountID, inviterID, invite)
	} else {
		idpUser, err = am.createNewIdpUser(ctx, accountID, inviterID, invite)
	}
	if err != nil {
		return nil, err
	}

	newUser := &types.User{
		Id:                   idpUser.ID,
		AccountID:            accountID,
		Role:                 types.StrRoleToUserRole(invite.Role),
		AutoGroups:           invite.AutoGroups,
		Issued:               invite.Issued,
		IntegrationReference: invite.IntegrationReference,
		CreatedAt:            time.Now().UTC(),
		Email:                invite.Email,
		Name:                 invite.Name,
	}

	if err = am.Store.SaveUser(ctx, newUser); err != nil {
		return nil, err
	}

	if !IsEmbeddedIdp(am.idpManager) {
		_, err = am.refreshCache(ctx, accountID)
		if err != nil {
			return nil, err
		}
	}

	eventType := activity.UserInvited
	if IsEmbeddedIdp(am.idpManager) {
		eventType = activity.UserCreated
	}
	am.StoreEvent(ctx, userID, newUser.Id, accountID, eventType, nil)

	return newUser.ToUserInfo(idpUser)
}

// createNewIdpUser validates the invite and creates a new user in the IdP
func (am *DefaultAccountManager) createNewIdpUser(ctx context.Context, accountID string, inviterID string, invite *types.UserInfo) (*idp.UserData, error) {
	inviter, err := am.GetUserByID(ctx, inviterID)
	if err != nil {
		return nil, fmt.Errorf("failed to get inviter user: %w", err)
	}

	// inviterUser is the one who is inviting the new user
	inviterUser, err := am.lookupUserInCache(ctx, inviterID, inviter.AccountID)
	if err != nil {
		return nil, status.Errorf(status.NotFound, "inviter user with ID %s doesn't exist in IdP", inviterID)
	}

	if inviterUser == nil {
		return nil, status.Errorf(status.NotFound, "inviter user with ID %s is empty", inviterID)
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

	return am.idpManager.CreateUser(ctx, invite.Email, invite.Name, accountID, inviterUser.Email)
}

// createEmbeddedIdpUser validates the invite and creates a new user in the embedded IdP.
// Unlike createNewIdpUser, this method fetches user data directly from the database
// since the embedded IdP usage ensures the username and email are stored locally in the User table.
func (am *DefaultAccountManager) createEmbeddedIdpUser(ctx context.Context, accountID string, inviterID string, invite *types.UserInfo) (*idp.UserData, error) {
	if IsLocalAuthDisabled(ctx, am.idpManager) {
		return nil, status.Errorf(status.PreconditionFailed, "local user creation is disabled - use an external identity provider")
	}

	inviter, err := am.Store.GetUserByUserID(ctx, store.LockingStrengthNone, inviterID)
	if err != nil {
		return nil, fmt.Errorf("failed to get inviter user: %w", err)
	}

	if inviter == nil {
		return nil, status.Errorf(status.NotFound, "inviter user with ID %s doesn't exist", inviterID)
	}

	// check if the user is already registered with this email => reject
	existingUsers, err := am.Store.GetAccountUsers(ctx, store.LockingStrengthNone, accountID)
	if err != nil {
		return nil, err
	}

	for _, user := range existingUsers {
		if strings.EqualFold(user.Email, invite.Email) {
			return nil, status.Errorf(status.UserAlreadyExists, "can't invite a user with an existing NetBird account")
		}
	}

	return am.idpManager.CreateUser(ctx, invite.Email, invite.Name, accountID, inviter.Email)
}

func (am *DefaultAccountManager) GetUserByID(ctx context.Context, id string) (*types.User, error) {
	return am.Store.GetUserByUserID(ctx, store.LockingStrengthNone, id)
}

// GetUser looks up a user by provided auth.UserAuths.
// Expects account to have been created already.
func (am *DefaultAccountManager) GetUserFromUserAuth(ctx context.Context, userAuth auth.UserAuth) (*types.User, error) {
	user, err := am.Store.GetUserByUserID(ctx, store.LockingStrengthNone, userAuth.UserId)
	if err != nil {
		return nil, err
	}

	// this code should be outside of the am.GetAccountIDFromToken(claims) because this method is called also by the gRPC
	// server when user authenticates a device. And we need to separate the Dashboard login event from the Device login event.
	newLogin := user.LastDashboardLoginChanged(userAuth.LastLogin)

	err = am.Store.SaveUserLastLogin(ctx, userAuth.AccountId, userAuth.UserId, userAuth.LastLogin)
	if err != nil {
		log.WithContext(ctx).Debugf("failed to update user last login: %v", err)
	}

	if newLogin {
		meta := map[string]any{"timestamp": userAuth.LastLogin}
		am.StoreEvent(ctx, userAuth.UserId, userAuth.UserId, userAuth.AccountId, activity.DashboardLogin, meta)
	}

	return user, nil
}

// ListUsers returns lists of all users under the account.
// It doesn't populate user information such as email or name.
func (am *DefaultAccountManager) ListUsers(ctx context.Context, accountID string) ([]*types.User, error) {
	return am.Store.GetAccountUsers(ctx, store.LockingStrengthNone, accountID)
}

// UpdateUserPassword updates the password for a user in the embedded IdP.
// This is only available when the embedded IdP is enabled.
// Users can only change their own password.
func (am *DefaultAccountManager) UpdateUserPassword(ctx context.Context, accountID, currentUserID, targetUserID string, oldPassword, newPassword string) error {
	if !IsEmbeddedIdp(am.idpManager) {
		return status.Errorf(status.PreconditionFailed, "password change is only available with embedded identity provider")
	}

	if oldPassword == "" {
		return status.Errorf(status.InvalidArgument, "old password is required")
	}

	if newPassword == "" {
		return status.Errorf(status.InvalidArgument, "new password is required")
	}

	embeddedIdp, ok := am.idpManager.(*idp.EmbeddedIdPManager)
	if !ok {
		return status.Errorf(status.Internal, "failed to get embedded IdP manager")
	}

	err := embeddedIdp.UpdateUserPassword(ctx, currentUserID, targetUserID, oldPassword, newPassword)
	if err != nil {
		return status.Errorf(status.InvalidArgument, "failed to update password: %v", err)
	}

	am.StoreEvent(ctx, currentUserID, targetUserID, accountID, activity.UserPasswordChanged, nil)

	return nil
}

func (am *DefaultAccountManager) deleteServiceUser(ctx context.Context, accountID string, initiatorUserID string, targetUser *types.User) error {
	if err := am.Store.DeleteUser(ctx, accountID, targetUser.Id); err != nil {
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

	initiatorUser, err := am.Store.GetUserByUserID(ctx, store.LockingStrengthNone, initiatorUserID)
	if err != nil {
		return err
	}

	allowed, err := am.permissionsManager.ValidateUserPermissions(ctx, accountID, initiatorUserID, modules.Users, operations.Delete)
	if err != nil {
		return status.NewPermissionValidationError(err)
	}
	if !allowed {
		return status.NewPermissionDeniedError()
	}

	targetUser, err := am.Store.GetUserByUserID(ctx, store.LockingStrengthNone, targetUserID)
	if err != nil {
		return err
	}

	if targetUser.Role == types.UserRoleOwner {
		return status.NewOwnerDeletePermissionError()
	}

	// disable deleting integration user if the initiator is not admin service user
	if targetUser.Issued == types.UserIssuedIntegration && !initiatorUser.IsServiceUser {
		return status.Errorf(status.PermissionDenied, "only integration service user can delete this user")
	}

	// handle service user first and exit, no need to fetch extra data from IDP, etc
	if targetUser.IsServiceUser {
		if targetUser.NonDeletable {
			return status.Errorf(status.PermissionDenied, "service user is marked as non-deletable")
		}

		return am.deleteServiceUser(ctx, accountID, initiatorUserID, targetUser)
	}

	userInfo, err := am.getUserInfo(ctx, targetUser, accountID)
	if err != nil {
		return err
	}

	_, err = am.deleteRegularUser(ctx, accountID, initiatorUserID, userInfo)
	if err != nil {
		return err
	}

	return nil
}

// InviteUser resend invitations to users who haven't activated their accounts prior to the expiration period.
func (am *DefaultAccountManager) InviteUser(ctx context.Context, accountID string, initiatorUserID string, targetUserID string) error {
	if am.idpManager == nil {
		return status.Errorf(status.PreconditionFailed, "IdP manager must be enabled to send user invites")
	}

	allowed, err := am.permissionsManager.ValidateUserPermissions(ctx, accountID, initiatorUserID, modules.Users, operations.Create)
	if err != nil {
		return status.NewPermissionValidationError(err)
	}
	if !allowed {
		return status.NewPermissionDeniedError()
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
func (am *DefaultAccountManager) CreatePAT(ctx context.Context, accountID string, initiatorUserID string, targetUserID string, tokenName string, expiresIn int) (*types.PersonalAccessTokenGenerated, error) {
	if tokenName == "" {
		return nil, status.Errorf(status.InvalidArgument, "token name can't be empty")
	}

	if expiresIn < 1 || expiresIn > 365 {
		return nil, status.Errorf(status.InvalidArgument, "expiration has to be between 1 and 365")
	}

	allowed, err := am.permissionsManager.ValidateUserPermissions(ctx, accountID, initiatorUserID, modules.Pats, operations.Create)
	if err != nil {
		return nil, status.NewPermissionValidationError(err)
	}
	if !allowed {
		return nil, status.NewPermissionDeniedError()
	}

	initiatorUser, err := am.Store.GetUserByUserID(ctx, store.LockingStrengthNone, initiatorUserID)
	if err != nil {
		return nil, err
	}

	targetUser, err := am.Store.GetUserByUserID(ctx, store.LockingStrengthNone, targetUserID)
	if err != nil {
		return nil, err
	}

	// @note this is essential to prevent non admin users with Pats create permission frpm creating one for a service user
	if initiatorUserID != targetUserID && !(initiatorUser.HasAdminPower() && targetUser.IsServiceUser) {
		return nil, status.NewAdminPermissionError()
	}

	pat, err := types.CreateNewPAT(tokenName, expiresIn, targetUserID, initiatorUser.Id)
	if err != nil {
		return nil, status.Errorf(status.Internal, "failed to create PAT: %v", err)
	}

	if err = am.Store.SavePAT(ctx, &pat.PersonalAccessToken); err != nil {
		return nil, err
	}

	meta := map[string]any{"name": pat.Name, "is_service_user": targetUser.IsServiceUser, "user_name": targetUser.ServiceUserName}
	am.StoreEvent(ctx, initiatorUserID, targetUserID, accountID, activity.PersonalAccessTokenCreated, meta)

	return pat, nil
}

// DeletePAT deletes a specific PAT from a user
func (am *DefaultAccountManager) DeletePAT(ctx context.Context, accountID string, initiatorUserID string, targetUserID string, tokenID string) error {
	allowed, err := am.permissionsManager.ValidateUserPermissions(ctx, accountID, initiatorUserID, modules.Pats, operations.Delete)
	if err != nil {
		return status.NewPermissionValidationError(err)
	}
	if !allowed {
		return status.NewPermissionDeniedError()
	}

	initiatorUser, err := am.Store.GetUserByUserID(ctx, store.LockingStrengthNone, initiatorUserID)
	if err != nil {
		return err
	}

	targetUser, err := am.Store.GetUserByUserID(ctx, store.LockingStrengthNone, targetUserID)
	if err != nil {
		return err
	}

	if initiatorUserID != targetUserID && !(initiatorUser.HasAdminPower() && targetUser.IsServiceUser) {
		return status.NewAdminPermissionError()
	}

	pat, err := am.Store.GetPATByID(ctx, store.LockingStrengthNone, targetUserID, tokenID)
	if err != nil {
		return err
	}

	if err = am.Store.DeletePAT(ctx, targetUserID, tokenID); err != nil {
		return err
	}

	meta := map[string]any{"name": pat.Name, "is_service_user": targetUser.IsServiceUser, "user_name": targetUser.ServiceUserName}
	am.StoreEvent(ctx, initiatorUserID, targetUserID, accountID, activity.PersonalAccessTokenDeleted, meta)

	return nil
}

// GetPAT returns a specific PAT from a user
func (am *DefaultAccountManager) GetPAT(ctx context.Context, accountID string, initiatorUserID string, targetUserID string, tokenID string) (*types.PersonalAccessToken, error) {
	allowed, err := am.permissionsManager.ValidateUserPermissions(ctx, accountID, initiatorUserID, modules.Pats, operations.Read)
	if err != nil {
		return nil, status.NewPermissionValidationError(err)
	}
	if !allowed {
		return nil, status.NewPermissionDeniedError()
	}

	initiatorUser, err := am.Store.GetUserByUserID(ctx, store.LockingStrengthNone, initiatorUserID)
	if err != nil {
		return nil, err
	}

	targetUser, err := am.Store.GetUserByUserID(ctx, store.LockingStrengthNone, targetUserID)
	if err != nil {
		return nil, err
	}

	if initiatorUserID != targetUserID && !(initiatorUser.HasAdminPower() && targetUser.IsServiceUser) {
		return nil, status.NewAdminPermissionError()
	}

	return am.Store.GetPATByID(ctx, store.LockingStrengthNone, targetUserID, tokenID)
}

// GetAllPATs returns all PATs for a user
func (am *DefaultAccountManager) GetAllPATs(ctx context.Context, accountID string, initiatorUserID string, targetUserID string) ([]*types.PersonalAccessToken, error) {
	allowed, err := am.permissionsManager.ValidateUserPermissions(ctx, accountID, initiatorUserID, modules.Pats, operations.Read)
	if err != nil {
		return nil, status.NewPermissionValidationError(err)
	}
	if !allowed {
		return nil, status.NewPermissionDeniedError()
	}

	initiatorUser, err := am.Store.GetUserByUserID(ctx, store.LockingStrengthNone, initiatorUserID)
	if err != nil {
		return nil, err
	}

	targetUser, err := am.Store.GetUserByUserID(ctx, store.LockingStrengthNone, targetUserID)
	if err != nil {
		return nil, err
	}

	if initiatorUserID != targetUserID && !(initiatorUser.HasAdminPower() && targetUser.IsServiceUser) {
		return nil, status.NewAdminPermissionError()
	}

	return am.Store.GetUserPATs(ctx, store.LockingStrengthNone, targetUserID)
}

// SaveUser saves updates to the given user. If the user doesn't exist, it will throw status.NotFound error.
func (am *DefaultAccountManager) SaveUser(ctx context.Context, accountID, initiatorUserID string, update *types.User) (*types.UserInfo, error) {
	return am.SaveOrAddUser(ctx, accountID, initiatorUserID, update, false) // false means do not create user and throw status.NotFound
}

// SaveOrAddUser updates the given user. If addIfNotExists is set to true it will add user when no exist
// Only User.AutoGroups, User.Role, and User.Blocked fields are allowed to be updated for now.
func (am *DefaultAccountManager) SaveOrAddUser(ctx context.Context, accountID, initiatorUserID string, update *types.User, addIfNotExists bool) (*types.UserInfo, error) {
	updatedUsers, err := am.SaveOrAddUsers(ctx, accountID, initiatorUserID, []*types.User{update}, addIfNotExists)
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
func (am *DefaultAccountManager) SaveOrAddUsers(ctx context.Context, accountID, initiatorUserID string, updates []*types.User, addIfNotExists bool) ([]*types.UserInfo, error) {
	if len(updates) == 0 {
		return nil, nil //nolint:nilnil
	}

	allowed, err := am.permissionsManager.ValidateUserPermissions(ctx, accountID, initiatorUserID, modules.Users, operations.Create) // TODO: split by Create and Update
	if err != nil {
		return nil, status.NewPermissionValidationError(err)
	}
	if !allowed {
		return nil, status.NewPermissionDeniedError()
	}
	settings, err := am.Store.GetAccountSettings(ctx, store.LockingStrengthNone, accountID)
	if err != nil {
		return nil, err
	}

	var updateAccountPeers bool
	var peersToExpire []*nbpeer.Peer
	var addUserEvents []func()
	var usersToSave = make([]*types.User, 0, len(updates))

	groups, err := am.Store.GetAccountGroups(ctx, store.LockingStrengthNone, accountID)
	if err != nil {
		return nil, fmt.Errorf("error getting account groups: %w", err)
	}

	groupsMap := make(map[string]*types.Group, len(groups))
	for _, group := range groups {
		groupsMap[group.ID] = group
	}

	var initiatorUser *types.User
	if initiatorUserID != activity.SystemInitiator {
		result, err := am.Store.GetUserByUserID(ctx, store.LockingStrengthNone, initiatorUserID)
		if err != nil {
			return nil, err
		}
		initiatorUser = result
	}

	var globalErr error
	for _, update := range updates {
		if update == nil {
			return nil, status.Errorf(status.InvalidArgument, "provided user update is nil")
		}

		err = am.Store.ExecuteInTransaction(ctx, func(transaction store.Store) error {
			_, updatedUser, userPeersToExpire, userEvents, err := am.processUserUpdate(
				ctx, transaction, groupsMap, accountID, initiatorUserID, initiatorUser, update, addIfNotExists, settings,
			)
			if err != nil {
				return fmt.Errorf("failed to process update for user %s: %w", update.Id, err)
			}

			updateAccountPeers = true

			err = transaction.SaveUser(ctx, updatedUser)
			if err != nil {
				return fmt.Errorf("failed to save updated user %s: %w", update.Id, err)
			}

			usersToSave = append(usersToSave, updatedUser)
			addUserEvents = append(addUserEvents, userEvents...)
			peersToExpire = append(peersToExpire, userPeersToExpire...)

			return nil
		})
		if err != nil {
			log.WithContext(ctx).Errorf("failed to save user %s: %s", update.Id, err)
			if len(updates) == 1 {
				return nil, err
			}
			globalErr = errors.Join(globalErr, err)
			// continue when updating multiple users
		}
	}

	var updatedUsersInfo = make([]*types.UserInfo, 0, len(usersToSave))

	userInfos, err := am.GetUsersFromAccount(ctx, accountID, initiatorUserID)
	if err != nil {
		return nil, err
	}

	for _, updatedUser := range usersToSave {
		updatedUserInfo, ok := userInfos[updatedUser.Id]
		if !ok || updatedUserInfo == nil {
			return nil, fmt.Errorf("failed to get user: %s updated user info", updatedUser.Id)
		}
		updatedUsersInfo = append(updatedUsersInfo, updatedUserInfo)
	}

	for _, addUserEvent := range addUserEvents {
		addUserEvent()
	}

	if len(peersToExpire) > 0 {
		if err := am.expireAndUpdatePeers(ctx, accountID, peersToExpire); err != nil {
			log.WithContext(ctx).Errorf("failed update expired peers: %s", err)
			return nil, err
		}
	} else if updateAccountPeers {
		if err = am.Store.IncrementNetworkSerial(ctx, accountID); err != nil {
			return nil, fmt.Errorf("failed to increment network serial: %w", err)
		}
		am.UpdateAccountPeers(ctx, accountID)
	}

	return updatedUsersInfo, globalErr
}

// prepareUserUpdateEvents prepares a list user update events based on the changes between the old and new user data.
func (am *DefaultAccountManager) prepareUserUpdateEvents(ctx context.Context, accountID string, initiatorUserID string, oldUser, newUser *types.User, transferredOwnerRole bool, isNewUser bool, removedGroupIDs, addedGroupIDs []string, tx store.Store) []func() {
	var eventsToStore []func()

	if isNewUser {
		eventsToStore = append(eventsToStore, func() {
			am.StoreEvent(ctx, initiatorUserID, newUser.Id, accountID, activity.UserCreated, nil)
		})
	}

	if oldUser.IsBlocked() != newUser.IsBlocked() {
		if newUser.IsBlocked() {
			eventsToStore = append(eventsToStore, func() {
				am.StoreEvent(ctx, initiatorUserID, oldUser.Id, accountID, activity.UserBlocked, nil)
			})
		} else {
			eventsToStore = append(eventsToStore, func() {
				am.StoreEvent(ctx, initiatorUserID, oldUser.Id, accountID, activity.UserUnblocked, nil)
			})
		}
	}

	switch {
	case transferredOwnerRole:
		eventsToStore = append(eventsToStore, func() {
			am.StoreEvent(ctx, initiatorUserID, oldUser.Id, accountID, activity.TransferredOwnerRole, nil)
		})
	case oldUser.Role != newUser.Role:
		eventsToStore = append(eventsToStore, func() {
			am.StoreEvent(ctx, initiatorUserID, oldUser.Id, accountID, activity.UserRoleUpdated, map[string]any{"role": newUser.Role})
		})
	}

	addedGroups, err := tx.GetGroupsByIDs(ctx, store.LockingStrengthNone, accountID, addedGroupIDs)
	if err != nil {
		log.WithContext(ctx).Errorf("failed to get added groups for user %s update event: %v", oldUser.Id, err)
	}

	for _, group := range addedGroups {
		meta := map[string]any{
			"group": group.Name, "group_id": group.ID,
			"is_service_user": oldUser.IsServiceUser, "user_name": oldUser.ServiceUserName,
		}
		eventsToStore = append(eventsToStore, func() {
			am.StoreEvent(ctx, initiatorUserID, oldUser.Id, accountID, activity.GroupAddedToUser, meta)
		})
	}

	removedGroups, err := tx.GetGroupsByIDs(ctx, store.LockingStrengthNone, accountID, removedGroupIDs)
	if err != nil {
		log.WithContext(ctx).Errorf("failed to get removed groups for user %s update event: %v", oldUser.Id, err)
	}
	for _, group := range removedGroups {
		meta := map[string]any{
			"group": group.Name, "group_id": group.ID,
			"is_service_user": oldUser.IsServiceUser, "user_name": oldUser.ServiceUserName,
		}
		eventsToStore = append(eventsToStore, func() {
			am.StoreEvent(ctx, initiatorUserID, oldUser.Id, accountID, activity.GroupRemovedFromUser, meta)
		})
	}

	return eventsToStore
}

func (am *DefaultAccountManager) processUserUpdate(ctx context.Context, transaction store.Store, groupsMap map[string]*types.Group,
	accountID, initiatorUserId string, initiatorUser, update *types.User, addIfNotExists bool, settings *types.Settings) (bool, *types.User, []*nbpeer.Peer, []func(), error) {

	if update == nil {
		return false, nil, nil, nil, status.Errorf(status.InvalidArgument, "provided user update is nil")
	}

	oldUser, isNewUser, err := getUserOrCreateIfNotExists(ctx, transaction, accountID, update, addIfNotExists)
	if err != nil {
		return false, nil, nil, nil, err
	}

	if err := validateUserUpdate(groupsMap, initiatorUser, oldUser, update); err != nil {
		return false, nil, nil, nil, err
	}

	// only auto groups, revoked status, and integration reference can be updated for now
	updatedUser := oldUser.Copy()
	updatedUser.Role = update.Role
	updatedUser.Blocked = update.Blocked
	updatedUser.AutoGroups = update.AutoGroups
	// these two fields can't be set via API, only via direct call to the method
	updatedUser.Issued = update.Issued
	updatedUser.IntegrationReference = update.IntegrationReference

	var transferredOwnerRole bool
	result, err := handleOwnerRoleTransfer(ctx, transaction, initiatorUser, update)
	if err != nil {
		return false, nil, nil, nil, err
	}
	transferredOwnerRole = result

	userPeers, err := transaction.GetUserPeers(ctx, store.LockingStrengthNone, updatedUser.AccountID, update.Id)
	if err != nil {
		return false, nil, nil, nil, err
	}

	var peersToExpire []*nbpeer.Peer

	if !oldUser.IsBlocked() && update.IsBlocked() {
		peersToExpire = userPeers
	}

	var removedGroups, addedGroups []string
	if update.AutoGroups != nil && settings.GroupsPropagationEnabled {
		removedGroups = util.Difference(oldUser.AutoGroups, update.AutoGroups)
		addedGroups = util.Difference(update.AutoGroups, oldUser.AutoGroups)
		for _, peer := range userPeers {
			for _, groupID := range removedGroups {
				if err := transaction.RemovePeerFromGroup(ctx, peer.ID, groupID); err != nil {
					return false, nil, nil, nil, fmt.Errorf("failed to remove peer %s from group %s: %w", peer.ID, groupID, err)
				}
			}
			for _, groupID := range addedGroups {
				if err := transaction.AddPeerToGroup(ctx, accountID, peer.ID, groupID); err != nil {
					return false, nil, nil, nil, fmt.Errorf("failed to add peer %s to group %s: %w", peer.ID, groupID, err)
				}
			}
		}
	}

	updateAccountPeers := len(userPeers) > 0
	userEventsToAdd := am.prepareUserUpdateEvents(ctx, updatedUser.AccountID, initiatorUserId, oldUser, updatedUser, transferredOwnerRole, isNewUser, removedGroups, addedGroups, transaction)

	return updateAccountPeers, updatedUser, peersToExpire, userEventsToAdd, nil
}

// getUserOrCreateIfNotExists retrieves the existing user or creates a new one if it doesn't exist.
func getUserOrCreateIfNotExists(ctx context.Context, transaction store.Store, accountID string, update *types.User, addIfNotExists bool) (*types.User, bool, error) {
	existingUser, err := transaction.GetUserByUserID(ctx, store.LockingStrengthNone, update.Id)
	if err != nil {
		if sErr, ok := status.FromError(err); ok && sErr.Type() == status.NotFound {
			if !addIfNotExists {
				return nil, false, status.Errorf(status.NotFound, "user to update doesn't exist: %s", update.Id)
			}
			update.AccountID = accountID
			return update, true, nil // use all fields from update if addIfNotExists is true
		}
		return nil, false, err
	}

	if existingUser.AccountID != accountID {
		return nil, false, status.Errorf(status.InvalidArgument, "user account ID mismatch")
	}

	return existingUser, false, nil
}

func handleOwnerRoleTransfer(ctx context.Context, transaction store.Store, initiatorUser, update *types.User) (bool, error) {
	if initiatorUser != nil && initiatorUser.Role == types.UserRoleOwner && initiatorUser.Id != update.Id && update.Role == types.UserRoleOwner {
		newInitiatorUser := initiatorUser.Copy()
		newInitiatorUser.Role = types.UserRoleAdmin

		if err := transaction.SaveUser(ctx, newInitiatorUser); err != nil {
			return false, err
		}
		return true, nil
	}
	return false, nil
}

// getUserInfo retrieves the UserInfo for a given User and Account.
// If the AccountManager has a non-nil idpManager and the User is not a service user,
// it will attempt to look up the UserData from the cache.
func (am *DefaultAccountManager) getUserInfo(ctx context.Context, user *types.User, accountID string) (*types.UserInfo, error) {
	if !isNil(am.idpManager) && !user.IsServiceUser && !IsEmbeddedIdp(am.idpManager) {
		userData, err := am.lookupUserInCache(ctx, user.Id, accountID)
		if err != nil {
			return nil, err
		}
		return user.ToUserInfo(userData)
	}

	userInfo, err := user.ToUserInfo(nil)
	if err != nil {
		return nil, err
	}

	// For embedded IDP users, extract the IdPID (connector ID) from the encoded user ID
	if IsEmbeddedIdp(am.idpManager) && !user.IsServiceUser {
		if _, connectorID, decodeErr := dex.DecodeDexUserID(user.Id); decodeErr == nil && connectorID != "" {
			userInfo.IdPID = connectorID
		}
	}

	return userInfo, nil
}

// validateUserUpdate validates the update operation for a user.
func validateUserUpdate(groupsMap map[string]*types.Group, initiatorUser, oldUser, update *types.User) error {
	if initiatorUser == nil {
		return nil
	}

	// @todo double check these
	if initiatorUser.HasAdminPower() && initiatorUser.Id == update.Id && oldUser.Blocked != update.Blocked {
		return status.Errorf(status.PermissionDenied, "admins can't block or unblock themselves")
	}
	if initiatorUser.HasAdminPower() && initiatorUser.Id == update.Id && update.Role != initiatorUser.Role {
		return status.Errorf(status.PermissionDenied, "admins can't change their role")
	}
	if initiatorUser.Role == types.UserRoleAdmin && oldUser.Role == types.UserRoleOwner && update.Role != oldUser.Role {
		return status.Errorf(status.PermissionDenied, "only owners can remove owner role from their user")
	}
	if initiatorUser.Role == types.UserRoleAdmin && oldUser.Role == types.UserRoleOwner && update.IsBlocked() && !oldUser.IsBlocked() {
		return status.Errorf(status.PermissionDenied, "unable to block owner user")
	}
	if initiatorUser.Role == types.UserRoleAdmin && update.Role == types.UserRoleOwner && update.Role != oldUser.Role {
		return status.Errorf(status.PermissionDenied, "only owners can add owner role to other users")
	}
	if oldUser.IsServiceUser && update.Role == types.UserRoleOwner {
		return status.Errorf(status.PermissionDenied, "can't update a service user with owner role")
	}

	for _, newGroupID := range update.AutoGroups {
		group, ok := groupsMap[newGroupID]
		if !ok {
			return status.Errorf(status.InvalidArgument, "provided group ID %s in the user %s update doesn't exist",
				newGroupID, update.Id)
		}
		if group.IsGroupAll() {
			return status.Errorf(status.InvalidArgument, "can't add All group to the user")
		}
	}

	return nil
}

// GetOrCreateAccountByUser returns an existing account for a given user id or creates a new one if doesn't exist
func (am *DefaultAccountManager) GetOrCreateAccountByUser(ctx context.Context, userAuth auth.UserAuth) (*types.Account, error) {
	userID := userAuth.UserId
	domain := userAuth.Domain

	start := time.Now()
	unlock := am.Store.AcquireGlobalLock(ctx)
	defer unlock()
	log.WithContext(ctx).Debugf("Acquired global lock in %s for user %s", time.Since(start), userID)

	lowerDomain := strings.ToLower(domain)

	account, err := am.Store.GetAccountByUser(ctx, userID)
	if err != nil {
		if s, ok := status.FromError(err); ok && s.Type() == status.NotFound {
			account, err = am.newAccount(ctx, userID, lowerDomain, userAuth.Email, userAuth.Name)
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

	if lowerDomain != "" && account.Domain != lowerDomain && userObj.Role == types.UserRoleOwner {
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
func (am *DefaultAccountManager) GetUsersFromAccount(ctx context.Context, accountID, initiatorUserID string) (map[string]*types.UserInfo, error) {
	allowed, err := am.permissionsManager.ValidateUserPermissions(ctx, accountID, initiatorUserID, modules.Users, operations.Read)
	if err != nil {
		return nil, status.NewPermissionValidationError(err)
	}

	var user *types.User
	if initiatorUserID != activity.SystemInitiator {
		result, err := am.Store.GetUserByUserID(ctx, store.LockingStrengthNone, initiatorUserID)
		if err != nil {
			return nil, fmt.Errorf("failed to get user: %w", err)
		}
		user = result
	}

	accountUsers := []*types.User{}
	switch {
	case allowed:
		start := time.Now()
		accountUsers, err = am.Store.GetAccountUsers(ctx, store.LockingStrengthNone, accountID)
		if err != nil {
			return nil, err
		}
		log.WithContext(ctx).Tracef("Got %d users from account %s after %s", len(accountUsers), accountID, time.Since(start))
	case user != nil && user.AccountID == accountID:
		accountUsers = append(accountUsers, user)
	default:
		return map[string]*types.UserInfo{}, nil
	}

	return am.BuildUserInfosForAccount(ctx, accountID, initiatorUserID, accountUsers)
}

// BuildUserInfosForAccount builds user info for the given account.
func (am *DefaultAccountManager) BuildUserInfosForAccount(ctx context.Context, accountID, _ string, accountUsers []*types.User) (map[string]*types.UserInfo, error) {
	var queriedUsers []*idp.UserData
	var err error

	// embedded IdP ensures that we have user data (email and name) stored in the database.
	if !isNil(am.idpManager) && !IsEmbeddedIdp(am.idpManager) {
		users := make(map[string]userLoggedInOnce, len(accountUsers))
		usersFromIntegration := make([]*idp.UserData, 0)
		filtered := make(map[string]*idp.UserData, len(accountUsers))
		log.WithContext(ctx).Tracef("Querying users from IDP for account %s", accountID)
		start := time.Now()

		integrationKeys := make(map[string]struct{})
		for _, user := range accountUsers {
			if user.Issued == types.UserIssuedIntegration {
				integrationKeys[user.IntegrationReference.CacheKey(accountID)] = struct{}{}
				continue
			}
			if !user.IsServiceUser {
				users[user.Id] = userLoggedInOnce(!user.GetLastLogin().IsZero())
			}
		}

		for key := range integrationKeys {
			usersData, err := am.externalCacheManager.GetUsers(am.ctx, key)
			if err != nil {
				log.WithContext(ctx).Debugf("GetUsers from ExternalCache for key: %s, error: %s", key, err)
				continue
			}
			for _, ud := range usersData {
				filtered[ud.ID] = ud
			}
		}

		for _, ud := range filtered {
			usersFromIntegration = append(usersFromIntegration, ud)
		}

		log.WithContext(ctx).Tracef("Got user info from external cache after %s", time.Since(start))
		start = time.Now()
		queriedUsers, err = am.lookupCache(ctx, users, accountID)
		log.WithContext(ctx).Tracef("Got user info from cache for %d users after %s", len(queriedUsers), time.Since(start))
		if err != nil {
			return nil, err
		}
		log.WithContext(ctx).Debugf("Got %d users from ExternalCache for account %s", len(usersFromIntegration), accountID)
		log.WithContext(ctx).Debugf("Got %d users from InternalCache for account %s", len(queriedUsers), accountID)
		queriedUsers = append(queriedUsers, usersFromIntegration...)
	}

	userInfosMap := make(map[string]*types.UserInfo)

	// in case of self-hosted, or IDP doesn't return anything, we will return the locally stored userInfo
	if len(queriedUsers) == 0 {
		for _, accountUser := range accountUsers {
			info, err := accountUser.ToUserInfo(nil)
			if err != nil {
				return nil, err
			}
			// Try to decode Dex user ID to extract the IdP ID (connector ID)
			if _, connectorID, decodeErr := dex.DecodeDexUserID(accountUser.Id); decodeErr == nil && connectorID != "" {
				info.IdPID = connectorID
			}
			userInfosMap[accountUser.Id] = info
		}

		return userInfosMap, nil
	}

	for _, localUser := range accountUsers {
		var info *types.UserInfo
		if queriedUser, contains := findUserInIDPUserdata(localUser.Id, queriedUsers); contains {
			info, err = localUser.ToUserInfo(queriedUser)
			if err != nil {
				return nil, err
			}
		} else {
			name := ""
			if localUser.IsServiceUser {
				name = localUser.ServiceUserName
			}

			info = &types.UserInfo{
				ID:            localUser.Id,
				Email:         localUser.Email,
				Name:          name,
				Role:          string(localUser.Role),
				AutoGroups:    localUser.AutoGroups,
				Status:        string(types.UserStatusActive),
				IsServiceUser: localUser.IsServiceUser,
				NonDeletable:  localUser.NonDeletable,
			}
		}
		// Try to decode Dex user ID to extract the IdP ID (connector ID)
		if _, connectorID, decodeErr := dex.DecodeDexUserID(localUser.Id); decodeErr == nil && connectorID != "" {
			info.IdPID = connectorID
		}
		userInfosMap[info.ID] = info
	}

	return userInfosMap, nil
}

// expireAndUpdatePeers expires all peers of the given user and updates them in the account
func (am *DefaultAccountManager) expireAndUpdatePeers(ctx context.Context, accountID string, peers []*nbpeer.Peer) error {
	log.WithContext(ctx).Debugf("Expiring %d peers for account %s", len(peers), accountID)
	settings, err := am.Store.GetAccountSettings(ctx, store.LockingStrengthNone, accountID)
	if err != nil {
		return err
	}
	dnsDomain := am.networkMapController.GetDNSDomain(settings)

	var peerIDs []string
	for _, peer := range peers {
		// nolint:staticcheck
		ctx = context.WithValue(ctx, nbcontext.PeerIDKey, peer.Key)

		if peer.UserID == "" {
			// we do not want to expire peers that are added via setup key
			continue
		}

		if peer.Status.LoginExpired {
			continue
		}
		peerIDs = append(peerIDs, peer.ID)
		peer.MarkLoginExpired(true)

		if err := am.Store.SavePeerStatus(ctx, accountID, peer.ID, *peer.Status); err != nil {
			return err
		}
		am.StoreEvent(
			ctx,
			peer.UserID, peer.ID, accountID,
			activity.PeerLoginExpired, peer.EventMeta(dnsDomain),
		)
	}

	if len(peerIDs) != 0 {
		if err := am.Store.IncrementNetworkSerial(ctx, accountID); err != nil {
			return err
		}
	}

	err = am.networkMapController.OnPeersUpdated(ctx, accountID, peerIDs)
	if err != nil {
		return fmt.Errorf("notify network map controller of peer update: %w", err)
	}

	if len(peerIDs) != 0 {
		// this will trigger peer disconnect from the management service
		log.Debugf("Expiring %d peers for account %s", len(peerIDs), accountID)
		am.networkMapController.DisconnectPeers(ctx, accountID, peerIDs)
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

// DeleteRegularUsers deletes regular users from an account.
// Note: This function does not acquire the global lock.
// It is the caller's responsibility to ensure proper locking is in place before invoking this method.
//
// If an error occurs while deleting the user, the function skips it and continues deleting other users.
// Errors are collected and returned at the end.
func (am *DefaultAccountManager) DeleteRegularUsers(ctx context.Context, accountID, initiatorUserID string, targetUserIDs []string, userInfos map[string]*types.UserInfo) error {
	allowed, err := am.permissionsManager.ValidateUserPermissions(ctx, accountID, initiatorUserID, modules.Users, operations.Delete)
	if err != nil {
		return status.NewPermissionValidationError(err)
	}
	if !allowed {
		return status.NewPermissionDeniedError()
	}

	initiatorUser, err := am.Store.GetUserByUserID(ctx, store.LockingStrengthNone, initiatorUserID)
	if err != nil {
		return err
	}

	var allErrors error

	for _, targetUserID := range targetUserIDs {
		if initiatorUserID == targetUserID {
			allErrors = errors.Join(allErrors, errors.New("self deletion is not allowed"))
			continue
		}

		targetUser, err := am.Store.GetUserByUserID(ctx, store.LockingStrengthNone, targetUserID)
		if err != nil {
			allErrors = errors.Join(allErrors, err)
			continue
		}

		if targetUser.Role == types.UserRoleOwner {
			allErrors = errors.Join(allErrors, fmt.Errorf("unable to delete a user: %s with owner role", targetUserID))
			continue
		}

		// disable deleting integration user if the initiator is not admin service user
		if targetUser.Issued == types.UserIssuedIntegration && !initiatorUser.IsServiceUser {
			allErrors = errors.Join(allErrors, errors.New("only integration service user can delete this user"))
			continue
		}

		userInfo, ok := userInfos[targetUserID]
		if !ok || userInfo == nil {
			allErrors = errors.Join(allErrors, fmt.Errorf("user info not found for user: %s", targetUserID))
			continue
		}

		_, err = am.deleteRegularUser(ctx, accountID, initiatorUserID, userInfo)
		if err != nil {
			allErrors = errors.Join(allErrors, err)
			continue
		}
	}

	return allErrors
}

// deleteRegularUser deletes a specified user and their related peers from the account.
func (am *DefaultAccountManager) deleteRegularUser(ctx context.Context, accountID, initiatorUserID string, targetUserInfo *types.UserInfo) (bool, error) {
	if !isNil(am.idpManager) {
		// Delete if the user already exists in the IdP. Necessary in cases where a user account
		// was created where a user account was provisioned but the user did not sign in
		_, err := am.idpManager.GetUserDataByID(ctx, targetUserInfo.ID, idp.AppMetadata{WTAccountID: accountID})
		if err == nil {
			err = am.deleteUserFromIDP(ctx, targetUserInfo.ID, accountID)
			if err != nil {
				log.WithContext(ctx).Debugf("failed to delete user from IDP: %s", targetUserInfo.ID)
				return false, err
			}
		} else {
			log.WithContext(ctx).Debugf("skipped deleting user %s from IDP, error: %v", targetUserInfo.ID, err)
		}
	}

	var addPeerRemovedEvents []func()
	var updateAccountPeers bool
	var userPeers []*nbpeer.Peer
	var targetUser *types.User
	var settings *types.Settings
	var err error

	err = am.Store.ExecuteInTransaction(ctx, func(transaction store.Store) error {
		targetUser, err = transaction.GetUserByUserID(ctx, store.LockingStrengthUpdate, targetUserInfo.ID)
		if err != nil {
			return fmt.Errorf("failed to get user to delete: %w", err)
		}

		settings, err = transaction.GetAccountSettings(ctx, store.LockingStrengthNone, accountID)
		if err != nil {
			return fmt.Errorf("failed to get account settings: %w", err)
		}

		userPeers, err = transaction.GetUserPeers(ctx, store.LockingStrengthNone, accountID, targetUserInfo.ID)
		if err != nil {
			return fmt.Errorf("failed to get user peers: %w", err)
		}

		if len(userPeers) > 0 {
			updateAccountPeers = true
			addPeerRemovedEvents, err = deletePeers(ctx, am, transaction, accountID, targetUserInfo.ID, userPeers, settings)
			if err != nil {
				return fmt.Errorf("failed to delete user peers: %w", err)
			}
		}

		if err = transaction.DeleteUser(ctx, accountID, targetUserInfo.ID); err != nil {
			return fmt.Errorf("failed to delete user: %s %w", targetUserInfo.ID, err)
		}

		return nil
	})
	if err != nil {
		return false, err
	}

	var peerIDs []string
	for _, peer := range userPeers {
		peerIDs = append(peerIDs, peer.ID)
		if err = am.integratedPeerValidator.PeerDeleted(ctx, accountID, peer.ID, settings.Extra); err != nil {
			log.WithContext(ctx).Errorf("failed to delete peer %s from integrated validator: %v", peer.ID, err)
		}
	}
	if err := am.networkMapController.OnPeersDeleted(ctx, accountID, peerIDs); err != nil {
		log.WithContext(ctx).Errorf("failed to delete peers %s from network map: %v", peerIDs, err)
	}

	for _, addPeerRemovedEvent := range addPeerRemovedEvents {
		addPeerRemovedEvent()
	}

	meta := map[string]any{"name": targetUserInfo.Name, "email": targetUserInfo.Email, "created_at": targetUser.CreatedAt, "issued": targetUser.Issued}
	am.StoreEvent(ctx, initiatorUserID, targetUser.Id, accountID, activity.UserDeleted, meta)

	return updateAccountPeers, nil
}

// GetOwnerInfo retrieves the owner information for a given account ID.
func (am *DefaultAccountManager) GetOwnerInfo(ctx context.Context, accountID string) (*types.UserInfo, error) {
	owner, err := am.Store.GetAccountOwner(ctx, store.LockingStrengthNone, accountID)
	if err != nil {
		return nil, err
	}

	if owner == nil {
		return nil, status.Errorf(status.NotFound, "owner not found")
	}

	userInfo, err := am.getUserInfo(ctx, owner, accountID)
	if err != nil {
		return nil, err
	}

	return userInfo, nil
}

func findUserInIDPUserdata(userID string, userData []*idp.UserData) (*idp.UserData, bool) {
	for _, user := range userData {
		if user.ID == userID {
			return user, true
		}
	}
	return nil, false
}

func validateUserInvite(invite *types.UserInfo) error {
	if invite == nil {
		return fmt.Errorf("provided user update is nil")
	}

	invitedRole := types.StrRoleToUserRole(invite.Role)

	switch {
	case invite.Name == "":
		return status.Errorf(status.InvalidArgument, "name can't be empty")
	case invite.Email == "":
		return status.Errorf(status.InvalidArgument, "email can't be empty")
	case invitedRole == types.UserRoleOwner:
		return status.Errorf(status.InvalidArgument, "can't invite a user with owner role")
	default:
	}

	return nil
}

// GetCurrentUserInfo retrieves the account's current user info and permissions
func (am *DefaultAccountManager) GetCurrentUserInfo(ctx context.Context, userAuth auth.UserAuth) (*users.UserInfoWithPermissions, error) {
	accountID, userID := userAuth.AccountId, userAuth.UserId

	user, err := am.Store.GetUserByUserID(ctx, store.LockingStrengthNone, userID)
	if err != nil {
		return nil, err
	}

	if user.IsBlocked() {
		return nil, status.NewUserBlockedError()
	}

	if user.IsServiceUser {
		return nil, status.NewPermissionDeniedError()
	}

	if err := am.permissionsManager.ValidateAccountAccess(ctx, accountID, user, false); err != nil {
		return nil, err
	}

	settings, err := am.Store.GetAccountSettings(ctx, store.LockingStrengthNone, accountID)
	if err != nil {
		return nil, err
	}

	userInfo, err := am.getUserInfo(ctx, user, accountID)
	if err != nil {
		return nil, err
	}

	userWithPermissions := &users.UserInfoWithPermissions{
		UserInfo:   userInfo,
		Restricted: !userAuth.IsChild && user.IsRestrictable() && settings.RegularUsersViewBlocked,
	}

	permissions, err := am.permissionsManager.GetPermissionsByRole(ctx, user.Role)
	if err == nil {
		userWithPermissions.Permissions = permissions
	}

	return userWithPermissions, nil
}

// ApproveUser approves a user that is pending approval
func (am *DefaultAccountManager) ApproveUser(ctx context.Context, accountID, initiatorUserID, targetUserID string) (*types.UserInfo, error) {
	allowed, err := am.permissionsManager.ValidateUserPermissions(ctx, accountID, initiatorUserID, modules.Users, operations.Update)
	if err != nil {
		return nil, status.NewPermissionValidationError(err)
	}
	if !allowed {
		return nil, status.NewPermissionDeniedError()
	}

	user, err := am.Store.GetUserByUserID(ctx, store.LockingStrengthNone, targetUserID)
	if err != nil {
		return nil, err
	}

	if user.AccountID != accountID {
		return nil, status.NewUserNotFoundError(targetUserID)
	}

	if !user.PendingApproval {
		return nil, status.Errorf(status.InvalidArgument, "user %s is not pending approval", targetUserID)
	}

	user.Blocked = false
	user.PendingApproval = false

	err = am.Store.SaveUser(ctx, user)
	if err != nil {
		return nil, err
	}

	am.StoreEvent(ctx, initiatorUserID, targetUserID, accountID, activity.UserApproved, nil)

	userInfo, err := am.getUserInfo(ctx, user, accountID)
	if err != nil {
		return nil, err
	}

	return userInfo, nil
}

// RejectUser rejects a user that is pending approval by deleting them
func (am *DefaultAccountManager) RejectUser(ctx context.Context, accountID, initiatorUserID, targetUserID string) error {
	allowed, err := am.permissionsManager.ValidateUserPermissions(ctx, accountID, initiatorUserID, modules.Users, operations.Delete)
	if err != nil {
		return status.NewPermissionValidationError(err)
	}
	if !allowed {
		return status.NewPermissionDeniedError()
	}

	user, err := am.Store.GetUserByUserID(ctx, store.LockingStrengthNone, targetUserID)
	if err != nil {
		return err
	}

	if user.AccountID != accountID {
		return status.NewUserNotFoundError(targetUserID)
	}

	if !user.PendingApproval {
		return status.Errorf(status.InvalidArgument, "user %s is not pending approval", targetUserID)
	}

	err = am.DeleteUser(ctx, accountID, initiatorUserID, targetUserID)
	if err != nil {
		return err
	}

	am.StoreEvent(ctx, initiatorUserID, targetUserID, accountID, activity.UserRejected, nil)

	return nil
}

// CreateUserInvite creates an invite link for a new user in the embedded IdP.
// The user is NOT created until the invite is accepted.
func (am *DefaultAccountManager) CreateUserInvite(ctx context.Context, accountID, initiatorUserID string, invite *types.UserInfo, expiresIn int) (*types.UserInvite, error) {
	if !IsEmbeddedIdp(am.idpManager) {
		return nil, status.Errorf(status.PreconditionFailed, "invite links are only available with embedded identity provider")
	}

	if IsLocalAuthDisabled(ctx, am.idpManager) {
		return nil, status.Errorf(status.PreconditionFailed, "local user creation is disabled - use an external identity provider")
	}

	if err := validateUserInvite(invite); err != nil {
		return nil, err
	}

	allowed, err := am.permissionsManager.ValidateUserPermissions(ctx, accountID, initiatorUserID, modules.Users, operations.Create)
	if err != nil {
		return nil, status.NewPermissionValidationError(err)
	}
	if !allowed {
		return nil, status.NewPermissionDeniedError()
	}

	// Check if user already exists in NetBird DB
	existingUsers, err := am.Store.GetAccountUsers(ctx, store.LockingStrengthNone, accountID)
	if err != nil {
		return nil, err
	}
	for _, user := range existingUsers {
		if strings.EqualFold(user.Email, invite.Email) {
			return nil, status.Errorf(status.UserAlreadyExists, "user with this email already exists")
		}
	}

	// Check if invite already exists for this email
	existingInvite, err := am.Store.GetUserInviteByEmail(ctx, store.LockingStrengthNone, accountID, invite.Email)
	if err != nil {
		if sErr, ok := status.FromError(err); !ok || sErr.Type() != status.NotFound {
			return nil, fmt.Errorf("failed to check existing invites: %w", err)
		}
	}
	if existingInvite != nil {
		return nil, status.Errorf(status.AlreadyExists, "invite already exists for this email")
	}

	// Calculate expiration time
	if expiresIn <= 0 {
		expiresIn = types.DefaultInviteExpirationSeconds
	}

	if expiresIn < types.MinInviteExpirationSeconds {
		return nil, status.Errorf(status.InvalidArgument, "invite expiration must be at least 1 hour")
	}
	expiresAt := time.Now().UTC().Add(time.Duration(expiresIn) * time.Second)

	// Generate invite token
	inviteID := types.NewInviteID()
	hashedToken, plainToken, err := types.GenerateInviteToken()
	if err != nil {
		return nil, fmt.Errorf("failed to generate invite token: %w", err)
	}

	// Create the invite record (no user created yet)
	userInvite := &types.UserInviteRecord{
		ID:          inviteID,
		AccountID:   accountID,
		Email:       invite.Email,
		Name:        invite.Name,
		Role:        invite.Role,
		AutoGroups:  invite.AutoGroups,
		HashedToken: hashedToken,
		ExpiresAt:   expiresAt,
		CreatedAt:   time.Now().UTC(),
		CreatedBy:   initiatorUserID,
	}

	if err := am.Store.SaveUserInvite(ctx, userInvite); err != nil {
		return nil, err
	}

	am.StoreEvent(ctx, initiatorUserID, inviteID, accountID, activity.UserInviteLinkCreated, map[string]any{"email": invite.Email})

	return &types.UserInvite{
		UserInfo: &types.UserInfo{
			ID:         inviteID,
			Email:      invite.Email,
			Name:       invite.Name,
			Role:       invite.Role,
			AutoGroups: invite.AutoGroups,
			Status:     string(types.UserStatusInvited),
			Issued:     types.UserIssuedAPI,
		},
		InviteToken:     plainToken,
		InviteExpiresAt: expiresAt,
	}, nil
}

// GetUserInviteInfo retrieves invite information from a token (public endpoint).
func (am *DefaultAccountManager) GetUserInviteInfo(ctx context.Context, token string) (*types.UserInviteInfo, error) {
	if err := types.ValidateInviteToken(token); err != nil {
		return nil, status.Errorf(status.InvalidArgument, "invalid invite token: %v", err)
	}

	hashedToken := types.HashInviteToken(token)
	invite, err := am.Store.GetUserInviteByHashedToken(ctx, store.LockingStrengthNone, hashedToken)
	if err != nil {
		return nil, err
	}

	// Get the inviter's name
	invitedBy := ""
	if invite.CreatedBy != "" {
		inviter, err := am.Store.GetUserByUserID(ctx, store.LockingStrengthNone, invite.CreatedBy)
		if err == nil && inviter != nil {
			invitedBy = inviter.Name
		}
	}

	return &types.UserInviteInfo{
		Email:     invite.Email,
		Name:      invite.Name,
		ExpiresAt: invite.ExpiresAt,
		Valid:     !invite.IsExpired(),
		InvitedBy: invitedBy,
	}, nil
}

// ListUserInvites returns all invites for an account.
func (am *DefaultAccountManager) ListUserInvites(ctx context.Context, accountID, initiatorUserID string) ([]*types.UserInvite, error) {
	if !IsEmbeddedIdp(am.idpManager) {
		return nil, status.Errorf(status.PreconditionFailed, "invite links are only available with embedded identity provider")
	}

	allowed, err := am.permissionsManager.ValidateUserPermissions(ctx, accountID, initiatorUserID, modules.Users, operations.Read)
	if err != nil {
		return nil, status.NewPermissionValidationError(err)
	}
	if !allowed {
		return nil, status.NewPermissionDeniedError()
	}

	records, err := am.Store.GetAccountUserInvites(ctx, store.LockingStrengthNone, accountID)
	if err != nil {
		return nil, err
	}

	invites := make([]*types.UserInvite, 0, len(records))
	for _, record := range records {
		invites = append(invites, &types.UserInvite{
			UserInfo: &types.UserInfo{
				ID:         record.ID,
				Email:      record.Email,
				Name:       record.Name,
				Role:       record.Role,
				AutoGroups: record.AutoGroups,
			},
			InviteExpiresAt: record.ExpiresAt,
			InviteCreatedAt: record.CreatedAt,
		})
	}

	return invites, nil
}

// AcceptUserInvite accepts an invite and creates the user in both IdP and NetBird DB.
func (am *DefaultAccountManager) AcceptUserInvite(ctx context.Context, token, password string) error {
	if !IsEmbeddedIdp(am.idpManager) {
		return status.Errorf(status.PreconditionFailed, "invite links are only available with embedded identity provider")
	}

	if IsLocalAuthDisabled(ctx, am.idpManager) {
		return status.Errorf(status.PreconditionFailed, "local user creation is disabled - use an external identity provider")
	}

	if password == "" {
		return status.Errorf(status.InvalidArgument, "password is required")
	}

	if err := validatePassword(password); err != nil {
		return status.Errorf(status.InvalidArgument, "invalid password: %v", err)
	}

	if err := types.ValidateInviteToken(token); err != nil {
		return status.Errorf(status.InvalidArgument, "invalid invite token: %v", err)
	}

	hashedToken := types.HashInviteToken(token)
	invite, err := am.Store.GetUserInviteByHashedToken(ctx, store.LockingStrengthUpdate, hashedToken)
	if err != nil {
		return err
	}

	if invite.IsExpired() {
		return status.Errorf(status.InvalidArgument, "invite has expired")
	}

	// Create user in Dex with the provided password
	embeddedIdp, ok := am.idpManager.(*idp.EmbeddedIdPManager)
	if !ok {
		return status.Errorf(status.Internal, "failed to get embedded IdP manager")
	}

	idpUser, err := embeddedIdp.CreateUserWithPassword(ctx, invite.Email, password, invite.Name)
	if err != nil {
		return fmt.Errorf("failed to create user in IdP: %w", err)
	}

	// Create user in NetBird DB
	newUser := &types.User{
		Id:         idpUser.ID,
		AccountID:  invite.AccountID,
		Role:       types.StrRoleToUserRole(invite.Role),
		AutoGroups: invite.AutoGroups,
		Issued:     types.UserIssuedAPI,
		CreatedAt:  time.Now().UTC(),
		Email:      invite.Email,
		Name:       invite.Name,
	}

	err = am.Store.ExecuteInTransaction(ctx, func(transaction store.Store) error {
		if err := transaction.SaveUser(ctx, newUser); err != nil {
			return fmt.Errorf("failed to save user: %w", err)
		}
		if err := transaction.DeleteUserInvite(ctx, invite.ID); err != nil {
			return fmt.Errorf("failed to delete invite: %w", err)
		}
		return nil
	})
	if err != nil {
		// Best-effort rollback: delete the IdP user to avoid orphaned records
		if deleteErr := embeddedIdp.DeleteUser(ctx, idpUser.ID); deleteErr != nil {
			log.WithContext(ctx).WithError(deleteErr).Errorf("failed to rollback IdP user %s after transaction failure", idpUser.ID)
		}
		return err
	}

	am.StoreEvent(ctx, newUser.Id, newUser.Id, invite.AccountID, activity.UserInviteLinkAccepted, map[string]any{"email": invite.Email})

	return nil
}

// RegenerateUserInvite creates a new invite token for an existing invite, invalidating the previous one.
func (am *DefaultAccountManager) RegenerateUserInvite(ctx context.Context, accountID, initiatorUserID, inviteID string, expiresIn int) (*types.UserInvite, error) {
	if !IsEmbeddedIdp(am.idpManager) {
		return nil, status.Errorf(status.PreconditionFailed, "invite links are only available with embedded identity provider")
	}

	allowed, err := am.permissionsManager.ValidateUserPermissions(ctx, accountID, initiatorUserID, modules.Users, operations.Update)
	if err != nil {
		return nil, status.NewPermissionValidationError(err)
	}
	if !allowed {
		return nil, status.NewPermissionDeniedError()
	}

	// Get existing invite
	existingInvite, err := am.Store.GetUserInviteByID(ctx, store.LockingStrengthUpdate, accountID, inviteID)
	if err != nil {
		return nil, err
	}

	// Calculate expiration time
	if expiresIn <= 0 {
		expiresIn = types.DefaultInviteExpirationSeconds
	}
	if expiresIn < types.MinInviteExpirationSeconds {
		return nil, status.Errorf(status.InvalidArgument, "invite expiration must be at least 1 hour")
	}
	expiresAt := time.Now().UTC().Add(time.Duration(expiresIn) * time.Second)

	// Generate new invite token
	hashedToken, plainToken, err := types.GenerateInviteToken()
	if err != nil {
		return nil, fmt.Errorf("failed to generate invite token: %w", err)
	}

	// Update existing invite with new token and expiration
	existingInvite.HashedToken = hashedToken
	existingInvite.ExpiresAt = expiresAt
	existingInvite.CreatedBy = initiatorUserID

	err = am.Store.SaveUserInvite(ctx, existingInvite)
	if err != nil {
		return nil, err
	}

	am.StoreEvent(ctx, initiatorUserID, existingInvite.ID, accountID, activity.UserInviteLinkRegenerated, map[string]any{"email": existingInvite.Email})

	return &types.UserInvite{
		UserInfo: &types.UserInfo{
			ID:         existingInvite.ID,
			Email:      existingInvite.Email,
			Name:       existingInvite.Name,
			Role:       existingInvite.Role,
			AutoGroups: existingInvite.AutoGroups,
			Status:     string(types.UserStatusInvited),
			Issued:     types.UserIssuedAPI,
		},
		InviteToken:     plainToken,
		InviteExpiresAt: expiresAt,
	}, nil
}

// DeleteUserInvite deletes an existing invite by ID.
func (am *DefaultAccountManager) DeleteUserInvite(ctx context.Context, accountID, initiatorUserID, inviteID string) error {
	if !IsEmbeddedIdp(am.idpManager) {
		return status.Errorf(status.PreconditionFailed, "invite links are only available with embedded identity provider")
	}

	allowed, err := am.permissionsManager.ValidateUserPermissions(ctx, accountID, initiatorUserID, modules.Users, operations.Delete)
	if err != nil {
		return status.NewPermissionValidationError(err)
	}
	if !allowed {
		return status.NewPermissionDeniedError()
	}

	invite, err := am.Store.GetUserInviteByID(ctx, store.LockingStrengthUpdate, accountID, inviteID)
	if err != nil {
		return err
	}

	if err := am.Store.DeleteUserInvite(ctx, inviteID); err != nil {
		return err
	}

	am.StoreEvent(ctx, initiatorUserID, inviteID, accountID, activity.UserInviteLinkDeleted, map[string]any{"email": invite.Email})

	return nil
}

const minPasswordLength = 8

// validatePassword checks password strength requirements:
// - Minimum 8 characters
// - At least 1 digit
// - At least 1 uppercase letter
// - At least 1 special character
func validatePassword(password string) error {
	if len(password) < minPasswordLength {
		return errors.New("password must be at least 8 characters long")
	}

	var hasDigit, hasUpper, hasSpecial bool
	for _, c := range password {
		switch {
		case unicode.IsDigit(c):
			hasDigit = true
		case unicode.IsUpper(c):
			hasUpper = true
		case !unicode.IsLetter(c) && !unicode.IsDigit(c):
			hasSpecial = true
		}
	}

	var missing []string
	if !hasDigit {
		missing = append(missing, "one digit")
	}
	if !hasUpper {
		missing = append(missing, "one uppercase letter")
	}
	if !hasSpecial {
		missing = append(missing, "one special character")
	}

	if len(missing) > 0 {
		return errors.New("password must contain at least " + strings.Join(missing, ", "))
	}

	return nil
}
