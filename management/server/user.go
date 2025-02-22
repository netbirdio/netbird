package server

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/management/server/activity"
	nbContext "github.com/netbirdio/netbird/management/server/context"
	"github.com/netbirdio/netbird/management/server/idp"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/status"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/management/server/util"
)

// createServiceUser creates a new service user under the given account.
func (am *DefaultAccountManager) createServiceUser(ctx context.Context, accountID string, initiatorUserID string, role types.UserRole, serviceUserName string, nonDeletable bool, autoGroups []string) (*types.UserInfo, error) {
	unlock := am.Store.AcquireWriteLockByUID(ctx, accountID)
	defer unlock()

	initiatorUser, err := am.Store.GetUserByUserID(ctx, store.LockingStrengthShare, initiatorUserID)
	if err != nil {
		return nil, err
	}

	if initiatorUser.AccountID != accountID {
		return nil, status.NewUserNotPartOfAccountError()
	}

	if !initiatorUser.HasAdminPower() {
		return nil, status.NewAdminPermissionError()
	}

	if role == types.UserRoleOwner {
		return nil, status.NewServiceUserRoleInvalidError()
	}

	newUserID := uuid.New().String()
	newUser := types.NewUser(newUserID, role, true, nonDeletable, serviceUserName, autoGroups, types.UserIssuedAPI)
	newUser.AccountID = accountID
	log.WithContext(ctx).Debugf("New User: %v", newUser)

	if err = am.Store.SaveUser(ctx, store.LockingStrengthUpdate, newUser); err != nil {
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
	unlock := am.Store.AcquireWriteLockByUID(ctx, accountID)
	defer unlock()

	if am.idpManager == nil {
		return nil, status.Errorf(status.PreconditionFailed, "IdP manager must be enabled to send user invites")
	}

	if err := validateUserInvite(invite); err != nil {
		return nil, err
	}

	initiatorUser, err := am.Store.GetUserByUserID(ctx, store.LockingStrengthShare, userID)
	if err != nil {
		return nil, err
	}

	if initiatorUser.AccountID != accountID {
		return nil, status.NewUserNotPartOfAccountError()
	}

	inviterID := userID
	if initiatorUser.IsServiceUser {
		createdBy, err := am.Store.GetAccountCreatedBy(ctx, store.LockingStrengthShare, accountID)
		if err != nil {
			return nil, err
		}
		inviterID = createdBy
	}

	idpUser, err := am.createNewIdpUser(ctx, accountID, inviterID, invite)
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
	}

	settings, err := am.Store.GetAccountSettings(ctx, store.LockingStrengthShare, accountID)
	if err != nil {
		return nil, err
	}

	if err = am.Store.SaveUser(ctx, store.LockingStrengthUpdate, newUser); err != nil {
		return nil, err
	}

	_, err = am.refreshCache(ctx, accountID)
	if err != nil {
		return nil, err
	}

	am.StoreEvent(ctx, userID, newUser.Id, accountID, activity.UserInvited, nil)

	return newUser.ToUserInfo(idpUser, settings)
}

// createNewIdpUser validates the invite and creates a new user in the IdP
func (am *DefaultAccountManager) createNewIdpUser(ctx context.Context, accountID string, inviterID string, invite *types.UserInfo) (*idp.UserData, error) {
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

	return am.idpManager.CreateUser(ctx, invite.Email, invite.Name, accountID, inviterUser.Email)
}

func (am *DefaultAccountManager) GetUserByID(ctx context.Context, id string) (*types.User, error) {
	return am.Store.GetUserByUserID(ctx, store.LockingStrengthShare, id)
}

// GetUser looks up a user by provided nbContext.UserAuths.
// Expects account to have been created already.
func (am *DefaultAccountManager) GetUserFromUserAuth(ctx context.Context, userAuth nbContext.UserAuth) (*types.User, error) {
	user, err := am.Store.GetUserByUserID(ctx, store.LockingStrengthShare, userAuth.UserId)
	if err != nil {
		return nil, err
	}

	// this code should be outside of the am.GetAccountIDFromToken(claims) because this method is called also by the gRPC
	// server when user authenticates a device. And we need to separate the Dashboard login event from the Device login event.
	newLogin := user.LastDashboardLoginChanged(userAuth.LastLogin)

	err = am.Store.SaveUserLastLogin(ctx, userAuth.AccountId, userAuth.UserId, userAuth.LastLogin)
	if err != nil {
		log.WithContext(ctx).Errorf("failed saving user last login: %v", err)
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
	return am.Store.GetAccountUsers(ctx, store.LockingStrengthShare, accountID)
}

func (am *DefaultAccountManager) deleteServiceUser(ctx context.Context, accountID string, initiatorUserID string, targetUser *types.User) error {
	if err := am.Store.DeleteUser(ctx, store.LockingStrengthUpdate, accountID, targetUser.Id); err != nil {
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

	unlock := am.Store.AcquireWriteLockByUID(ctx, accountID)
	defer unlock()

	initiatorUser, err := am.Store.GetUserByUserID(ctx, store.LockingStrengthShare, initiatorUserID)
	if err != nil {
		return err
	}

	if initiatorUser.AccountID != accountID {
		return status.NewUserNotPartOfAccountError()
	}

	if !initiatorUser.HasAdminPower() {
		return status.NewAdminPermissionError()
	}

	targetUser, err := am.Store.GetUserByUserID(ctx, store.LockingStrengthShare, targetUserID)
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

	updateAccountPeers, err := am.deleteRegularUser(ctx, accountID, initiatorUserID, userInfo)
	if err != nil {
		return err
	}

	if updateAccountPeers {
		am.UpdateAccountPeers(ctx, accountID)
	}

	return nil
}

// InviteUser resend invitations to users who haven't activated their accounts prior to the expiration period.
func (am *DefaultAccountManager) InviteUser(ctx context.Context, accountID string, initiatorUserID string, targetUserID string) error {
	unlock := am.Store.AcquireWriteLockByUID(ctx, accountID)
	defer unlock()

	if am.idpManager == nil {
		return status.Errorf(status.PreconditionFailed, "IdP manager must be enabled to send user invites")
	}

	initiatorUser, err := am.Store.GetUserByUserID(ctx, store.LockingStrengthShare, initiatorUserID)
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
func (am *DefaultAccountManager) CreatePAT(ctx context.Context, accountID string, initiatorUserID string, targetUserID string, tokenName string, expiresIn int) (*types.PersonalAccessTokenGenerated, error) {
	unlock := am.Store.AcquireWriteLockByUID(ctx, accountID)
	defer unlock()

	if tokenName == "" {
		return nil, status.Errorf(status.InvalidArgument, "token name can't be empty")
	}

	if expiresIn < 1 || expiresIn > 365 {
		return nil, status.Errorf(status.InvalidArgument, "expiration has to be between 1 and 365")
	}

	initiatorUser, err := am.Store.GetUserByUserID(ctx, store.LockingStrengthShare, initiatorUserID)
	if err != nil {
		return nil, err
	}

	if initiatorUser.AccountID != accountID {
		return nil, status.NewUserNotPartOfAccountError()
	}

	targetUser, err := am.Store.GetUserByUserID(ctx, store.LockingStrengthShare, targetUserID)
	if err != nil {
		return nil, err
	}

	if initiatorUserID != targetUserID && !(initiatorUser.HasAdminPower() && targetUser.IsServiceUser) {
		return nil, status.NewAdminPermissionError()
	}

	pat, err := types.CreateNewPAT(tokenName, expiresIn, targetUserID, initiatorUser.Id)
	if err != nil {
		return nil, status.Errorf(status.Internal, "failed to create PAT: %v", err)
	}

	if err = am.Store.SavePAT(ctx, store.LockingStrengthUpdate, &pat.PersonalAccessToken); err != nil {
		return nil, err
	}

	meta := map[string]any{"name": pat.Name, "is_service_user": targetUser.IsServiceUser, "user_name": targetUser.ServiceUserName}
	am.StoreEvent(ctx, initiatorUserID, targetUserID, accountID, activity.PersonalAccessTokenCreated, meta)

	return pat, nil
}

// DeletePAT deletes a specific PAT from a user
func (am *DefaultAccountManager) DeletePAT(ctx context.Context, accountID string, initiatorUserID string, targetUserID string, tokenID string) error {
	unlock := am.Store.AcquireWriteLockByUID(ctx, accountID)
	defer unlock()

	initiatorUser, err := am.Store.GetUserByUserID(ctx, store.LockingStrengthShare, initiatorUserID)
	if err != nil {
		return err
	}

	if initiatorUser.AccountID != accountID {
		return status.NewUserNotPartOfAccountError()
	}

	if initiatorUserID != targetUserID && initiatorUser.IsRegularUser() {
		return status.NewAdminPermissionError()
	}

	pat, err := am.Store.GetPATByID(ctx, store.LockingStrengthShare, targetUserID, tokenID)
	if err != nil {
		return err
	}

	targetUser, err := am.Store.GetUserByUserID(ctx, store.LockingStrengthShare, targetUserID)
	if err != nil {
		return err
	}

	if err = am.Store.DeletePAT(ctx, store.LockingStrengthUpdate, targetUserID, tokenID); err != nil {
		return err
	}

	meta := map[string]any{"name": pat.Name, "is_service_user": targetUser.IsServiceUser, "user_name": targetUser.ServiceUserName}
	am.StoreEvent(ctx, initiatorUserID, targetUserID, accountID, activity.PersonalAccessTokenDeleted, meta)

	return nil
}

// GetPAT returns a specific PAT from a user
func (am *DefaultAccountManager) GetPAT(ctx context.Context, accountID string, initiatorUserID string, targetUserID string, tokenID string) (*types.PersonalAccessToken, error) {
	initiatorUser, err := am.Store.GetUserByUserID(ctx, store.LockingStrengthShare, initiatorUserID)
	if err != nil {
		return nil, err
	}

	if initiatorUser.AccountID != accountID {
		return nil, status.NewUserNotPartOfAccountError()
	}

	if initiatorUserID != targetUserID && initiatorUser.IsRegularUser() {
		return nil, status.NewAdminPermissionError()
	}

	return am.Store.GetPATByID(ctx, store.LockingStrengthShare, targetUserID, tokenID)
}

// GetAllPATs returns all PATs for a user
func (am *DefaultAccountManager) GetAllPATs(ctx context.Context, accountID string, initiatorUserID string, targetUserID string) ([]*types.PersonalAccessToken, error) {
	initiatorUser, err := am.Store.GetUserByUserID(ctx, store.LockingStrengthShare, initiatorUserID)
	if err != nil {
		return nil, err
	}

	if initiatorUser.AccountID != accountID {
		return nil, status.NewUserNotPartOfAccountError()
	}

	if initiatorUserID != targetUserID && initiatorUser.IsRegularUser() {
		return nil, status.NewAdminPermissionError()
	}

	return am.Store.GetUserPATs(ctx, store.LockingStrengthShare, targetUserID)
}

// SaveUser saves updates to the given user. If the user doesn't exist, it will throw status.NotFound error.
func (am *DefaultAccountManager) SaveUser(ctx context.Context, accountID, initiatorUserID string, update *types.User) (*types.UserInfo, error) {
	return am.SaveOrAddUser(ctx, accountID, initiatorUserID, update, false) // false means do not create user and throw status.NotFound
}

// SaveOrAddUser updates the given user. If addIfNotExists is set to true it will add user when no exist
// Only User.AutoGroups, User.Role, and User.Blocked fields are allowed to be updated for now.
func (am *DefaultAccountManager) SaveOrAddUser(ctx context.Context, accountID, initiatorUserID string, update *types.User, addIfNotExists bool) (*types.UserInfo, error) {
	unlock := am.Store.AcquireWriteLockByUID(ctx, accountID)
	defer unlock()

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

	initiatorUser, err := am.Store.GetUserByUserID(ctx, store.LockingStrengthShare, initiatorUserID)
	if err != nil {
		return nil, err
	}

	if initiatorUser.AccountID != accountID {
		return nil, status.NewUserNotPartOfAccountError()
	}

	if !initiatorUser.HasAdminPower() || initiatorUser.IsBlocked() {
		return nil, status.NewAdminPermissionError()
	}

	settings, err := am.Store.GetAccountSettings(ctx, store.LockingStrengthShare, accountID)
	if err != nil {
		return nil, err
	}

	var updateAccountPeers bool
	var peersToExpire []*nbpeer.Peer
	var addUserEvents []func()
	var usersToSave = make([]*types.User, 0, len(updates))

	groups, err := am.Store.GetAccountGroups(ctx, store.LockingStrengthShare, accountID)
	if err != nil {
		return nil, fmt.Errorf("error getting account groups: %w", err)
	}

	groupsMap := make(map[string]*types.Group, len(groups))
	for _, group := range groups {
		groupsMap[group.ID] = group
	}

	err = am.Store.ExecuteInTransaction(ctx, func(transaction store.Store) error {
		for _, update := range updates {
			if update == nil {
				return status.Errorf(status.InvalidArgument, "provided user update is nil")
			}

			userHadPeers, updatedUser, userPeersToExpire, userEvents, err := am.processUserUpdate(
				ctx, transaction, groupsMap, initiatorUser, update, addIfNotExists, settings,
			)
			if err != nil {
				return fmt.Errorf("failed to process user update: %w", err)
			}
			usersToSave = append(usersToSave, updatedUser)
			addUserEvents = append(addUserEvents, userEvents...)
			peersToExpire = append(peersToExpire, userPeersToExpire...)

			if userHadPeers {
				updateAccountPeers = true
			}
		}
		return transaction.SaveUsers(ctx, store.LockingStrengthUpdate, usersToSave)
	})
	if err != nil {
		return nil, err
	}

	var updatedUsersInfo = make([]*types.UserInfo, 0, len(updates))

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
	}

	if settings.GroupsPropagationEnabled && updateAccountPeers {
		if err = am.Store.IncrementNetworkSerial(ctx, store.LockingStrengthUpdate, accountID); err != nil {
			return nil, fmt.Errorf("failed to increment network serial: %w", err)
		}
		am.UpdateAccountPeers(ctx, accountID)
	}

	return updatedUsersInfo, nil
}

// prepareUserUpdateEvents prepares a list user update events based on the changes between the old and new user data.
func (am *DefaultAccountManager) prepareUserUpdateEvents(ctx context.Context, accountID string, initiatorUserID string, oldUser, newUser *types.User, transferredOwnerRole bool) []func() {
	var eventsToStore []func()

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

	return eventsToStore
}

func (am *DefaultAccountManager) processUserUpdate(ctx context.Context, transaction store.Store, groupsMap map[string]*types.Group,
	initiatorUser, update *types.User, addIfNotExists bool, settings *types.Settings) (bool, *types.User, []*nbpeer.Peer, []func(), error) {

	if update == nil {
		return false, nil, nil, nil, status.Errorf(status.InvalidArgument, "provided user update is nil")
	}

	oldUser, err := getUserOrCreateIfNotExists(ctx, transaction, update, addIfNotExists)
	if err != nil {
		return false, nil, nil, nil, err
	}

	if err := validateUserUpdate(groupsMap, initiatorUser, oldUser, update); err != nil {
		return false, nil, nil, nil, err
	}

	// only auto groups, revoked status, and integration reference can be updated for now
	updatedUser := oldUser.Copy()
	updatedUser.AccountID = initiatorUser.AccountID
	updatedUser.Role = update.Role
	updatedUser.Blocked = update.Blocked
	updatedUser.AutoGroups = update.AutoGroups
	// these two fields can't be set via API, only via direct call to the method
	updatedUser.Issued = update.Issued
	updatedUser.IntegrationReference = update.IntegrationReference

	transferredOwnerRole, err := handleOwnerRoleTransfer(ctx, transaction, initiatorUser, update)
	if err != nil {
		return false, nil, nil, nil, err
	}

	userPeers, err := transaction.GetUserPeers(ctx, store.LockingStrengthUpdate, updatedUser.AccountID, update.Id)
	if err != nil {
		return false, nil, nil, nil, err
	}

	var peersToExpire []*nbpeer.Peer

	if !oldUser.IsBlocked() && update.IsBlocked() {
		peersToExpire = userPeers
	}

	if update.AutoGroups != nil && settings.GroupsPropagationEnabled {
		removedGroups := util.Difference(oldUser.AutoGroups, update.AutoGroups)
		updatedGroups, err := updateUserPeersInGroups(groupsMap, userPeers, update.AutoGroups, removedGroups)
		if err != nil {
			return false, nil, nil, nil, fmt.Errorf("error modifying user peers in groups: %w", err)
		}

		if err = transaction.SaveGroups(ctx, store.LockingStrengthUpdate, updatedGroups); err != nil {
			return false, nil, nil, nil, fmt.Errorf("error saving groups: %w", err)
		}
	}

	updateAccountPeers := len(userPeers) > 0
	userEventsToAdd := am.prepareUserUpdateEvents(ctx, updatedUser.AccountID, initiatorUser.Id, oldUser, updatedUser, transferredOwnerRole)

	return updateAccountPeers, updatedUser, peersToExpire, userEventsToAdd, nil
}

// getUserOrCreateIfNotExists retrieves the existing user or creates a new one if it doesn't exist.
func getUserOrCreateIfNotExists(ctx context.Context, transaction store.Store, update *types.User, addIfNotExists bool) (*types.User, error) {
	existingUser, err := transaction.GetUserByUserID(ctx, store.LockingStrengthShare, update.Id)
	if err != nil {
		if sErr, ok := status.FromError(err); ok && sErr.Type() == status.NotFound {
			if !addIfNotExists {
				return nil, status.Errorf(status.NotFound, "user to update doesn't exist: %s", update.Id)
			}
			return update, nil // use all fields from update if addIfNotExists is true
		}
		return nil, err
	}
	return existingUser, nil
}

func handleOwnerRoleTransfer(ctx context.Context, transaction store.Store, initiatorUser, update *types.User) (bool, error) {
	if initiatorUser.Role == types.UserRoleOwner && initiatorUser.Id != update.Id && update.Role == types.UserRoleOwner {
		newInitiatorUser := initiatorUser.Copy()
		newInitiatorUser.Role = types.UserRoleAdmin

		if err := transaction.SaveUser(ctx, store.LockingStrengthUpdate, newInitiatorUser); err != nil {
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
	settings, err := am.Store.GetAccountSettings(ctx, store.LockingStrengthShare, accountID)
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
func validateUserUpdate(groupsMap map[string]*types.Group, initiatorUser, oldUser, update *types.User) error {
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
func (am *DefaultAccountManager) GetOrCreateAccountByUser(ctx context.Context, userID, domain string) (*types.Account, error) {
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
	accountUsers, err := am.Store.GetAccountUsers(ctx, store.LockingStrengthShare, accountID)
	if err != nil {
		return nil, err
	}

	initiatorUser, err := am.Store.GetUserByUserID(ctx, store.LockingStrengthShare, initiatorUserID)
	if err != nil {
		return nil, err
	}

	if initiatorUser.AccountID != accountID {
		return nil, status.NewUserNotPartOfAccountError()
	}

	return am.BuildUserInfosForAccount(ctx, accountID, initiatorUserID, accountUsers)
}

// BuildUserInfosForAccount builds user info for the given account.
func (am *DefaultAccountManager) BuildUserInfosForAccount(ctx context.Context, accountID, initiatorUserID string, accountUsers []*types.User) (map[string]*types.UserInfo, error) {
	var queriedUsers []*idp.UserData
	var err error

	initiatorUser, err := am.Store.GetUserByUserID(ctx, store.LockingStrengthShare, initiatorUserID)
	if err != nil {
		return nil, err
	}

	if !isNil(am.idpManager) {
		users := make(map[string]userLoggedInOnce, len(accountUsers))
		usersFromIntegration := make([]*idp.UserData, 0)
		for _, user := range accountUsers {
			if user.Issued == types.UserIssuedIntegration {
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
				users[user.Id] = userLoggedInOnce(!user.GetLastLogin().IsZero())
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

	settings, err := am.Store.GetAccountSettings(ctx, store.LockingStrengthShare, accountID)
	if err != nil {
		return nil, err
	}

	userInfosMap := make(map[string]*types.UserInfo)

	// in case of self-hosted, or IDP doesn't return anything, we will return the locally stored userInfo
	if len(queriedUsers) == 0 {
		for _, accountUser := range accountUsers {
			if initiatorUser.IsRegularUser() && initiatorUser.Id != accountUser.Id {
				// if user is not an admin then show only current user and do not show other users
				continue
			}

			info, err := accountUser.ToUserInfo(nil, settings)
			if err != nil {
				return nil, err
			}
			userInfosMap[accountUser.Id] = info
		}

		return userInfosMap, nil
	}

	for _, localUser := range accountUsers {
		if initiatorUser.IsRegularUser() && initiatorUser.Id != localUser.Id {
			// if user is not an admin then show only current user and do not show other users
			continue
		}

		var info *types.UserInfo
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

			info = &types.UserInfo{
				ID:            localUser.Id,
				Email:         "",
				Name:          name,
				Role:          string(localUser.Role),
				AutoGroups:    localUser.AutoGroups,
				Status:        string(types.UserStatusActive),
				IsServiceUser: localUser.IsServiceUser,
				NonDeletable:  localUser.NonDeletable,
				Permissions:   types.UserPermissions{DashboardView: dashboardViewPermissions},
			}
		}
		userInfosMap[info.ID] = info
	}

	return userInfosMap, nil
}

// expireAndUpdatePeers expires all peers of the given user and updates them in the account
func (am *DefaultAccountManager) expireAndUpdatePeers(ctx context.Context, accountID string, peers []*nbpeer.Peer) error {
	var peerIDs []string
	for _, peer := range peers {
		// nolint:staticcheck
		ctx = context.WithValue(ctx, nbContext.PeerIDKey, peer.Key)

		if peer.Status.LoginExpired {
			continue
		}
		peerIDs = append(peerIDs, peer.ID)
		peer.MarkLoginExpired(true)

		if err := am.Store.SavePeerStatus(ctx, store.LockingStrengthUpdate, accountID, peer.ID, *peer.Status); err != nil {
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
		am.UpdateAccountPeers(ctx, accountID)
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
	initiatorUser, err := am.Store.GetUserByUserID(ctx, store.LockingStrengthShare, initiatorUserID)
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

		targetUser, err := am.Store.GetUserByUserID(ctx, store.LockingStrengthShare, targetUserID)
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

		userHadPeers, err := am.deleteRegularUser(ctx, accountID, initiatorUserID, userInfo)
		if err != nil {
			allErrors = errors.Join(allErrors, err)
			continue
		}

		if userHadPeers {
			updateAccountPeers = true
		}
	}

	if updateAccountPeers {
		am.UpdateAccountPeers(ctx, accountID)
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
	var targetUser *types.User
	var err error

	err = am.Store.ExecuteInTransaction(ctx, func(transaction store.Store) error {
		targetUser, err = transaction.GetUserByUserID(ctx, store.LockingStrengthShare, targetUserInfo.ID)
		if err != nil {
			return fmt.Errorf("failed to get user to delete: %w", err)
		}

		userPeers, err := transaction.GetUserPeers(ctx, store.LockingStrengthShare, accountID, targetUserInfo.ID)
		if err != nil {
			return fmt.Errorf("failed to get user peers: %w", err)
		}

		if len(userPeers) > 0 {
			updateAccountPeers = true
			addPeerRemovedEvents, err = deletePeers(ctx, am, transaction, accountID, targetUserInfo.ID, userPeers)
			if err != nil {
				return fmt.Errorf("failed to delete user peers: %w", err)
			}
		}

		if err = transaction.DeleteUser(ctx, store.LockingStrengthUpdate, accountID, targetUserInfo.ID); err != nil {
			return fmt.Errorf("failed to delete user: %s %w", targetUserInfo.ID, err)
		}

		return nil
	})
	if err != nil {
		return false, err
	}

	for _, addPeerRemovedEvent := range addPeerRemovedEvents {
		addPeerRemovedEvent()
	}
	meta := map[string]any{"name": targetUserInfo.Name, "email": targetUserInfo.Email, "created_at": targetUser.CreatedAt}
	am.StoreEvent(ctx, initiatorUserID, targetUser.Id, accountID, activity.UserDeleted, meta)

	return updateAccountPeers, nil
}

// updateUserPeersInGroups updates the user's peers in the specified groups by adding or removing them.
func updateUserPeersInGroups(accountGroups map[string]*types.Group, peers []*nbpeer.Peer, groupsToAdd, groupsToRemove []string) (groupsToUpdate []*types.Group, err error) {
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
func addUserPeersToGroup(userPeerIDs map[string]struct{}, group *types.Group) {
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
func removeUserPeersFromGroup(userPeerIDs map[string]struct{}, group *types.Group) {
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
