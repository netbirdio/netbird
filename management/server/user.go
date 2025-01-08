package server

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/management/server/activity"
	nbContext "github.com/netbirdio/netbird/management/server/context"
	"github.com/netbirdio/netbird/management/server/idp"
	"github.com/netbirdio/netbird/management/server/jwtclaims"
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

	account, err := am.Store.GetAccount(ctx, accountID)
	if err != nil {
		return nil, status.Errorf(status.NotFound, "account %s doesn't exist", accountID)
	}

	executingUser := account.Users[initiatorUserID]
	if executingUser == nil {
		return nil, status.Errorf(status.NotFound, "user not found")
	}
	if !executingUser.HasAdminPower() {
		return nil, status.Errorf(status.PermissionDenied, "only users with admin power can create service users")
	}

	if role == types.UserRoleOwner {
		return nil, status.Errorf(status.InvalidArgument, "can't create a service user with owner role")
	}

	newUserID := uuid.New().String()
	newUser := types.NewUser(newUserID, role, true, nonDeletable, serviceUserName, autoGroups, types.UserIssuedAPI)
	log.WithContext(ctx).Debugf("New User: %v", newUser)
	account.Users[newUserID] = newUser

	err = am.Store.SaveAccount(ctx, account)
	if err != nil {
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

	if invite == nil {
		return nil, fmt.Errorf("provided user update is nil")
	}

	invitedRole := types.StrRoleToUserRole(invite.Role)

	switch {
	case invite.Name == "":
		return nil, status.Errorf(status.InvalidArgument, "name can't be empty")
	case invite.Email == "":
		return nil, status.Errorf(status.InvalidArgument, "email can't be empty")
	case invitedRole == types.UserRoleOwner:
		return nil, status.Errorf(status.InvalidArgument, "can't invite a user with owner role")
	default:
	}

	account, err := am.Store.GetAccount(ctx, accountID)
	if err != nil {
		return nil, status.Errorf(status.NotFound, "account %s doesn't exist", accountID)
	}

	initiatorUser, err := account.FindUser(userID)
	if err != nil {
		return nil, status.Errorf(status.NotFound, "initiator user with ID %s doesn't exist", userID)
	}

	inviterID := userID
	if initiatorUser.IsServiceUser {
		inviterID = account.CreatedBy
	}

	// inviterUser is the one who is inviting the new user
	inviterUser, err := am.lookupUserInCache(ctx, inviterID, account)
	if err != nil || inviterUser == nil {
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

	newUser := &types.User{
		Id:                   idpUser.ID,
		Role:                 invitedRole,
		AutoGroups:           invite.AutoGroups,
		Issued:               invite.Issued,
		IntegrationReference: invite.IntegrationReference,
		CreatedAt:            time.Now().UTC(),
	}
	account.Users[idpUser.ID] = newUser

	err = am.Store.SaveAccount(ctx, account)
	if err != nil {
		return nil, err
	}

	_, err = am.refreshCache(ctx, account.Id)
	if err != nil {
		return nil, err
	}

	am.StoreEvent(ctx, userID, newUser.Id, accountID, activity.UserInvited, nil)

	return newUser.ToUserInfo(idpUser, account.Settings)
}

func (am *DefaultAccountManager) GetUserByID(ctx context.Context, id string) (*types.User, error) {
	return am.Store.GetUserByUserID(ctx, store.LockingStrengthShare, id)
}

// GetUser looks up a user by provided authorization claims.
// It will also create an account if didn't exist for this user before.
func (am *DefaultAccountManager) GetUser(ctx context.Context, claims jwtclaims.AuthorizationClaims) (*types.User, error) {
	accountID, userID, err := am.GetAccountIDFromToken(ctx, claims)
	if err != nil {
		return nil, fmt.Errorf("failed to get account with token claims %v", err)
	}

	user, err := am.Store.GetUserByUserID(ctx, store.LockingStrengthShare, userID)
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
func (am *DefaultAccountManager) ListUsers(ctx context.Context, accountID string) ([]*types.User, error) {
	unlock := am.Store.AcquireWriteLockByUID(ctx, accountID)
	defer unlock()

	account, err := am.Store.GetAccount(ctx, accountID)
	if err != nil {
		return nil, err
	}

	users := make([]*types.User, 0, len(account.Users))
	for _, item := range account.Users {
		users = append(users, item)
	}

	return users, nil
}

func (am *DefaultAccountManager) deleteServiceUser(ctx context.Context, account *types.Account, initiatorUserID string, targetUser *types.User) {
	meta := map[string]any{"name": targetUser.ServiceUserName, "created_at": targetUser.CreatedAt}
	am.StoreEvent(ctx, initiatorUserID, targetUser.Id, account.Id, activity.ServiceUserDeleted, meta)
	delete(account.Users, targetUser.Id)
}

// DeleteUser deletes a user from the given account.
func (am *DefaultAccountManager) DeleteUser(ctx context.Context, accountID, initiatorUserID string, targetUserID string) error {
	if initiatorUserID == targetUserID {
		return status.Errorf(status.InvalidArgument, "self deletion is not allowed")
	}
	unlock := am.Store.AcquireWriteLockByUID(ctx, accountID)
	defer unlock()

	account, err := am.Store.GetAccount(ctx, accountID)
	if err != nil {
		return err
	}

	executingUser := account.Users[initiatorUserID]
	if executingUser == nil {
		return status.Errorf(status.NotFound, "user not found")
	}
	if !executingUser.HasAdminPower() {
		return status.Errorf(status.PermissionDenied, "only users with admin power can delete users")
	}

	targetUser := account.Users[targetUserID]
	if targetUser == nil {
		return status.Errorf(status.NotFound, "target user not found")
	}

	if targetUser.Role == types.UserRoleOwner {
		return status.Errorf(status.PermissionDenied, "unable to delete a user with owner role")
	}

	// disable deleting integration user if the initiator is not admin service user
	if targetUser.Issued == types.UserIssuedIntegration && !executingUser.IsServiceUser {
		return status.Errorf(status.PermissionDenied, "only integration service user can delete this user")
	}

	// handle service user first and exit, no need to fetch extra data from IDP, etc
	if targetUser.IsServiceUser {
		if targetUser.NonDeletable {
			return status.Errorf(status.PermissionDenied, "service user is marked as non-deletable")
		}

		am.deleteServiceUser(ctx, account, initiatorUserID, targetUser)
		return am.Store.SaveAccount(ctx, account)
	}

	return am.deleteRegularUser(ctx, account, initiatorUserID, targetUserID)
}

func (am *DefaultAccountManager) deleteRegularUser(ctx context.Context, account *types.Account, initiatorUserID, targetUserID string) error {
	meta, updateAccountPeers, err := am.prepareUserDeletion(ctx, account, initiatorUserID, targetUserID)
	if err != nil {
		return err
	}

	delete(account.Users, targetUserID)
	if updateAccountPeers {
		account.Network.IncSerial()
	}

	err = am.Store.SaveAccount(ctx, account)
	if err != nil {
		return err
	}

	am.StoreEvent(ctx, initiatorUserID, targetUserID, account.Id, activity.UserDeleted, meta)
	if updateAccountPeers {
		am.UpdateAccountPeers(ctx, account.Id)
	}

	return nil
}

func (am *DefaultAccountManager) deleteUserPeers(ctx context.Context, initiatorUserID string, targetUserID string, account *types.Account) (bool, error) {
	peers, err := account.FindUserPeers(targetUserID)
	if err != nil {
		return false, status.Errorf(status.Internal, "failed to find user peers")
	}

	hadPeers := len(peers) > 0
	if !hadPeers {
		return false, nil
	}

	eventsToStore, err := deletePeers(ctx, am, am.Store, account.Id, initiatorUserID, peers)
	if err != nil {
		return false, err
	}

	for _, storeEvent := range eventsToStore {
		storeEvent()
	}

	for _, peer := range peers {
		account.DeletePeer(peer.ID)
	}

	return hadPeers, nil
}

// InviteUser resend invitations to users who haven't activated their accounts prior to the expiration period.
func (am *DefaultAccountManager) InviteUser(ctx context.Context, accountID string, initiatorUserID string, targetUserID string) error {
	unlock := am.Store.AcquireWriteLockByUID(ctx, accountID)
	defer unlock()

	if am.idpManager == nil {
		return status.Errorf(status.PreconditionFailed, "IdP manager must be enabled to send user invites")
	}

	account, err := am.Store.GetAccount(ctx, accountID)
	if err != nil {
		return status.Errorf(status.NotFound, "account %s doesn't exist", accountID)
	}

	// check if the user is already registered with this ID
	user, err := am.lookupUserInCache(ctx, targetUserID, account)
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

	account, err := am.Store.GetAccount(ctx, accountID)
	if err != nil {
		return nil, err
	}

	targetUser, ok := account.Users[targetUserID]
	if !ok {
		return nil, status.Errorf(status.NotFound, "user not found")
	}

	executingUser, ok := account.Users[initiatorUserID]
	if !ok {
		return nil, status.Errorf(status.NotFound, "user not found")
	}

	if !(initiatorUserID == targetUserID || (executingUser.HasAdminPower() && targetUser.IsServiceUser)) {
		return nil, status.Errorf(status.PermissionDenied, "no permission to create PAT for this user")
	}

	pat, err := types.CreateNewPAT(tokenName, expiresIn, executingUser.Id)
	if err != nil {
		return nil, status.Errorf(status.Internal, "failed to create PAT: %v", err)
	}

	targetUser.PATs[pat.ID] = &pat.PersonalAccessToken

	err = am.Store.SaveAccount(ctx, account)
	if err != nil {
		return nil, status.Errorf(status.Internal, "failed to save account: %v", err)
	}

	meta := map[string]any{"name": pat.Name, "is_service_user": targetUser.IsServiceUser, "user_name": targetUser.ServiceUserName}
	am.StoreEvent(ctx, initiatorUserID, targetUserID, accountID, activity.PersonalAccessTokenCreated, meta)

	return pat, nil
}

// DeletePAT deletes a specific PAT from a user
func (am *DefaultAccountManager) DeletePAT(ctx context.Context, accountID string, initiatorUserID string, targetUserID string, tokenID string) error {
	unlock := am.Store.AcquireWriteLockByUID(ctx, accountID)
	defer unlock()

	account, err := am.Store.GetAccount(ctx, accountID)
	if err != nil {
		return status.Errorf(status.NotFound, "account not found: %s", err)
	}

	targetUser, ok := account.Users[targetUserID]
	if !ok {
		return status.Errorf(status.NotFound, "user not found")
	}

	executingUser, ok := account.Users[initiatorUserID]
	if !ok {
		return status.Errorf(status.NotFound, "user not found")
	}

	if !(initiatorUserID == targetUserID || (executingUser.HasAdminPower() && targetUser.IsServiceUser)) {
		return status.Errorf(status.PermissionDenied, "no permission to delete PAT for this user")
	}

	pat := targetUser.PATs[tokenID]
	if pat == nil {
		return status.Errorf(status.NotFound, "PAT not found")
	}

	err = am.Store.DeleteTokenID2UserIDIndex(pat.ID)
	if err != nil {
		return status.Errorf(status.Internal, "Failed to delete token id index: %s", err)
	}
	err = am.Store.DeleteHashedPAT2TokenIDIndex(pat.HashedToken)
	if err != nil {
		return status.Errorf(status.Internal, "Failed to delete hashed token index: %s", err)
	}

	meta := map[string]any{"name": pat.Name, "is_service_user": targetUser.IsServiceUser, "user_name": targetUser.ServiceUserName}
	am.StoreEvent(ctx, initiatorUserID, targetUserID, accountID, activity.PersonalAccessTokenDeleted, meta)

	delete(targetUser.PATs, tokenID)

	err = am.Store.SaveAccount(ctx, account)
	if err != nil {
		return status.Errorf(status.Internal, "Failed to save account: %s", err)
	}
	return nil
}

// GetPAT returns a specific PAT from a user
func (am *DefaultAccountManager) GetPAT(ctx context.Context, accountID string, initiatorUserID string, targetUserID string, tokenID string) (*types.PersonalAccessToken, error) {
	initiatorUser, err := am.Store.GetUserByUserID(ctx, store.LockingStrengthShare, initiatorUserID)
	if err != nil {
		return nil, err
	}

	targetUser, err := am.Store.GetUserByUserID(ctx, store.LockingStrengthShare, targetUserID)
	if err != nil {
		return nil, err
	}

	if (initiatorUserID != targetUserID && !initiatorUser.IsAdminOrServiceUser()) || initiatorUser.AccountID != accountID {
		return nil, status.Errorf(status.PermissionDenied, "no permission to get PAT for this user")
	}

	for _, pat := range targetUser.PATsG {
		if pat.ID == tokenID {
			return pat.Copy(), nil
		}
	}

	return nil, status.Errorf(status.NotFound, "PAT not found")
}

// GetAllPATs returns all PATs for a user
func (am *DefaultAccountManager) GetAllPATs(ctx context.Context, accountID string, initiatorUserID string, targetUserID string) ([]*types.PersonalAccessToken, error) {
	initiatorUser, err := am.Store.GetUserByUserID(ctx, store.LockingStrengthShare, initiatorUserID)
	if err != nil {
		return nil, err
	}

	targetUser, err := am.Store.GetUserByUserID(ctx, store.LockingStrengthShare, targetUserID)
	if err != nil {
		return nil, err
	}

	if (initiatorUserID != targetUserID && !initiatorUser.IsAdminOrServiceUser()) || initiatorUser.AccountID != accountID {
		return nil, status.Errorf(status.PermissionDenied, "no permission to get PAT for this user")
	}

	pats := make([]*types.PersonalAccessToken, 0, len(targetUser.PATsG))
	for _, pat := range targetUser.PATsG {
		pats = append(pats, pat.Copy())
	}

	return pats, nil
}

// SaveUser saves updates to the given user. If the user doesn't exist, it will throw status.NotFound error.
func (am *DefaultAccountManager) SaveUser(ctx context.Context, accountID, initiatorUserID string, update *types.User) (*types.UserInfo, error) {
	return am.SaveOrAddUser(ctx, accountID, initiatorUserID, update, false) // false means do not create user and throw status.NotFound
}

// SaveOrAddUser updates the given user. If addIfNotExists is set to true it will add user when no exist
// Only User.AutoGroups, User.Role, and User.Blocked fields are allowed to be updated for now.
func (am *DefaultAccountManager) SaveOrAddUser(ctx context.Context, accountID, initiatorUserID string, update *types.User, addIfNotExists bool) (*types.UserInfo, error) {
	if update == nil {
		return nil, status.Errorf(status.InvalidArgument, "provided user update is nil")
	}

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

	updatedUsers := make([]*types.UserInfo, 0, len(updates))
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

		peerGroupsAdded := make(map[string][]string)
		peerGroupsRemoved := make(map[string][]string)
		if update.AutoGroups != nil && account.Settings.GroupsPropagationEnabled {
			removedGroups := util.Difference(oldUser.AutoGroups, update.AutoGroups)
			// need force update all auto groups in any case they will not be duplicated
			peerGroupsAdded = account.UserGroupsAddToPeers(oldUser.Id, update.AutoGroups...)
			peerGroupsRemoved = account.UserGroupsRemoveFromPeers(oldUser.Id, removedGroups...)
		}

		userUpdateEvents := am.prepareUserUpdateEvents(ctx, initiatorUser.Id, oldUser, newUser, account, transferredOwnerRole)
		eventsToStore = append(eventsToStore, userUpdateEvents...)

		userGroupsEvents := am.prepareUserGroupsEvents(ctx, initiatorUser.Id, oldUser, newUser, account, peerGroupsAdded, peerGroupsRemoved)
		eventsToStore = append(eventsToStore, userGroupsEvents...)

		updatedUserInfo, err := getUserInfo(ctx, am, newUser, account)
		if err != nil {
			return nil, err
		}
		updatedUsers = append(updatedUsers, updatedUserInfo)
	}

	if len(expiredPeers) > 0 {
		if err := am.expireAndUpdatePeers(ctx, account.Id, expiredPeers); err != nil {
			log.WithContext(ctx).Errorf("failed update expired peers: %s", err)
			return nil, err
		}
	}

	account.Network.IncSerial()
	if err = am.Store.SaveAccount(ctx, account); err != nil {
		return nil, err
	}

	if account.Settings.GroupsPropagationEnabled && areUsersLinkedToPeers(account, userIDs) {
		am.UpdateAccountPeers(ctx, account.Id)
	}

	for _, storeEvent := range eventsToStore {
		storeEvent()
	}

	return updatedUsers, nil
}

// prepareUserUpdateEvents prepares a list user update events based on the changes between the old and new user data.
func (am *DefaultAccountManager) prepareUserUpdateEvents(ctx context.Context, initiatorUserID string, oldUser, newUser *types.User, account *types.Account, transferredOwnerRole bool) []func() {
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

	return eventsToStore
}

func (am *DefaultAccountManager) prepareUserGroupsEvents(ctx context.Context, initiatorUserID string, oldUser, newUser *types.User, account *types.Account, peerGroupsAdded, peerGroupsRemoved map[string][]string) []func() {
	var eventsToStore []func()
	if newUser.AutoGroups != nil {
		removedGroups := util.Difference(oldUser.AutoGroups, newUser.AutoGroups)
		addedGroups := util.Difference(newUser.AutoGroups, oldUser.AutoGroups)

		removedEvents := am.handleGroupRemovedFromUser(ctx, initiatorUserID, oldUser, newUser, account, removedGroups, peerGroupsRemoved)
		eventsToStore = append(eventsToStore, removedEvents...)

		addedEvents := am.handleGroupAddedToUser(ctx, initiatorUserID, oldUser, newUser, account, addedGroups, peerGroupsAdded)
		eventsToStore = append(eventsToStore, addedEvents...)
	}
	return eventsToStore
}

func (am *DefaultAccountManager) handleGroupAddedToUser(ctx context.Context, initiatorUserID string, oldUser, newUser *types.User, account *types.Account, addedGroups []string, peerGroupsAdded map[string][]string) []func() {
	var eventsToStore []func()
	for _, g := range addedGroups {
		group := account.GetGroup(g)
		if group != nil {
			eventsToStore = append(eventsToStore, func() {
				am.StoreEvent(ctx, initiatorUserID, oldUser.Id, account.Id, activity.GroupAddedToUser,
					map[string]any{"group": group.Name, "group_id": group.ID, "is_service_user": newUser.IsServiceUser, "user_name": newUser.ServiceUserName})
			})
		}
	}
	for groupID, peerIDs := range peerGroupsAdded {
		group := account.GetGroup(groupID)
		for _, peerID := range peerIDs {
			peer := account.GetPeer(peerID)
			eventsToStore = append(eventsToStore, func() {
				meta := map[string]any{
					"group": group.Name, "group_id": group.ID,
					"peer_ip": peer.IP.String(), "peer_fqdn": peer.FQDN(am.GetDNSDomain()),
				}
				am.StoreEvent(ctx, activity.SystemInitiator, peer.ID, account.Id, activity.GroupAddedToPeer, meta)
			})
		}
	}
	return eventsToStore
}

func (am *DefaultAccountManager) handleGroupRemovedFromUser(ctx context.Context, initiatorUserID string, oldUser, newUser *types.User, account *types.Account, removedGroups []string, peerGroupsRemoved map[string][]string) []func() {
	var eventsToStore []func()
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
	for groupID, peerIDs := range peerGroupsRemoved {
		group := account.GetGroup(groupID)
		for _, peerID := range peerIDs {
			peer := account.GetPeer(peerID)
			eventsToStore = append(eventsToStore, func() {
				meta := map[string]any{
					"group": group.Name, "group_id": group.ID,
					"peer_ip": peer.IP.String(), "peer_fqdn": peer.FQDN(am.GetDNSDomain()),
				}
				am.StoreEvent(ctx, activity.SystemInitiator, peer.ID, account.Id, activity.GroupRemovedFromPeer, meta)
			})
		}
	}
	return eventsToStore
}

func handleOwnerRoleTransfer(account *types.Account, initiatorUser, update *types.User) bool {
	if initiatorUser.Role == types.UserRoleOwner && initiatorUser.Id != update.Id && update.Role == types.UserRoleOwner {
		newInitiatorUser := initiatorUser.Copy()
		newInitiatorUser.Role = types.UserRoleAdmin
		account.Users[initiatorUser.Id] = newInitiatorUser
		return true
	}
	return false
}

// getUserInfo retrieves the UserInfo for a given User and Account.
// If the AccountManager has a non-nil idpManager and the User is not a service user,
// it will attempt to look up the UserData from the cache.
func getUserInfo(ctx context.Context, am *DefaultAccountManager, user *types.User, account *types.Account) (*types.UserInfo, error) {
	if !isNil(am.idpManager) && !user.IsServiceUser {
		userData, err := am.lookupUserInCache(ctx, user.Id, account)
		if err != nil {
			return nil, err
		}
		return user.ToUserInfo(userData, account.Settings)
	}
	return user.ToUserInfo(nil, account.Settings)
}

// validateUserUpdate validates the update operation for a user.
func validateUserUpdate(account *types.Account, initiatorUser, oldUser, update *types.User) error {
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
func (am *DefaultAccountManager) GetUsersFromAccount(ctx context.Context, accountID, userID string) ([]*types.UserInfo, error) {
	account, err := am.Store.GetAccount(ctx, accountID)
	if err != nil {
		return nil, err
	}

	user, err := account.FindUser(userID)
	if err != nil {
		return nil, err
	}

	queriedUsers := make([]*idp.UserData, 0)
	if !isNil(am.idpManager) {
		users := make(map[string]userLoggedInOnce, len(account.Users))
		usersFromIntegration := make([]*idp.UserData, 0)
		for _, user := range account.Users {
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

	userInfos := make([]*types.UserInfo, 0)

	// in case of self-hosted, or IDP doesn't return anything, we will return the locally stored userInfo
	if len(queriedUsers) == 0 {
		for _, accountUser := range account.Users {
			if !(user.HasAdminPower() || user.IsServiceUser || user.Id == accountUser.Id) {
				// if user is not an admin then show only current user and do not show other users
				continue
			}
			info, err := accountUser.ToUserInfo(nil, account.Settings)
			if err != nil {
				return nil, err
			}
			userInfos = append(userInfos, info)
		}
		return userInfos, nil
	}

	for _, localUser := range account.Users {
		if !(user.HasAdminPower() || user.IsServiceUser) && user.Id != localUser.Id {
			// if user is not an admin then show only current user and do not show other users
			continue
		}

		var info *types.UserInfo
		if queriedUser, contains := findUserInIDPUserdata(localUser.Id, queriedUsers); contains {
			info, err = localUser.ToUserInfo(queriedUser, account.Settings)
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
				if account.Settings.RegularUsersViewBlocked {
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
		userInfos = append(userInfos, info)
	}

	return userInfos, nil
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
// Note: This function does not acquire the global lock.
// It is the caller's responsibility to ensure proper locking is in place before invoking this method.
//
// If an error occurs while deleting the user, the function skips it and continues deleting other users.
// Errors are collected and returned at the end.
func (am *DefaultAccountManager) DeleteRegularUsers(ctx context.Context, accountID, initiatorUserID string, targetUserIDs []string) error {
	account, err := am.Store.GetAccount(ctx, accountID)
	if err != nil {
		return err
	}

	executingUser := account.Users[initiatorUserID]
	if executingUser == nil {
		return status.Errorf(status.NotFound, "user not found")
	}
	if !executingUser.HasAdminPower() {
		return status.Errorf(status.PermissionDenied, "only users with admin power can delete users")
	}

	var (
		allErrors          error
		updateAccountPeers bool
	)

	deletedUsersMeta := make(map[string]map[string]any)
	for _, targetUserID := range targetUserIDs {
		if initiatorUserID == targetUserID {
			allErrors = errors.Join(allErrors, errors.New("self deletion is not allowed"))
			continue
		}

		targetUser := account.Users[targetUserID]
		if targetUser == nil {
			allErrors = errors.Join(allErrors, fmt.Errorf("target user: %s not found", targetUserID))
			continue
		}

		if targetUser.Role == types.UserRoleOwner {
			allErrors = errors.Join(allErrors, fmt.Errorf("unable to delete a user: %s with owner role", targetUserID))
			continue
		}

		// disable deleting integration user if the initiator is not admin service user
		if targetUser.Issued == types.UserIssuedIntegration && !executingUser.IsServiceUser {
			allErrors = errors.Join(allErrors, errors.New("only integration service user can delete this user"))
			continue
		}

		meta, hadPeers, err := am.prepareUserDeletion(ctx, account, initiatorUserID, targetUserID)
		if err != nil {
			allErrors = errors.Join(allErrors, fmt.Errorf("failed to delete user %s: %s", targetUserID, err))
			continue
		}

		if hadPeers {
			updateAccountPeers = true
		}

		delete(account.Users, targetUserID)
		deletedUsersMeta[targetUserID] = meta
	}

	if updateAccountPeers {
		account.Network.IncSerial()
	}
	err = am.Store.SaveAccount(ctx, account)
	if err != nil {
		return fmt.Errorf("failed to delete users: %w", err)
	}

	if updateAccountPeers {
		am.UpdateAccountPeers(ctx, accountID)
	}

	for targetUserID, meta := range deletedUsersMeta {
		am.StoreEvent(ctx, initiatorUserID, targetUserID, account.Id, activity.UserDeleted, meta)
	}

	return allErrors
}

func (am *DefaultAccountManager) prepareUserDeletion(ctx context.Context, account *types.Account, initiatorUserID, targetUserID string) (map[string]any, bool, error) {
	tuEmail, tuName, err := am.getEmailAndNameOfTargetUser(ctx, account.Id, initiatorUserID, targetUserID)
	if err != nil {
		log.WithContext(ctx).Errorf("failed to resolve email address: %s", err)
		return nil, false, err
	}

	if !isNil(am.idpManager) {
		// Delete if the user already exists in the IdP. Necessary in cases where a user account
		// was created where a user account was provisioned but the user did not sign in
		_, err = am.idpManager.GetUserDataByID(ctx, targetUserID, idp.AppMetadata{WTAccountID: account.Id})
		if err == nil {
			err = am.deleteUserFromIDP(ctx, targetUserID, account.Id)
			if err != nil {
				log.WithContext(ctx).Debugf("failed to delete user from IDP: %s", targetUserID)
				return nil, false, err
			}
		} else {
			log.WithContext(ctx).Debugf("skipped deleting user %s from IDP, error: %v", targetUserID, err)
		}
	}

	hadPeers, err := am.deleteUserPeers(ctx, initiatorUserID, targetUserID, account)
	if err != nil {
		return nil, false, err
	}

	u, err := account.FindUser(targetUserID)
	if err != nil {
		log.WithContext(ctx).Errorf("failed to find user %s for deletion, this should never happen: %s", targetUserID, err)
	}

	var tuCreatedAt time.Time
	if u != nil {
		tuCreatedAt = u.CreatedAt
	}

	return map[string]any{"name": tuName, "email": tuEmail, "created_at": tuCreatedAt}, hadPeers, nil
}

// updateUserPeersInGroups updates the user's peers in the specified groups by adding or removing them.
func (am *DefaultAccountManager) updateUserPeersInGroups(accountGroups map[string]*types.Group, peers []*nbpeer.Peer, groupsToAdd,
	groupsToRemove []string) (groupsToUpdate []*types.Group, err error) {

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

// areUsersLinkedToPeers checks if any of the given userIDs are linked to any of the peers in the account.
func areUsersLinkedToPeers(account *types.Account, userIDs []string) bool {
	for _, peer := range account.Peers {
		if slices.Contains(userIDs, peer.UserID) {
			return true
		}
	}
	return false
}
