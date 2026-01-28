package server

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/server/activity"
	"github.com/netbirdio/netbird/management/server/idp"
	"github.com/netbirdio/netbird/management/server/permissions"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/status"
	"github.com/netbirdio/netbird/util/crypt"
)

const (
	testAccountID     = "testAccountID"
	testAdminUserID   = "testAdminUserID"
	testRegularUserID = "testRegularUserID"
)

// setupInviteTestManagerWithEmbeddedIdP creates a test manager with a real embedded IdP
// and store encryption enabled. This is required for tests that need to pass the IsEmbeddedIdp check.
func setupInviteTestManagerWithEmbeddedIdP(t *testing.T) (*DefaultAccountManager, func()) {
	t.Helper()
	ctx := context.Background()

	tmpDir := t.TempDir()
	dexDataDir := tmpDir + "/dex"
	require.NoError(t, os.MkdirAll(dexDataDir, 0700))

	// Create test store
	s, cleanup, err := store.NewTestStoreFromSQL(ctx, "", tmpDir)
	require.NoError(t, err, "Error when creating store")

	// Enable encryption
	key, err := crypt.GenerateKey()
	require.NoError(t, err)
	fieldEncrypt, err := crypt.NewFieldEncrypt(key)
	require.NoError(t, err)
	s.SetFieldEncrypt(fieldEncrypt)

	// Create embedded IDP config
	embeddedIdPConfig := &idp.EmbeddedIdPConfig{
		Enabled: true,
		Issuer:  "http://localhost:5556/dex",
		Storage: idp.EmbeddedStorageConfig{
			Type: "sqlite3",
			Config: idp.EmbeddedStorageTypeConfig{
				File: dexDataDir + "/dex.db",
			},
		},
	}

	// Create embedded IDP manager
	embeddedIdp, err := idp.NewEmbeddedIdPManager(ctx, embeddedIdPConfig, nil)
	require.NoError(t, err)

	account := newAccountWithId(ctx, testAccountID, testAdminUserID, "", "admin@test.com", "Admin User", false)
	account.Users[testRegularUserID] = &types.User{
		Id:        testRegularUserID,
		AccountID: testAccountID,
		Role:      types.UserRoleUser,
		Email:     "regular@test.com",
		Name:      "Regular User",
	}

	err = s.SaveAccount(ctx, account)
	require.NoError(t, err, "Error when saving account")

	permissionsManager := permissions.NewManager(s)

	am := DefaultAccountManager{
		Store:              s,
		eventStore:         &activity.InMemoryEventStore{},
		permissionsManager: permissionsManager,
		idpManager:         embeddedIdp,
	}

	cleanupFunc := func() {
		_ = embeddedIdp.Stop(ctx)
		cleanup()
	}

	return &am, cleanupFunc
}

func TestCreateUserInvite_Success(t *testing.T) {
	am, cleanup := setupInviteTestManagerWithEmbeddedIdP(t)
	defer cleanup()

	invite := &types.UserInfo{
		Email:      "newuser@test.com",
		Name:       "New User",
		Role:       "user",
		AutoGroups: []string{},
	}

	result, err := am.CreateUserInvite(context.Background(), testAccountID, testAdminUserID, invite, 0)
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, "newuser@test.com", result.UserInfo.Email)
	assert.Equal(t, "New User", result.UserInfo.Name)
	assert.Equal(t, "user", result.UserInfo.Role)
	assert.Equal(t, string(types.UserStatusInvited), result.UserInfo.Status)
	assert.NotEmpty(t, result.InviteToken)
	assert.True(t, result.InviteExpiresAt.After(time.Now()))

	// Verify invite is stored in DB
	invites, err := am.Store.GetAccountUserInvites(context.Background(), store.LockingStrengthNone, testAccountID)
	require.NoError(t, err)
	assert.Len(t, invites, 1)
	assert.Equal(t, "newuser@test.com", invites[0].Email)
}

func TestCreateUserInvite_DuplicateEmail(t *testing.T) {
	am, cleanup := setupInviteTestManagerWithEmbeddedIdP(t)
	defer cleanup()

	invite := &types.UserInfo{
		Email:      "newuser@test.com",
		Name:       "New User",
		Role:       "user",
		AutoGroups: []string{},
	}

	// Create first invite
	_, err := am.CreateUserInvite(context.Background(), testAccountID, testAdminUserID, invite, 0)
	require.NoError(t, err)

	// Try to create duplicate invite
	_, err = am.CreateUserInvite(context.Background(), testAccountID, testAdminUserID, invite, 0)
	require.Error(t, err)

	sErr, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, status.AlreadyExists, sErr.Type())
}

func TestCreateUserInvite_ExistingUserEmail(t *testing.T) {
	am, cleanup := setupInviteTestManagerWithEmbeddedIdP(t)
	defer cleanup()

	// Try to invite with an email that already exists as a user
	invite := &types.UserInfo{
		Email:      "regular@test.com", // Already exists as a user
		Name:       "Duplicate User",
		Role:       "user",
		AutoGroups: []string{},
	}

	_, err := am.CreateUserInvite(context.Background(), testAccountID, testAdminUserID, invite, 0)
	require.Error(t, err)

	sErr, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, status.UserAlreadyExists, sErr.Type())
}

func TestCreateUserInvite_PermissionDenied(t *testing.T) {
	am, cleanup := setupInviteTestManagerWithEmbeddedIdP(t)
	defer cleanup()

	invite := &types.UserInfo{
		Email:      "newuser@test.com",
		Name:       "New User",
		Role:       "user",
		AutoGroups: []string{},
	}

	// Regular user should not be able to create invites
	_, err := am.CreateUserInvite(context.Background(), testAccountID, testRegularUserID, invite, 0)
	require.Error(t, err)
}

func TestCreateUserInvite_InvalidEmail(t *testing.T) {
	am, cleanup := setupInviteTestManagerWithEmbeddedIdP(t)
	defer cleanup()

	invite := &types.UserInfo{
		Email:      "",
		Name:       "New User",
		Role:       "user",
		AutoGroups: []string{},
	}

	_, err := am.CreateUserInvite(context.Background(), testAccountID, testAdminUserID, invite, 0)
	require.Error(t, err)

	sErr, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, status.InvalidArgument, sErr.Type())
}

func TestCreateUserInvite_InvalidName(t *testing.T) {
	am, cleanup := setupInviteTestManagerWithEmbeddedIdP(t)
	defer cleanup()

	invite := &types.UserInfo{
		Email:      "newuser@test.com",
		Name:       "",
		Role:       "user",
		AutoGroups: []string{},
	}

	_, err := am.CreateUserInvite(context.Background(), testAccountID, testAdminUserID, invite, 0)
	require.Error(t, err)

	sErr, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, status.InvalidArgument, sErr.Type())
}

func TestCreateUserInvite_OwnerRole(t *testing.T) {
	am, cleanup := setupInviteTestManagerWithEmbeddedIdP(t)
	defer cleanup()

	invite := &types.UserInfo{
		Email:      "newowner@test.com",
		Name:       "New Owner",
		Role:       "owner",
		AutoGroups: []string{},
	}

	_, err := am.CreateUserInvite(context.Background(), testAccountID, testAdminUserID, invite, 0)
	require.Error(t, err)

	sErr, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, status.InvalidArgument, sErr.Type())
}

func TestCreateUserInvite_ExpirationTooShort(t *testing.T) {
	am, cleanup := setupInviteTestManagerWithEmbeddedIdP(t)
	defer cleanup()

	invite := &types.UserInfo{
		Email:      "newuser@test.com",
		Name:       "New User",
		Role:       "user",
		AutoGroups: []string{},
	}

	// Try to create with expiration less than 1 hour
	_, err := am.CreateUserInvite(context.Background(), testAccountID, testAdminUserID, invite, 1800) // 30 minutes
	require.Error(t, err)

	sErr, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, status.InvalidArgument, sErr.Type())
	assert.Contains(t, err.Error(), "at least 1 hour")
}

func TestCreateUserInvite_CustomExpiration(t *testing.T) {
	am, cleanup := setupInviteTestManagerWithEmbeddedIdP(t)
	defer cleanup()

	invite := &types.UserInfo{
		Email:      "newuser@test.com",
		Name:       "New User",
		Role:       "user",
		AutoGroups: []string{},
	}

	expiresIn := 7200 // 2 hours
	result, err := am.CreateUserInvite(context.Background(), testAccountID, testAdminUserID, invite, expiresIn)
	require.NoError(t, err)

	// Verify expiration is approximately 2 hours from now
	expectedExpiration := time.Now().Add(time.Duration(expiresIn) * time.Second)
	assert.WithinDuration(t, expectedExpiration, result.InviteExpiresAt, time.Minute)
}

func TestCreateUserInvite_WithAutoGroups(t *testing.T) {
	am, cleanup := setupInviteTestManagerWithEmbeddedIdP(t)
	defer cleanup()

	invite := &types.UserInfo{
		Email:      "newuser@test.com",
		Name:       "New User",
		Role:       "user",
		AutoGroups: []string{"group1", "group2"},
	}

	result, err := am.CreateUserInvite(context.Background(), testAccountID, testAdminUserID, invite, 0)
	require.NoError(t, err)
	assert.Equal(t, []string{"group1", "group2"}, result.UserInfo.AutoGroups)

	// Verify invite in DB has auto groups
	invites, err := am.Store.GetAccountUserInvites(context.Background(), store.LockingStrengthNone, testAccountID)
	require.NoError(t, err)
	require.Len(t, invites, 1)
	assert.Equal(t, []string{"group1", "group2"}, invites[0].AutoGroups)
}

func TestGetUserInviteInfo_Success(t *testing.T) {
	am, cleanup := setupInviteTestManagerWithEmbeddedIdP(t)
	defer cleanup()

	// Create an invite first
	invite := &types.UserInfo{
		Email:      "newuser@test.com",
		Name:       "New User",
		Role:       "user",
		AutoGroups: []string{},
	}

	result, err := am.CreateUserInvite(context.Background(), testAccountID, testAdminUserID, invite, 0)
	require.NoError(t, err)

	// Get the invite info using the token
	info, err := am.GetUserInviteInfo(context.Background(), result.InviteToken)
	require.NoError(t, err)
	require.NotNil(t, info)

	assert.Equal(t, "newuser@test.com", info.Email)
	assert.Equal(t, "New User", info.Name)
	assert.True(t, info.Valid)
	assert.Equal(t, "Admin User", info.InvitedBy)
}

func TestGetUserInviteInfo_InvalidToken(t *testing.T) {
	am, cleanup := setupInviteTestManagerWithEmbeddedIdP(t)
	defer cleanup()

	_, err := am.GetUserInviteInfo(context.Background(), "invalid_token")
	require.Error(t, err)

	sErr, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, status.InvalidArgument, sErr.Type())
}

func TestGetUserInviteInfo_TokenNotFound(t *testing.T) {
	am, cleanup := setupInviteTestManagerWithEmbeddedIdP(t)
	defer cleanup()

	// Generate a valid token format that doesn't exist in DB
	_, validToken, err := types.GenerateInviteToken()
	require.NoError(t, err)

	_, err = am.GetUserInviteInfo(context.Background(), validToken)
	require.Error(t, err)

	sErr, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, status.NotFound, sErr.Type())
}

func TestGetUserInviteInfo_ExpiredInvite(t *testing.T) {
	am, cleanup := setupInviteTestManagerWithEmbeddedIdP(t)
	defer cleanup()

	// Create an invite with valid expiration
	invite := &types.UserInfo{
		Email:      "newuser@test.com",
		Name:       "New User",
		Role:       "user",
		AutoGroups: []string{},
	}

	result, err := am.CreateUserInvite(context.Background(), testAccountID, testAdminUserID, invite, 0)
	require.NoError(t, err)

	// Manually set the invite to expired by updating the store directly
	inviteRecord, err := am.Store.GetUserInviteByID(context.Background(), store.LockingStrengthUpdate, testAccountID, result.UserInfo.ID)
	require.NoError(t, err)
	inviteRecord.ExpiresAt = time.Now().Add(-time.Hour) // Set to 1 hour ago
	err = am.Store.SaveUserInvite(context.Background(), inviteRecord)
	require.NoError(t, err)

	// Get the invite info - should still return info but Valid should be false
	info, err := am.GetUserInviteInfo(context.Background(), result.InviteToken)
	require.NoError(t, err)
	assert.False(t, info.Valid)
}

func TestListUserInvites_Success(t *testing.T) {
	am, cleanup := setupInviteTestManagerWithEmbeddedIdP(t)
	defer cleanup()

	// Create multiple invites
	for i, email := range []string{"user1@test.com", "user2@test.com", "user3@test.com"} {
		invite := &types.UserInfo{
			Email:      email,
			Name:       "User " + string(rune('1'+i)),
			Role:       "user",
			AutoGroups: []string{},
		}
		_, err := am.CreateUserInvite(context.Background(), testAccountID, testAdminUserID, invite, 0)
		require.NoError(t, err)
	}

	// List invites
	invites, err := am.ListUserInvites(context.Background(), testAccountID, testAdminUserID)
	require.NoError(t, err)
	assert.Len(t, invites, 3)
}

func TestListUserInvites_Empty(t *testing.T) {
	am, cleanup := setupInviteTestManagerWithEmbeddedIdP(t)
	defer cleanup()

	invites, err := am.ListUserInvites(context.Background(), testAccountID, testAdminUserID)
	require.NoError(t, err)
	assert.Len(t, invites, 0)
}

func TestListUserInvites_PermissionDenied(t *testing.T) {
	am, cleanup := setupInviteTestManagerWithEmbeddedIdP(t)
	defer cleanup()

	_, err := am.ListUserInvites(context.Background(), testAccountID, testRegularUserID)
	require.Error(t, err)
}

func TestRegenerateUserInvite_Success(t *testing.T) {
	am, cleanup := setupInviteTestManagerWithEmbeddedIdP(t)
	defer cleanup()

	// Create an invite first
	invite := &types.UserInfo{
		Email:      "newuser@test.com",
		Name:       "New User",
		Role:       "user",
		AutoGroups: []string{},
	}

	originalResult, err := am.CreateUserInvite(context.Background(), testAccountID, testAdminUserID, invite, 0)
	require.NoError(t, err)

	// Regenerate the invite
	newResult, err := am.RegenerateUserInvite(context.Background(), testAccountID, testAdminUserID, originalResult.UserInfo.ID, 0)
	require.NoError(t, err)
	require.NotNil(t, newResult)

	// Verify invite ID remains the same (stable ID for clients)
	assert.Equal(t, originalResult.UserInfo.ID, newResult.UserInfo.ID)

	// Verify new token is different
	assert.NotEqual(t, originalResult.InviteToken, newResult.InviteToken)
	assert.Equal(t, "newuser@test.com", newResult.UserInfo.Email)
	assert.Equal(t, "New User", newResult.UserInfo.Name)

	// Verify old token no longer works
	_, err = am.GetUserInviteInfo(context.Background(), originalResult.InviteToken)
	require.Error(t, err)

	// Verify new token works
	info, err := am.GetUserInviteInfo(context.Background(), newResult.InviteToken)
	require.NoError(t, err)
	assert.Equal(t, "newuser@test.com", info.Email)
}

func TestRegenerateUserInvite_NotFound(t *testing.T) {
	am, cleanup := setupInviteTestManagerWithEmbeddedIdP(t)
	defer cleanup()

	_, err := am.RegenerateUserInvite(context.Background(), testAccountID, testAdminUserID, "nonexistent-id", 0)
	require.Error(t, err)

	sErr, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, status.NotFound, sErr.Type())
}

func TestRegenerateUserInvite_PermissionDenied(t *testing.T) {
	am, cleanup := setupInviteTestManagerWithEmbeddedIdP(t)
	defer cleanup()

	// Create an invite first
	invite := &types.UserInfo{
		Email:      "newuser@test.com",
		Name:       "New User",
		Role:       "user",
		AutoGroups: []string{},
	}

	result, err := am.CreateUserInvite(context.Background(), testAccountID, testAdminUserID, invite, 0)
	require.NoError(t, err)

	// Regular user should not be able to regenerate
	_, err = am.RegenerateUserInvite(context.Background(), testAccountID, testRegularUserID, result.UserInfo.ID, 0)
	require.Error(t, err)
}

func TestDeleteUserInvite_Success(t *testing.T) {
	am, cleanup := setupInviteTestManagerWithEmbeddedIdP(t)
	defer cleanup()

	// Create an invite first
	invite := &types.UserInfo{
		Email:      "newuser@test.com",
		Name:       "New User",
		Role:       "user",
		AutoGroups: []string{},
	}

	result, err := am.CreateUserInvite(context.Background(), testAccountID, testAdminUserID, invite, 0)
	require.NoError(t, err)

	// Delete the invite
	err = am.DeleteUserInvite(context.Background(), testAccountID, testAdminUserID, result.UserInfo.ID)
	require.NoError(t, err)

	// Verify invite is deleted
	invites, err := am.Store.GetAccountUserInvites(context.Background(), store.LockingStrengthNone, testAccountID)
	require.NoError(t, err)
	assert.Len(t, invites, 0)

	// Verify token no longer works
	_, err = am.GetUserInviteInfo(context.Background(), result.InviteToken)
	require.Error(t, err)
}

func TestDeleteUserInvite_NotFound(t *testing.T) {
	am, cleanup := setupInviteTestManagerWithEmbeddedIdP(t)
	defer cleanup()

	err := am.DeleteUserInvite(context.Background(), testAccountID, testAdminUserID, "nonexistent-id")
	require.Error(t, err)

	sErr, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, status.NotFound, sErr.Type())
}

func TestDeleteUserInvite_PermissionDenied(t *testing.T) {
	am, cleanup := setupInviteTestManagerWithEmbeddedIdP(t)
	defer cleanup()

	// Create an invite first
	invite := &types.UserInfo{
		Email:      "newuser@test.com",
		Name:       "New User",
		Role:       "user",
		AutoGroups: []string{},
	}

	result, err := am.CreateUserInvite(context.Background(), testAccountID, testAdminUserID, invite, 0)
	require.NoError(t, err)

	// Regular user should not be able to delete
	err = am.DeleteUserInvite(context.Background(), testAccountID, testRegularUserID, result.UserInfo.ID)
	require.Error(t, err)
}

func TestDeleteUserInvite_WrongAccount(t *testing.T) {
	am, cleanup := setupInviteTestManagerWithEmbeddedIdP(t)
	defer cleanup()

	// Create an invite
	invite := &types.UserInfo{
		Email:      "newuser@test.com",
		Name:       "New User",
		Role:       "user",
		AutoGroups: []string{},
	}

	result, err := am.CreateUserInvite(context.Background(), testAccountID, testAdminUserID, invite, 0)
	require.NoError(t, err)

	// Create another account
	anotherAccountID := "anotherAccountID"
	anotherAdminID := "anotherAdminID"
	anotherAccount := newAccountWithId(context.Background(), anotherAccountID, anotherAdminID, "", "otheradmin@test.com", "Other Admin", false)
	err = am.Store.SaveAccount(context.Background(), anotherAccount)
	require.NoError(t, err)

	// Try to delete from wrong account
	err = am.DeleteUserInvite(context.Background(), anotherAccountID, anotherAdminID, result.UserInfo.ID)
	require.Error(t, err)

	sErr, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, status.NotFound, sErr.Type())
}

func TestAcceptUserInvite_Success(t *testing.T) {
	am, cleanup := setupInviteTestManagerWithEmbeddedIdP(t)
	defer cleanup()

	// Create an invite
	invite := &types.UserInfo{
		Email:      "newuser@test.com",
		Name:       "New User",
		Role:       "user",
		AutoGroups: []string{},
	}

	result, err := am.CreateUserInvite(context.Background(), testAccountID, testAdminUserID, invite, 0)
	require.NoError(t, err)

	// Accept the invite with a valid password
	err = am.AcceptUserInvite(context.Background(), result.InviteToken, "Password1!")
	require.NoError(t, err)

	// Verify user is created in DB
	users, err := am.Store.GetAccountUsers(context.Background(), store.LockingStrengthNone, testAccountID)
	require.NoError(t, err)

	var foundUser *types.User
	for _, u := range users {
		if u.Email == "newuser@test.com" {
			foundUser = u
			break
		}
	}
	require.NotNil(t, foundUser, "User should be created in DB")
	assert.Equal(t, "New User", foundUser.Name)
	assert.Equal(t, types.UserRoleUser, foundUser.Role)

	// Verify invite is deleted
	invites, err := am.Store.GetAccountUserInvites(context.Background(), store.LockingStrengthNone, testAccountID)
	require.NoError(t, err)
	assert.Len(t, invites, 0)
}

func TestAcceptUserInvite_InvalidToken(t *testing.T) {
	am, cleanup := setupInviteTestManagerWithEmbeddedIdP(t)
	defer cleanup()

	err := am.AcceptUserInvite(context.Background(), "invalid_token", "Password1!")
	require.Error(t, err)

	sErr, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, status.InvalidArgument, sErr.Type())
}

func TestAcceptUserInvite_TokenNotFound(t *testing.T) {
	am, cleanup := setupInviteTestManagerWithEmbeddedIdP(t)
	defer cleanup()

	// Generate a valid token format that doesn't exist in DB
	_, validToken, err := types.GenerateInviteToken()
	require.NoError(t, err)

	err = am.AcceptUserInvite(context.Background(), validToken, "Password1!")
	require.Error(t, err)

	sErr, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, status.NotFound, sErr.Type())
}

func TestAcceptUserInvite_ExpiredToken(t *testing.T) {
	am, cleanup := setupInviteTestManagerWithEmbeddedIdP(t)
	defer cleanup()

	// Create an invite with valid expiration
	invite := &types.UserInfo{
		Email:      "newuser@test.com",
		Name:       "New User",
		Role:       "user",
		AutoGroups: []string{},
	}

	result, err := am.CreateUserInvite(context.Background(), testAccountID, testAdminUserID, invite, 0)
	require.NoError(t, err)

	// Manually set the invite to expired by updating the store directly
	inviteRecord, err := am.Store.GetUserInviteByID(context.Background(), store.LockingStrengthUpdate, testAccountID, result.UserInfo.ID)
	require.NoError(t, err)
	inviteRecord.ExpiresAt = time.Now().Add(-time.Hour) // Set to 1 hour ago
	err = am.Store.SaveUserInvite(context.Background(), inviteRecord)
	require.NoError(t, err)

	err = am.AcceptUserInvite(context.Background(), result.InviteToken, "Password1!")
	require.Error(t, err)

	sErr, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, status.InvalidArgument, sErr.Type())
	assert.Contains(t, err.Error(), "expired")
}

func TestAcceptUserInvite_EmptyPassword(t *testing.T) {
	am, cleanup := setupInviteTestManagerWithEmbeddedIdP(t)
	defer cleanup()

	// Create an invite
	invite := &types.UserInfo{
		Email:      "newuser@test.com",
		Name:       "New User",
		Role:       "user",
		AutoGroups: []string{},
	}

	result, err := am.CreateUserInvite(context.Background(), testAccountID, testAdminUserID, invite, 0)
	require.NoError(t, err)

	err = am.AcceptUserInvite(context.Background(), result.InviteToken, "")
	require.Error(t, err)

	sErr, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, status.InvalidArgument, sErr.Type())
	assert.Contains(t, err.Error(), "password is required")
}

func TestAcceptUserInvite_WeakPassword(t *testing.T) {
	am, cleanup := setupInviteTestManagerWithEmbeddedIdP(t)
	defer cleanup()

	// Create an invite
	invite := &types.UserInfo{
		Email:      "newuser@test.com",
		Name:       "New User",
		Role:       "user",
		AutoGroups: []string{},
	}

	result, err := am.CreateUserInvite(context.Background(), testAccountID, testAdminUserID, invite, 0)
	require.NoError(t, err)

	testCases := []struct {
		name        string
		password    string
		expectedMsg string
	}{
		{"too short", "Pass1!", "at least 8 characters"},
		{"no digit", "Password!", "one digit"},
		{"no uppercase", "password1!", "one uppercase"},
		{"no special", "Password1", "one special character"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := am.AcceptUserInvite(context.Background(), result.InviteToken, tc.password)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.expectedMsg)
		})
	}
}

func TestValidatePassword(t *testing.T) {
	testCases := []struct {
		name        string
		password    string
		expectError bool
		errorMsg    string
	}{
		{"valid password", "Password1!", false, ""},
		{"valid complex password", "MyP@ssw0rd#2024", false, ""},
		{"too short", "Pass1!", true, "at least 8 characters"},
		{"no digit", "Password!", true, "one digit"},
		{"no uppercase", "password1!", true, "one uppercase"},
		{"no special", "Password1", true, "one special character"},
		{"only lowercase", "password", true, "one digit"},
		{"no uppercase no special", "password1", true, "one uppercase"},
		{"all lowercase short", "pass", true, "at least 8 characters"},
		{"empty", "", true, "at least 8 characters"},
		{"spaces count as special", "Pass word1", false, ""},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := validatePassword(tc.password)
			if tc.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.errorMsg)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestInviteToken_GenerateAndValidate(t *testing.T) {
	hashedToken, plainToken, err := types.GenerateInviteToken()
	require.NoError(t, err)
	require.NotEmpty(t, hashedToken)
	require.NotEmpty(t, plainToken)

	// Validate token format
	assert.Len(t, plainToken, types.InviteTokenLength)
	assert.True(t, len(plainToken) > len(types.InviteTokenPrefix))
	assert.Equal(t, types.InviteTokenPrefix, plainToken[:len(types.InviteTokenPrefix)])

	// Validate checksum
	err = types.ValidateInviteToken(plainToken)
	require.NoError(t, err)

	// Verify hashing is consistent
	hashedAgain := types.HashInviteToken(plainToken)
	assert.Equal(t, hashedToken, hashedAgain)
}

func TestInviteToken_ValidateInvalid(t *testing.T) {
	testCases := []struct {
		name  string
		token string
	}{
		{"empty", ""},
		{"too short", "nbi_abc"},
		{"wrong prefix", "xyz_123456789012345678901234567890"},
		{"invalid checksum", "nbi_123456789012345678901234567890abcdef"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := types.ValidateInviteToken(tc.token)
			require.Error(t, err)
		})
	}
}

func TestUserInviteRecord_IsExpired(t *testing.T) {
	// Not expired
	invite := &types.UserInviteRecord{
		ExpiresAt: time.Now().Add(time.Hour),
	}
	assert.False(t, invite.IsExpired())

	// Expired
	invite = &types.UserInviteRecord{
		ExpiresAt: time.Now().Add(-time.Hour),
	}
	assert.True(t, invite.IsExpired())
}

func TestUserInviteRecord_Copy(t *testing.T) {
	original := &types.UserInviteRecord{
		ID:          "invite-id",
		AccountID:   "account-id",
		Email:       "test@example.com",
		Name:        "Test User",
		Role:        "user",
		AutoGroups:  []string{"group1", "group2"},
		HashedToken: "hashed-token",
		ExpiresAt:   time.Now().Add(time.Hour),
		CreatedAt:   time.Now(),
		CreatedBy:   "creator-id",
	}

	copied := original.Copy()

	assert.Equal(t, original.ID, copied.ID)
	assert.Equal(t, original.AccountID, copied.AccountID)
	assert.Equal(t, original.Email, copied.Email)
	assert.Equal(t, original.Name, copied.Name)
	assert.Equal(t, original.Role, copied.Role)
	assert.Equal(t, original.AutoGroups, copied.AutoGroups)
	assert.Equal(t, original.HashedToken, copied.HashedToken)
	assert.Equal(t, original.ExpiresAt, copied.ExpiresAt)
	assert.Equal(t, original.CreatedAt, copied.CreatedAt)
	assert.Equal(t, original.CreatedBy, copied.CreatedBy)

	// Verify deep copy of AutoGroups
	copied.AutoGroups[0] = "modified"
	assert.NotEqual(t, original.AutoGroups[0], copied.AutoGroups[0])
}

func TestCreateUserInvite_NonEmbeddedIdP(t *testing.T) {
	s, cleanup, err := store.NewTestStoreFromSQL(context.Background(), "", t.TempDir())
	require.NoError(t, err)
	defer cleanup()

	account := newAccountWithId(context.Background(), testAccountID, testAdminUserID, "", "admin@test.com", "Admin User", false)
	err = s.SaveAccount(context.Background(), account)
	require.NoError(t, err)

	permissionsManager := permissions.NewManager(s)

	// Use nil IDP manager (non-embedded)
	am := DefaultAccountManager{
		Store:              s,
		eventStore:         &activity.InMemoryEventStore{},
		permissionsManager: permissionsManager,
		idpManager:         nil,
	}

	invite := &types.UserInfo{
		Email:      "newuser@test.com",
		Name:       "New User",
		Role:       "user",
		AutoGroups: []string{},
	}

	_, err = am.CreateUserInvite(context.Background(), testAccountID, testAdminUserID, invite, 0)
	require.Error(t, err)

	sErr, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, status.PreconditionFailed, sErr.Type())
	assert.Contains(t, err.Error(), "embedded identity provider")
}

func TestAcceptUserInvite_WithAutoGroups(t *testing.T) {
	am, cleanup := setupInviteTestManagerWithEmbeddedIdP(t)
	defer cleanup()

	// Create an invite with auto groups
	invite := &types.UserInfo{
		Email:      "newuser@test.com",
		Name:       "New User",
		Role:       "admin",
		AutoGroups: []string{"group1", "group2"},
	}

	result, err := am.CreateUserInvite(context.Background(), testAccountID, testAdminUserID, invite, 0)
	require.NoError(t, err)

	// Accept the invite
	err = am.AcceptUserInvite(context.Background(), result.InviteToken, "Password1!")
	require.NoError(t, err)

	// Verify user has the auto groups and role
	users, err := am.Store.GetAccountUsers(context.Background(), store.LockingStrengthNone, testAccountID)
	require.NoError(t, err)

	var foundUser *types.User
	for _, u := range users {
		if u.Email == "newuser@test.com" {
			foundUser = u
			break
		}
	}
	require.NotNil(t, foundUser)
	assert.Equal(t, types.UserRoleAdmin, foundUser.Role)
	assert.Equal(t, []string{"group1", "group2"}, foundUser.AutoGroups)
}

func TestUserInvite_EncryptDecryptSensitiveData(t *testing.T) {
	key, err := crypt.GenerateKey()
	require.NoError(t, err)
	fieldEncrypt, err := crypt.NewFieldEncrypt(key)
	require.NoError(t, err)

	t.Run("encrypt and decrypt", func(t *testing.T) {
		invite := &types.UserInviteRecord{
			ID:        "test-invite",
			AccountID: "test-account",
			Email:     "test@example.com",
			Name:      "Test User",
			Role:      "user",
		}

		// Encrypt
		err := invite.EncryptSensitiveData(fieldEncrypt)
		require.NoError(t, err)

		// Verify encrypted values are different from original
		assert.NotEqual(t, "test@example.com", invite.Email)
		assert.NotEqual(t, "Test User", invite.Name)

		// Decrypt
		err = invite.DecryptSensitiveData(fieldEncrypt)
		require.NoError(t, err)

		// Verify decrypted values match original
		assert.Equal(t, "test@example.com", invite.Email)
		assert.Equal(t, "Test User", invite.Name)
	})

	t.Run("encrypt empty fields", func(t *testing.T) {
		invite := &types.UserInviteRecord{
			ID:        "test-invite",
			AccountID: "test-account",
			Email:     "",
			Name:      "",
			Role:      "user",
		}

		// Encrypt empty fields
		err := invite.EncryptSensitiveData(fieldEncrypt)
		require.NoError(t, err)

		// Empty strings should remain empty
		assert.Equal(t, "", invite.Email)
		assert.Equal(t, "", invite.Name)

		// Decrypt empty fields
		err = invite.DecryptSensitiveData(fieldEncrypt)
		require.NoError(t, err)

		// Should still be empty
		assert.Equal(t, "", invite.Email)
		assert.Equal(t, "", invite.Name)
	})

	t.Run("nil encryptor", func(t *testing.T) {
		invite := &types.UserInviteRecord{
			ID:        "test-invite",
			AccountID: "test-account",
			Email:     "test@example.com",
			Name:      "Test User",
			Role:      "user",
		}

		// Encrypt with nil encryptor should be no-op
		err := invite.EncryptSensitiveData(nil)
		require.NoError(t, err)
		assert.Equal(t, "test@example.com", invite.Email)
		assert.Equal(t, "Test User", invite.Name)

		// Decrypt with nil encryptor should be no-op
		err = invite.DecryptSensitiveData(nil)
		require.NoError(t, err)
		assert.Equal(t, "test@example.com", invite.Email)
		assert.Equal(t, "Test User", invite.Name)
	})
}
