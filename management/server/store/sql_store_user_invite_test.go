package store

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/server/types"
)

func TestSqlStore_SaveUserInvite(t *testing.T) {
	runTestForAllEngines(t, "", func(t *testing.T, store Store) {
		if store == nil {
			t.Skip("store is nil")
		}
		ctx := context.Background()

		invite := &types.UserInviteRecord{
			ID:          "invite-1",
			AccountID:   "account-1",
			Email:       "test@example.com",
			Name:        "Test User",
			Role:        "user",
			AutoGroups:  []string{"group-1", "group-2"},
			HashedToken: "hashed-token-123",
			ExpiresAt:   time.Now().Add(72 * time.Hour),
			CreatedAt:   time.Now(),
			CreatedBy:   "admin-user",
		}

		err := store.SaveUserInvite(ctx, invite)
		require.NoError(t, err)

		// Verify the invite was saved
		retrieved, err := store.GetUserInviteByID(ctx, LockingStrengthNone, invite.AccountID, invite.ID)
		require.NoError(t, err)
		assert.Equal(t, invite.ID, retrieved.ID)
		assert.Equal(t, invite.Email, retrieved.Email)
		assert.Equal(t, invite.Name, retrieved.Name)
		assert.Equal(t, invite.Role, retrieved.Role)
		assert.Equal(t, invite.AutoGroups, retrieved.AutoGroups)
		assert.Equal(t, invite.CreatedBy, retrieved.CreatedBy)
	})
}

func TestSqlStore_SaveUserInvite_Update(t *testing.T) {
	runTestForAllEngines(t, "", func(t *testing.T, store Store) {
		if store == nil {
			t.Skip("store is nil")
		}
		ctx := context.Background()

		invite := &types.UserInviteRecord{
			ID:          "invite-update",
			AccountID:   "account-1",
			Email:       "test@example.com",
			Name:        "Test User",
			Role:        "user",
			AutoGroups:  []string{"group-1"},
			HashedToken: "hashed-token-123",
			ExpiresAt:   time.Now().Add(72 * time.Hour),
			CreatedAt:   time.Now(),
			CreatedBy:   "admin-user",
		}

		err := store.SaveUserInvite(ctx, invite)
		require.NoError(t, err)

		// Update the invite with a new token
		invite.HashedToken = "new-hashed-token"
		invite.ExpiresAt = time.Now().Add(24 * time.Hour)

		err = store.SaveUserInvite(ctx, invite)
		require.NoError(t, err)

		// Verify the update
		retrieved, err := store.GetUserInviteByID(ctx, LockingStrengthNone, invite.AccountID, invite.ID)
		require.NoError(t, err)
		assert.Equal(t, "new-hashed-token", retrieved.HashedToken)
	})
}

func TestSqlStore_GetUserInviteByID(t *testing.T) {
	runTestForAllEngines(t, "", func(t *testing.T, store Store) {
		if store == nil {
			t.Skip("store is nil")
		}
		ctx := context.Background()

		invite := &types.UserInviteRecord{
			ID:          "invite-get-by-id",
			AccountID:   "account-1",
			Email:       "getbyid@example.com",
			Name:        "Get By ID User",
			Role:        "admin",
			AutoGroups:  []string{},
			HashedToken: "hashed-token-get",
			ExpiresAt:   time.Now().Add(72 * time.Hour),
			CreatedAt:   time.Now(),
			CreatedBy:   "admin-user",
		}

		err := store.SaveUserInvite(ctx, invite)
		require.NoError(t, err)

		// Get by ID - success
		retrieved, err := store.GetUserInviteByID(ctx, LockingStrengthNone, invite.AccountID, invite.ID)
		require.NoError(t, err)
		assert.Equal(t, invite.ID, retrieved.ID)
		assert.Equal(t, invite.Email, retrieved.Email)

		// Get by ID - wrong account
		_, err = store.GetUserInviteByID(ctx, LockingStrengthNone, "wrong-account", invite.ID)
		assert.Error(t, err)

		// Get by ID - not found
		_, err = store.GetUserInviteByID(ctx, LockingStrengthNone, invite.AccountID, "non-existent")
		assert.Error(t, err)
	})
}

func TestSqlStore_GetUserInviteByHashedToken(t *testing.T) {
	runTestForAllEngines(t, "", func(t *testing.T, store Store) {
		if store == nil {
			t.Skip("store is nil")
		}
		ctx := context.Background()

		invite := &types.UserInviteRecord{
			ID:          "invite-get-by-token",
			AccountID:   "account-1",
			Email:       "getbytoken@example.com",
			Name:        "Get By Token User",
			Role:        "user",
			AutoGroups:  []string{"group-1"},
			HashedToken: "unique-hashed-token-456",
			ExpiresAt:   time.Now().Add(72 * time.Hour),
			CreatedAt:   time.Now(),
			CreatedBy:   "admin-user",
		}

		err := store.SaveUserInvite(ctx, invite)
		require.NoError(t, err)

		// Get by hashed token - success
		retrieved, err := store.GetUserInviteByHashedToken(ctx, LockingStrengthNone, invite.HashedToken)
		require.NoError(t, err)
		assert.Equal(t, invite.ID, retrieved.ID)
		assert.Equal(t, invite.Email, retrieved.Email)

		// Get by hashed token - not found
		_, err = store.GetUserInviteByHashedToken(ctx, LockingStrengthNone, "non-existent-token")
		assert.Error(t, err)
	})
}

func TestSqlStore_GetUserInviteByEmail(t *testing.T) {
	runTestForAllEngines(t, "", func(t *testing.T, store Store) {
		if store == nil {
			t.Skip("store is nil")
		}
		ctx := context.Background()

		invite := &types.UserInviteRecord{
			ID:          "invite-get-by-email",
			AccountID:   "account-email-test",
			Email:       "unique-email@example.com",
			Name:        "Get By Email User",
			Role:        "user",
			AutoGroups:  []string{},
			HashedToken: "hashed-token-email",
			ExpiresAt:   time.Now().Add(72 * time.Hour),
			CreatedAt:   time.Now(),
			CreatedBy:   "admin-user",
		}

		err := store.SaveUserInvite(ctx, invite)
		require.NoError(t, err)

		// Get by email - success
		retrieved, err := store.GetUserInviteByEmail(ctx, LockingStrengthNone, invite.AccountID, invite.Email)
		require.NoError(t, err)
		assert.Equal(t, invite.ID, retrieved.ID)

		// Get by email - case insensitive
		retrieved, err = store.GetUserInviteByEmail(ctx, LockingStrengthNone, invite.AccountID, "UNIQUE-EMAIL@EXAMPLE.COM")
		require.NoError(t, err)
		assert.Equal(t, invite.ID, retrieved.ID)

		// Get by email - wrong account
		_, err = store.GetUserInviteByEmail(ctx, LockingStrengthNone, "wrong-account", invite.Email)
		assert.Error(t, err)

		// Get by email - not found
		_, err = store.GetUserInviteByEmail(ctx, LockingStrengthNone, invite.AccountID, "nonexistent@example.com")
		assert.Error(t, err)
	})
}

func TestSqlStore_GetAccountUserInvites(t *testing.T) {
	runTestForAllEngines(t, "", func(t *testing.T, store Store) {
		if store == nil {
			t.Skip("store is nil")
		}
		ctx := context.Background()

		accountID := "account-list-invites"

		invites := []*types.UserInviteRecord{
			{
				ID:          "invite-list-1",
				AccountID:   accountID,
				Email:       "user1@example.com",
				Name:        "User One",
				Role:        "user",
				AutoGroups:  []string{"group-1"},
				HashedToken: "hashed-token-list-1",
				ExpiresAt:   time.Now().Add(72 * time.Hour),
				CreatedAt:   time.Now(),
				CreatedBy:   "admin-user",
			},
			{
				ID:          "invite-list-2",
				AccountID:   accountID,
				Email:       "user2@example.com",
				Name:        "User Two",
				Role:        "admin",
				AutoGroups:  []string{"group-2"},
				HashedToken: "hashed-token-list-2",
				ExpiresAt:   time.Now().Add(24 * time.Hour),
				CreatedAt:   time.Now(),
				CreatedBy:   "admin-user",
			},
			{
				ID:          "invite-list-3",
				AccountID:   "different-account",
				Email:       "user3@example.com",
				Name:        "User Three",
				Role:        "user",
				AutoGroups:  []string{},
				HashedToken: "hashed-token-list-3",
				ExpiresAt:   time.Now().Add(72 * time.Hour),
				CreatedAt:   time.Now(),
				CreatedBy:   "admin-user",
			},
		}

		for _, invite := range invites {
			err := store.SaveUserInvite(ctx, invite)
			require.NoError(t, err)
		}

		// Get all invites for the account
		retrieved, err := store.GetAccountUserInvites(ctx, LockingStrengthNone, accountID)
		require.NoError(t, err)
		assert.Len(t, retrieved, 2)

		// Verify the invites belong to the correct account
		for _, invite := range retrieved {
			assert.Equal(t, accountID, invite.AccountID)
		}

		// Get invites for account with no invites
		retrieved, err = store.GetAccountUserInvites(ctx, LockingStrengthNone, "empty-account")
		require.NoError(t, err)
		assert.Len(t, retrieved, 0)
	})
}

func TestSqlStore_DeleteUserInvite(t *testing.T) {
	runTestForAllEngines(t, "", func(t *testing.T, store Store) {
		if store == nil {
			t.Skip("store is nil")
		}
		ctx := context.Background()

		invite := &types.UserInviteRecord{
			ID:          "invite-delete",
			AccountID:   "account-delete-test",
			Email:       "delete@example.com",
			Name:        "Delete User",
			Role:        "user",
			AutoGroups:  []string{},
			HashedToken: "hashed-token-delete",
			ExpiresAt:   time.Now().Add(72 * time.Hour),
			CreatedAt:   time.Now(),
			CreatedBy:   "admin-user",
		}

		err := store.SaveUserInvite(ctx, invite)
		require.NoError(t, err)

		// Verify invite exists
		_, err = store.GetUserInviteByID(ctx, LockingStrengthNone, invite.AccountID, invite.ID)
		require.NoError(t, err)

		// Delete the invite
		err = store.DeleteUserInvite(ctx, invite.ID)
		require.NoError(t, err)

		// Verify invite is deleted
		_, err = store.GetUserInviteByID(ctx, LockingStrengthNone, invite.AccountID, invite.ID)
		assert.Error(t, err)
	})
}

func TestSqlStore_UserInvite_EncryptedFields(t *testing.T) {
	runTestForAllEngines(t, "", func(t *testing.T, store Store) {
		if store == nil {
			t.Skip("store is nil")
		}
		ctx := context.Background()

		invite := &types.UserInviteRecord{
			ID:          "invite-encrypted",
			AccountID:   "account-encrypted",
			Email:       "sensitive-email@example.com",
			Name:        "Sensitive Name",
			Role:        "user",
			AutoGroups:  []string{"group-1"},
			HashedToken: "hashed-token-encrypted",
			ExpiresAt:   time.Now().Add(72 * time.Hour),
			CreatedAt:   time.Now(),
			CreatedBy:   "admin-user",
		}

		err := store.SaveUserInvite(ctx, invite)
		require.NoError(t, err)

		// Retrieve and verify decryption works
		retrieved, err := store.GetUserInviteByID(ctx, LockingStrengthNone, invite.AccountID, invite.ID)
		require.NoError(t, err)
		assert.Equal(t, "sensitive-email@example.com", retrieved.Email)
		assert.Equal(t, "Sensitive Name", retrieved.Name)
	})
}

func TestSqlStore_DeleteUserInvite_NonExistent(t *testing.T) {
	runTestForAllEngines(t, "", func(t *testing.T, store Store) {
		if store == nil {
			t.Skip("store is nil")
		}
		ctx := context.Background()

		// Deleting a non-existent invite should not return an error
		err := store.DeleteUserInvite(ctx, "non-existent-invite-id")
		require.NoError(t, err)
	})
}

func TestSqlStore_UserInvite_SameEmailDifferentAccounts(t *testing.T) {
	runTestForAllEngines(t, "", func(t *testing.T, store Store) {
		if store == nil {
			t.Skip("store is nil")
		}
		ctx := context.Background()

		email := "shared-email@example.com"

		// Create invite in first account
		invite1 := &types.UserInviteRecord{
			ID:          "invite-account1",
			AccountID:   "account-1",
			Email:       email,
			Name:        "User Account 1",
			Role:        "user",
			AutoGroups:  []string{},
			HashedToken: "hashed-token-account1",
			ExpiresAt:   time.Now().Add(72 * time.Hour),
			CreatedAt:   time.Now(),
			CreatedBy:   "admin-1",
		}

		// Create invite in second account with same email
		invite2 := &types.UserInviteRecord{
			ID:          "invite-account2",
			AccountID:   "account-2",
			Email:       email,
			Name:        "User Account 2",
			Role:        "admin",
			AutoGroups:  []string{"group-1"},
			HashedToken: "hashed-token-account2",
			ExpiresAt:   time.Now().Add(72 * time.Hour),
			CreatedAt:   time.Now(),
			CreatedBy:   "admin-2",
		}

		err := store.SaveUserInvite(ctx, invite1)
		require.NoError(t, err)

		err = store.SaveUserInvite(ctx, invite2)
		require.NoError(t, err)

		// Verify each account gets the correct invite by email
		retrieved1, err := store.GetUserInviteByEmail(ctx, LockingStrengthNone, "account-1", email)
		require.NoError(t, err)
		assert.Equal(t, "invite-account1", retrieved1.ID)
		assert.Equal(t, "User Account 1", retrieved1.Name)

		retrieved2, err := store.GetUserInviteByEmail(ctx, LockingStrengthNone, "account-2", email)
		require.NoError(t, err)
		assert.Equal(t, "invite-account2", retrieved2.ID)
		assert.Equal(t, "User Account 2", retrieved2.Name)
	})
}

func TestSqlStore_UserInvite_LockingStrength(t *testing.T) {
	runTestForAllEngines(t, "", func(t *testing.T, store Store) {
		if store == nil {
			t.Skip("store is nil")
		}
		ctx := context.Background()

		invite := &types.UserInviteRecord{
			ID:          "invite-locking",
			AccountID:   "account-locking",
			Email:       "locking@example.com",
			Name:        "Locking Test User",
			Role:        "user",
			AutoGroups:  []string{},
			HashedToken: "hashed-token-locking",
			ExpiresAt:   time.Now().Add(72 * time.Hour),
			CreatedAt:   time.Now(),
			CreatedBy:   "admin-user",
		}

		err := store.SaveUserInvite(ctx, invite)
		require.NoError(t, err)

		// Test with different locking strengths
		lockStrengths := []LockingStrength{LockingStrengthNone, LockingStrengthShare, LockingStrengthUpdate}

		for _, strength := range lockStrengths {
			retrieved, err := store.GetUserInviteByID(ctx, strength, invite.AccountID, invite.ID)
			require.NoError(t, err)
			assert.Equal(t, invite.ID, retrieved.ID)

			retrieved, err = store.GetUserInviteByHashedToken(ctx, strength, invite.HashedToken)
			require.NoError(t, err)
			assert.Equal(t, invite.ID, retrieved.ID)

			retrieved, err = store.GetUserInviteByEmail(ctx, strength, invite.AccountID, invite.Email)
			require.NoError(t, err)
			assert.Equal(t, invite.ID, retrieved.ID)

			invites, err := store.GetAccountUserInvites(ctx, strength, invite.AccountID)
			require.NoError(t, err)
			assert.Len(t, invites, 1)
		}
	})
}

func TestSqlStore_UserInvite_EmptyAutoGroups(t *testing.T) {
	runTestForAllEngines(t, "", func(t *testing.T, store Store) {
		if store == nil {
			t.Skip("store is nil")
		}
		ctx := context.Background()

		// Test with nil AutoGroups
		invite := &types.UserInviteRecord{
			ID:          "invite-nil-autogroups",
			AccountID:   "account-autogroups",
			Email:       "nilgroups@example.com",
			Name:        "Nil Groups User",
			Role:        "user",
			AutoGroups:  nil,
			HashedToken: "hashed-token-nil",
			ExpiresAt:   time.Now().Add(72 * time.Hour),
			CreatedAt:   time.Now(),
			CreatedBy:   "admin-user",
		}

		err := store.SaveUserInvite(ctx, invite)
		require.NoError(t, err)

		retrieved, err := store.GetUserInviteByID(ctx, LockingStrengthNone, invite.AccountID, invite.ID)
		require.NoError(t, err)
		// Should return empty slice or nil, both are acceptable
		assert.Empty(t, retrieved.AutoGroups)
	})
}

func TestSqlStore_UserInvite_TimestampPrecision(t *testing.T) {
	runTestForAllEngines(t, "", func(t *testing.T, store Store) {
		if store == nil {
			t.Skip("store is nil")
		}
		ctx := context.Background()

		now := time.Now().UTC().Truncate(time.Millisecond)
		expiresAt := now.Add(72 * time.Hour)

		invite := &types.UserInviteRecord{
			ID:          "invite-timestamp",
			AccountID:   "account-timestamp",
			Email:       "timestamp@example.com",
			Name:        "Timestamp User",
			Role:        "user",
			AutoGroups:  []string{},
			HashedToken: "hashed-token-timestamp",
			ExpiresAt:   expiresAt,
			CreatedAt:   now,
			CreatedBy:   "admin-user",
		}

		err := store.SaveUserInvite(ctx, invite)
		require.NoError(t, err)

		retrieved, err := store.GetUserInviteByID(ctx, LockingStrengthNone, invite.AccountID, invite.ID)
		require.NoError(t, err)

		// Verify timestamps are preserved (within reasonable precision)
		assert.WithinDuration(t, now, retrieved.CreatedAt, time.Second)
		assert.WithinDuration(t, expiresAt, retrieved.ExpiresAt, time.Second)
	})
}
