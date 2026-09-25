package store

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/management/server/util"
	"github.com/netbirdio/netbird/shared/management/status"
	"github.com/netbirdio/netbird/util/crypt"
)

func TestSqlStore_GetAccountUsers(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/extended-store.sql", t.TempDir())
	t.Cleanup(cleanup)
	if err != nil {
		t.Fatal(err)
	}
	accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"
	account, err := store.GetAccount(context.Background(), accountID)
	require.NoError(t, err)
	users, err := store.GetAccountUsers(context.Background(), LockingStrengthNone, accountID)
	require.NoError(t, err)
	require.Len(t, users, len(account.Users))
}

func TestSqlStore_GetUserByUserID(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/extended-store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	tests := []struct {
		name        string
		userID      string
		expectError bool
	}{
		{
			name:        "retrieve existing user",
			userID:      "edafee4e-63fb-11ec-90d6-0242ac120003",
			expectError: false,
		},
		{
			name:        "retrieve non-existing user",
			userID:      "non-existing",
			expectError: true,
		},
		{
			name:        "retrieve with empty user ID",
			userID:      "",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			user, err := store.GetUserByUserID(context.Background(), LockingStrengthNone, tt.userID)
			if tt.expectError {
				require.Error(t, err)
				sErr, ok := status.FromError(err)
				require.True(t, ok)
				require.Equal(t, sErr.Type(), status.NotFound)
				require.Nil(t, user)
			} else {
				require.NoError(t, err)
				require.NotNil(t, user)
				require.Equal(t, tt.userID, user.Id)
			}
		})
	}
}

func TestSqlStore_GetUserByPATID(t *testing.T) {
	store, cleanUp, err := NewTestStoreFromSQL(context.Background(), "../testdata/store.sql", t.TempDir())
	t.Cleanup(cleanUp)
	assert.NoError(t, err)

	id := "9dj38s35-63fb-11ec-90d6-0242ac120003"

	user, err := store.GetUserByPATID(context.Background(), LockingStrengthNone, id)
	require.NoError(t, err)
	require.Equal(t, "f4f6d672-63fb-11ec-90d6-0242ac120003", user.Id)
}

func TestSqlStore_SaveUser(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/extended-store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"

	user := &types.User{
		Id:            "user-id",
		AccountID:     accountID,
		Role:          types.UserRoleAdmin,
		IsServiceUser: false,
		AutoGroups:    []string{"groupA", "groupB"},
		Blocked:       false,
		LastLogin:     util.ToPtr(time.Now().UTC()),
		CreatedAt:     time.Now().UTC().Add(-time.Hour),
		Issued:        types.UserIssuedIntegration,
	}
	err = store.SaveUser(context.Background(), user)
	require.NoError(t, err)

	saveUser, err := store.GetUserByUserID(context.Background(), LockingStrengthNone, user.Id)
	require.NoError(t, err)
	require.Equal(t, user.Id, saveUser.Id)
	require.Equal(t, user.AccountID, saveUser.AccountID)
	require.Equal(t, user.Role, saveUser.Role)
	require.Equal(t, user.AutoGroups, saveUser.AutoGroups)
	require.WithinDurationf(t, user.GetLastLogin(), saveUser.LastLogin.UTC(), time.Millisecond, "LastLogin should be equal")
	require.WithinDurationf(t, user.CreatedAt, saveUser.CreatedAt.UTC(), time.Millisecond, "CreatedAt should be equal")
	require.Equal(t, user.Issued, saveUser.Issued)
	require.Equal(t, user.Blocked, saveUser.Blocked)
	require.Equal(t, user.IsServiceUser, saveUser.IsServiceUser)
}

func TestSqlStore_SaveUsers(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/extended-store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"

	accountUsers, err := store.GetAccountUsers(context.Background(), LockingStrengthNone, accountID)
	require.NoError(t, err)
	require.Len(t, accountUsers, 2)

	users := []*types.User{
		{
			Id:         "user-1",
			AccountID:  accountID,
			Issued:     "api",
			AutoGroups: []string{"groupA", "groupB"},
		},
		{
			Id:         "user-2",
			AccountID:  accountID,
			Issued:     "integration",
			AutoGroups: []string{"groupA"},
		},
	}
	err = store.SaveUsers(context.Background(), users)
	require.NoError(t, err)

	accountUsers, err = store.GetAccountUsers(context.Background(), LockingStrengthNone, accountID)
	require.NoError(t, err)
	require.Len(t, accountUsers, 4)

	users[1].AutoGroups = []string{"groupA", "groupC"}
	err = store.SaveUsers(context.Background(), users)
	require.NoError(t, err)

	user, err := store.GetUserByUserID(context.Background(), LockingStrengthNone, users[1].Id)
	require.NoError(t, err)
	require.Equal(t, users[1].AutoGroups, user.AutoGroups)
}

func TestSqlStore_SaveUserWithEncryption(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/extended-store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	// Enable encryption
	key, err := crypt.GenerateKey()
	require.NoError(t, err)
	fieldEncrypt, err := crypt.NewFieldEncrypt(key)
	require.NoError(t, err)
	store.SetFieldEncrypt(fieldEncrypt)

	accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"

	// rawUser is used to read raw (potentially encrypted) data from the database
	// without any gorm hooks or automatic decryption
	type rawUser struct {
		Id    string
		Email string
		Name  string
	}

	t.Run("save user with empty email and name", func(t *testing.T) {
		user := &types.User{
			Id:         "user-empty-fields",
			AccountID:  accountID,
			Role:       types.UserRoleUser,
			Email:      "",
			Name:       "",
			AutoGroups: []string{"groupA"},
		}
		err = store.SaveUser(context.Background(), user)
		require.NoError(t, err)

		// Verify using direct database query that empty strings remain empty (not encrypted)
		var raw rawUser
		err = store.(*SqlStore).db.Table("users").Select("id, email, name").Where("id = ?", user.Id).First(&raw).Error
		require.NoError(t, err)
		require.Equal(t, "", raw.Email, "empty email should remain empty in database")
		require.Equal(t, "", raw.Name, "empty name should remain empty in database")

		// Verify manual decryption returns empty strings
		decryptedEmail, err := fieldEncrypt.Decrypt(raw.Email)
		require.NoError(t, err)
		require.Equal(t, "", decryptedEmail)

		decryptedName, err := fieldEncrypt.Decrypt(raw.Name)
		require.NoError(t, err)
		require.Equal(t, "", decryptedName)
	})

	t.Run("save user with email and name", func(t *testing.T) {
		user := &types.User{
			Id:         "user-with-fields",
			AccountID:  accountID,
			Role:       types.UserRoleAdmin,
			Email:      "test@example.com",
			Name:       "Test User",
			AutoGroups: []string{"groupB"},
		}
		err = store.SaveUser(context.Background(), user)
		require.NoError(t, err)

		// Verify using direct database query that the data is encrypted (not plaintext)
		var raw rawUser
		err = store.(*SqlStore).db.Table("users").Select("id, email, name").Where("id = ?", user.Id).First(&raw).Error
		require.NoError(t, err)
		require.NotEqual(t, "test@example.com", raw.Email, "email should be encrypted in database")
		require.NotEqual(t, "Test User", raw.Name, "name should be encrypted in database")

		// Verify manual decryption returns correct values
		decryptedEmail, err := fieldEncrypt.Decrypt(raw.Email)
		require.NoError(t, err)
		require.Equal(t, "test@example.com", decryptedEmail)

		decryptedName, err := fieldEncrypt.Decrypt(raw.Name)
		require.NoError(t, err)
		require.Equal(t, "Test User", decryptedName)
	})

	t.Run("save multiple users with mixed fields", func(t *testing.T) {
		users := []*types.User{
			{
				Id:        "batch-user-1",
				AccountID: accountID,
				Email:     "",
				Name:      "",
			},
			{
				Id:        "batch-user-2",
				AccountID: accountID,
				Email:     "batch@example.com",
				Name:      "Batch User",
			},
		}
		err = store.SaveUsers(context.Background(), users)
		require.NoError(t, err)

		// Verify first user (empty fields) using direct database query
		var raw1 rawUser
		err = store.(*SqlStore).db.Table("users").Select("id, email, name").Where("id = ?", "batch-user-1").First(&raw1).Error
		require.NoError(t, err)
		require.Equal(t, "", raw1.Email, "empty email should remain empty in database")
		require.Equal(t, "", raw1.Name, "empty name should remain empty in database")

		// Verify second user (with fields) using direct database query
		var raw2 rawUser
		err = store.(*SqlStore).db.Table("users").Select("id, email, name").Where("id = ?", "batch-user-2").First(&raw2).Error
		require.NoError(t, err)
		require.NotEqual(t, "batch@example.com", raw2.Email, "email should be encrypted in database")
		require.NotEqual(t, "Batch User", raw2.Name, "name should be encrypted in database")

		// Verify manual decryption returns empty strings for first user
		decryptedEmail1, err := fieldEncrypt.Decrypt(raw1.Email)
		require.NoError(t, err)
		require.Equal(t, "", decryptedEmail1)

		decryptedName1, err := fieldEncrypt.Decrypt(raw1.Name)
		require.NoError(t, err)
		require.Equal(t, "", decryptedName1)

		// Verify manual decryption returns correct values for second user
		decryptedEmail2, err := fieldEncrypt.Decrypt(raw2.Email)
		require.NoError(t, err)
		require.Equal(t, "batch@example.com", decryptedEmail2)

		decryptedName2, err := fieldEncrypt.Decrypt(raw2.Name)
		require.NoError(t, err)
		require.Equal(t, "Batch User", decryptedName2)
	})
}

func TestSqlStore_DeleteUser(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/extended-store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"
	userID := "f4f6d672-63fb-11ec-90d6-0242ac120003"

	err = store.DeleteUser(context.Background(), accountID, userID)
	require.NoError(t, err)

	user, err := store.GetUserByUserID(context.Background(), LockingStrengthNone, userID)
	require.Error(t, err)
	require.Nil(t, user)

	userPATs, err := store.GetUserPATs(context.Background(), LockingStrengthNone, userID)
	require.NoError(t, err)
	require.Len(t, userPATs, 0)
}

func TestSqlStore_SaveUsers_LargeBatch(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/extended-store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"

	accountUsers, err := store.GetAccountUsers(context.Background(), LockingStrengthNone, accountID)
	require.NoError(t, err)
	require.Len(t, accountUsers, 2)

	usersToSave := make([]*types.User, 0)

	for i := 1; i <= 8000; i++ {
		usersToSave = append(usersToSave, &types.User{
			Id:        fmt.Sprintf("user-%d", i),
			AccountID: accountID,
			Role:      types.UserRoleUser,
		})
	}

	err = store.SaveUsers(context.Background(), usersToSave)
	require.NoError(t, err)

	accountUsers, err = store.GetAccountUsers(context.Background(), LockingStrengthNone, accountID)
	require.NoError(t, err)
	require.Equal(t, 8002, len(accountUsers))
}
