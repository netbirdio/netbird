package store

import (
	"context"
	"fmt"
	"slices"
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

func TestSqlStore_GetAccountUsersPaginated(t *testing.T) {
	runTestForAllEngines(t, "../testdata/extended-store.sql", func(t *testing.T, store Store) {
		ctx := context.Background()
		accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"

		// The seed holds two regular users. Add enough to span several pages, a few
		// service users, and one non-deletable user that must never be listed.
		var users []*types.User
		for i := range 7 {
			users = append(users, types.NewUser(fmt.Sprintf("paged-user-%02d", i), types.UserRoleUser, false, false, "", []string{}, types.UserIssuedAPI, "", ""))
		}
		for i := range 3 {
			users = append(users, types.NewUser(fmt.Sprintf("paged-service-%02d", i), types.UserRoleUser, true, false, "svc", []string{}, types.UserIssuedAPI, "", ""))
		}
		nonDeletable := types.NewUser("paged-non-deletable", types.UserRoleAdmin, true, true, "integration", []string{"grp-a"}, types.UserIssuedIntegration, "", "")
		users = append(users, nonDeletable)
		for _, u := range users {
			u.AccountID = accountID
		}

		// Vary the fields the filters and sorts use. The seed's admin user has the auto group
		// cfefqs706sqkneg59g3g, and neither seed user has logged in or has pending_approval set.
		loginTime := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
		users[0].Role, users[0].AutoGroups, users[0].LastLogin = types.UserRoleAdmin, []string{"grp-a"}, new(loginTime.Add(time.Hour))
		users[1].Role, users[1].AutoGroups, users[1].PendingApproval = types.UserRoleNetworkAdmin, []string{"grp-a", "grp-b"}, true
		users[2].AutoGroups, users[2].LastLogin = []string{"grp-b"}, new(loginTime.Add(2*time.Hour))
		require.NoError(t, store.SaveUsers(ctx, users))

		// auto_groups can hold a value that isn't a JSON array; such users have no groups.
		db := store.(*SqlStore).db
		require.NoError(t, db.Exec("UPDATE users SET auto_groups = ? WHERE id = ?", "null", users[3].Id).Error)
		require.NoError(t, db.Exec("UPDATE users SET auto_groups = ? WHERE id = ?", "", users[4].Id).Error)
		require.NoError(t, db.Exec("UPDATE users SET auto_groups = NULL WHERE id = ?", users[5].Id).Error)

		const listedUsers = 12

		listIDs := func(t *testing.T, pagination PaginationState, filters UserFilters, sorting UserSorting) ([]string, int) {
			t.Helper()
			got, count, err := store.GetAccountUsersPaginated(ctx, LockingStrengthNone, accountID, pagination, filters, sorting)
			require.NoError(t, err)
			ids := make([]string, 0, len(got))
			for _, u := range got {
				ids = append(ids, u.Id)
			}
			return ids, count
		}
		allUsers := PaginationState{Page: 1, PageSize: 100}
		const seedAdmin, seedUser = "edafee4e-63fb-11ec-90d6-0242ac120003", "f4f6d672-63fb-11ec-90d6-0242ac120003"

		t.Run("pages cover every listed user once, in id order", func(t *testing.T) {
			var ids []string
			for page, wantLen := range []int{5, 5, 2} {
				got, count, err := store.GetAccountUsersPaginated(ctx, LockingStrengthNone, accountID,
					PaginationState{Page: page + 1, PageSize: 5}, UserFilters{}, UserSorting{})
				require.NoError(t, err)
				assert.Equal(t, listedUsers, count, "total count on page %d", page+1)
				assert.Len(t, got, wantLen, "users on page %d", page+1)
				for _, u := range got {
					ids = append(ids, u.Id)
				}
			}

			assert.Len(t, ids, listedUsers, "users across all pages")
			assert.True(t, slices.IsSorted(ids), "users should be ordered by id across pages, got %v", ids)
			assert.Len(t, slices.Compact(slices.Clone(ids)), listedUsers, "no user should appear on two pages")
			assert.NotContains(t, ids, nonDeletable.Id, "non-deletable users must not be listed")
		})

		t.Run("service_user filter", func(t *testing.T) {
			for _, tc := range []struct {
				serviceUser bool
				want        int
			}{
				{serviceUser: true, want: 3},
				{serviceUser: false, want: 9},
			} {
				got, count, err := store.GetAccountUsersPaginated(ctx, LockingStrengthNone, accountID,
					PaginationState{Page: 1, PageSize: 100}, UserFilters{ServiceUser: &tc.serviceUser}, UserSorting{})
				require.NoError(t, err)
				assert.Equal(t, tc.want, count, "total count with service_user=%v", tc.serviceUser)
				assert.Len(t, got, tc.want, "users with service_user=%v", tc.serviceUser)
				for _, u := range got {
					assert.Equal(t, tc.serviceUser, u.IsServiceUser, "user %s with service_user=%v", u.Id, tc.serviceUser)
				}
			}
		})

		t.Run("role filter matches any of the roles", func(t *testing.T) {
			ids, count := listIDs(t, allUsers, UserFilters{Roles: []types.UserRole{types.UserRoleAdmin, types.UserRoleNetworkAdmin}}, UserSorting{})
			assert.Equal(t, []string{seedAdmin, "paged-user-00", "paged-user-01"}, ids, "admins and network admins, without the non-deletable admin")
			assert.Equal(t, 3, count, "total count with the role filter")
		})

		t.Run("pending_approval filter counts unset as false", func(t *testing.T) {
			ids, count := listIDs(t, allUsers, UserFilters{PendingApproval: new(true)}, UserSorting{})
			assert.Equal(t, []string{"paged-user-01"}, ids, "users pending approval")
			assert.Equal(t, 1, count, "total count with pending_approval=true")

			ids, count = listIDs(t, allUsers, UserFilters{PendingApproval: new(false)}, UserSorting{})
			assert.Equal(t, listedUsers-1, count, "total count with pending_approval=false")
			assert.Contains(t, ids, seedUser, "a seed user with pending_approval unset is not pending")
			assert.NotContains(t, ids, "paged-user-01", "a pending user is excluded")
		})

		t.Run("user_ids filter", func(t *testing.T) {
			ids, count := listIDs(t, allUsers, UserFilters{UserIDs: []string{"paged-user-05", "paged-user-00", nonDeletable.Id, "no-such-user"}}, UserSorting{})
			assert.Equal(t, []string{"paged-user-00", "paged-user-05"}, ids, "listed users with the requested ids")
			assert.Equal(t, 2, count, "total count with the user_ids filter")
		})

		t.Run("group_ids filter matches any auto group", func(t *testing.T) {
			for _, tc := range []struct {
				groups []string
				want   []string
			}{
				{groups: []string{"grp-a"}, want: []string{"paged-user-00", "paged-user-01"}},
				{groups: []string{"grp-b", "cfefqs706sqkneg59g3g"}, want: []string{seedAdmin, "paged-user-01", "paged-user-02"}},
				{groups: []string{"no-such-group"}, want: []string{}},
			} {
				ids, count := listIDs(t, allUsers, UserFilters{GroupIDs: tc.groups}, UserSorting{})
				assert.Equal(t, tc.want, ids, "users with any of the groups %v", tc.groups)
				assert.Equal(t, len(tc.want), count, "total count with the groups %v", tc.groups)
			}
		})

		t.Run("is_current sorts the current user first", func(t *testing.T) {
			sorting := UserSorting{CurrentUserID: "paged-user-04", Fields: []UserSortingKey{{Field: UserSortByIsCurrent, Order: DescOrderBy}}}
			ids, _ := listIDs(t, PaginationState{Page: 1, PageSize: 3}, UserFilters{}, sorting)
			assert.Equal(t, []string{"paged-user-04", seedAdmin, seedUser}, ids, "the current user, then the rest by id")
		})

		t.Run("role sort breaks ties by id", func(t *testing.T) {
			sorting := UserSorting{Fields: []UserSortingKey{{Field: UserSortByRole, Order: AscOrderBy}}}
			ids, _ := listIDs(t, PaginationState{Page: 1, PageSize: 4}, UserFilters{}, sorting)
			assert.Equal(t, []string{seedAdmin, "paged-user-00", "paged-user-01", seedUser}, ids, "admins, then network admins, then users, each by id")
		})

		t.Run("last_login sort puts users who never logged in last", func(t *testing.T) {
			for _, tc := range []struct {
				order OrderBy
				want  []string
			}{
				{order: DescOrderBy, want: []string{"paged-user-02", "paged-user-00", seedAdmin, seedUser}},
				{order: AscOrderBy, want: []string{"paged-user-00", "paged-user-02", seedAdmin, seedUser}},
			} {
				sorting := UserSorting{Fields: []UserSortingKey{{Field: UserSortByLastLogin, Order: tc.order}}}
				page1, _ := listIDs(t, PaginationState{Page: 1, PageSize: 2}, UserFilters{}, sorting)
				page2, _ := listIDs(t, PaginationState{Page: 2, PageSize: 2}, UserFilters{}, sorting)
				assert.Equal(t, tc.want, append(page1, page2...), "first two pages with last_login order %v", tc.order)
			}
		})
	})
}

func TestSqlStore_SaveUserLastLogin(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/extended-store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	ctx := context.Background()
	accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"
	userID := "f4f6d672-63fb-11ec-90d6-0242ac120003"

	before, err := store.GetUserByUserID(ctx, LockingStrengthNone, userID)
	require.NoError(t, err)

	lastLoginOf := func() time.Time {
		user, err := store.GetUserByUserID(ctx, LockingStrengthNone, userID)
		require.NoError(t, err)
		return user.GetLastLogin().UTC()
	}

	first := time.Now().UTC().Truncate(time.Second)
	require.NoError(t, store.SaveUserLastLogin(ctx, accountID, userID, first))
	assert.True(t, first.Equal(lastLoginOf()), "first login must be stored")

	require.NoError(t, store.SaveUserLastLogin(ctx, accountID, userID, first))
	assert.True(t, first.Equal(lastLoginOf()), "repeating the same login must keep the stored value")

	later := first.Add(30 * time.Second)
	require.NoError(t, store.SaveUserLastLogin(ctx, accountID, userID, later))
	assert.True(t, later.Equal(lastLoginOf()), "a newer login must be written")

	require.NoError(t, store.SaveUserLastLogin(ctx, accountID, userID, first))
	assert.True(t, later.Equal(lastLoginOf()), "an older login must not overwrite a newer one")

	require.NoError(t, store.SaveUserLastLogin(ctx, accountID, userID, time.Time{}))
	assert.True(t, later.Equal(lastLoginOf()), "zero login must be ignored")

	err = store.SaveUserLastLogin(ctx, accountID, "unknown-user", later.Add(time.Hour))
	sErr, ok := status.FromError(err)
	require.True(t, ok, "unknown user must return a status error")
	assert.Equal(t, status.NotFound, sErr.Type())

	after, err := store.GetUserByUserID(ctx, LockingStrengthNone, userID)
	require.NoError(t, err)
	assert.Equal(t, before.Role, after.Role)
	assert.Equal(t, before.AutoGroups, after.AutoGroups)
	assert.Equal(t, before.Blocked, after.Blocked)
}
