package server

import (
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/server/activity"
	"github.com/netbirdio/netbird/management/server/jwtclaims"
)

const (
	mockAccountID       = "accountID"
	mockUserID          = "userID"
	mockServiceUserID   = "serviceUserID"
	mockRole            = "user"
	mockServiceUserName = "serviceUserName"
	mockTargetUserId    = "targetUserID"
	mockTokenID1        = "tokenID1"
	mockToken1          = "SoMeHaShEdToKeN1"
	mockTokenID2        = "tokenID2"
	mockToken2          = "SoMeHaShEdToKeN2"
	mockTokenName       = "tokenName"
	mockEmptyTokenName  = ""
	mockExpiresIn       = 7
	mockWrongExpiresIn  = 4506
)

func TestUser_CreatePAT_ForSameUser(t *testing.T) {
	store := newStore(t)
	account := newAccountWithId(mockAccountID, mockUserID, "")

	err := store.SaveAccount(account)
	if err != nil {
		t.Fatalf("Error when saving account: %s", err)
	}

	am := DefaultAccountManager{
		Store:      store,
		eventStore: &activity.InMemoryEventStore{},
	}

	pat, err := am.CreatePAT(mockAccountID, mockUserID, mockUserID, mockTokenName, mockExpiresIn)
	if err != nil {
		t.Fatalf("Error when adding PAT to user: %s", err)
	}

	assert.Equal(t, pat.CreatedBy, mockUserID)

	fileStore := am.Store.(*FileStore)
	tokenID := fileStore.HashedPAT2TokenID[pat.HashedToken]

	if tokenID == "" {
		t.Fatal("GetTokenIDByHashedToken failed after adding PAT")
	}

	assert.Equal(t, pat.ID, tokenID)

	userID := fileStore.TokenID2UserID[tokenID]
	if userID == "" {
		t.Fatal("GetUserByTokenId failed after adding PAT")
	}
	assert.Equal(t, mockUserID, userID)
}

func TestUser_CreatePAT_ForDifferentUser(t *testing.T) {
	store := newStore(t)
	account := newAccountWithId(mockAccountID, mockUserID, "")
	account.Users[mockTargetUserId] = &User{
		Id:            mockTargetUserId,
		IsServiceUser: false,
	}
	err := store.SaveAccount(account)
	if err != nil {
		t.Fatalf("Error when saving account: %s", err)
	}

	am := DefaultAccountManager{
		Store:      store,
		eventStore: &activity.InMemoryEventStore{},
	}

	_, err = am.CreatePAT(mockAccountID, mockUserID, mockTargetUserId, mockTokenName, mockExpiresIn)
	assert.Errorf(t, err, "Creating PAT for different user should thorw error")
}

func TestUser_CreatePAT_ForServiceUser(t *testing.T) {
	store := newStore(t)
	account := newAccountWithId(mockAccountID, mockUserID, "")
	account.Users[mockTargetUserId] = &User{
		Id:            mockTargetUserId,
		IsServiceUser: true,
	}
	err := store.SaveAccount(account)
	if err != nil {
		t.Fatalf("Error when saving account: %s", err)
	}

	am := DefaultAccountManager{
		Store:      store,
		eventStore: &activity.InMemoryEventStore{},
	}

	pat, err := am.CreatePAT(mockAccountID, mockUserID, mockTargetUserId, mockTokenName, mockExpiresIn)
	if err != nil {
		t.Fatalf("Error when adding PAT to user: %s", err)
	}

	assert.Equal(t, pat.CreatedBy, mockUserID)
}

func TestUser_CreatePAT_WithWrongExpiration(t *testing.T) {
	store := newStore(t)
	account := newAccountWithId(mockAccountID, mockUserID, "")

	err := store.SaveAccount(account)
	if err != nil {
		t.Fatalf("Error when saving account: %s", err)
	}

	am := DefaultAccountManager{
		Store:      store,
		eventStore: &activity.InMemoryEventStore{},
	}

	_, err = am.CreatePAT(mockAccountID, mockUserID, mockUserID, mockTokenName, mockWrongExpiresIn)
	assert.Errorf(t, err, "Wrong expiration should thorw error")
}

func TestUser_CreatePAT_WithEmptyName(t *testing.T) {
	store := newStore(t)
	account := newAccountWithId(mockAccountID, mockUserID, "")

	err := store.SaveAccount(account)
	if err != nil {
		t.Fatalf("Error when saving account: %s", err)
	}

	am := DefaultAccountManager{
		Store:      store,
		eventStore: &activity.InMemoryEventStore{},
	}

	_, err = am.CreatePAT(mockAccountID, mockUserID, mockUserID, mockEmptyTokenName, mockExpiresIn)
	assert.Errorf(t, err, "Wrong expiration should thorw error")
}

func TestUser_DeletePAT(t *testing.T) {
	store := newStore(t)
	account := newAccountWithId(mockAccountID, mockUserID, "")
	account.Users[mockUserID] = &User{
		Id: mockUserID,
		PATs: map[string]*PersonalAccessToken{
			mockTokenID1: {
				ID:          mockTokenID1,
				HashedToken: mockToken1,
			},
		},
	}
	err := store.SaveAccount(account)
	if err != nil {
		t.Fatalf("Error when saving account: %s", err)
	}

	am := DefaultAccountManager{
		Store:      store,
		eventStore: &activity.InMemoryEventStore{},
	}

	err = am.DeletePAT(mockAccountID, mockUserID, mockUserID, mockTokenID1)
	if err != nil {
		t.Fatalf("Error when adding PAT to user: %s", err)
	}

	assert.Nil(t, store.Accounts[mockAccountID].Users[mockUserID].PATs[mockTokenID1])
	assert.Empty(t, store.HashedPAT2TokenID[mockToken1])
	assert.Empty(t, store.TokenID2UserID[mockTokenID1])
}

func TestUser_GetPAT(t *testing.T) {
	store := newStore(t)
	account := newAccountWithId(mockAccountID, mockUserID, "")
	account.Users[mockUserID] = &User{
		Id: mockUserID,
		PATs: map[string]*PersonalAccessToken{
			mockTokenID1: {
				ID:          mockTokenID1,
				HashedToken: mockToken1,
			},
		},
	}
	err := store.SaveAccount(account)
	if err != nil {
		t.Fatalf("Error when saving account: %s", err)
	}

	am := DefaultAccountManager{
		Store:      store,
		eventStore: &activity.InMemoryEventStore{},
	}

	pat, err := am.GetPAT(mockAccountID, mockUserID, mockUserID, mockTokenID1)
	if err != nil {
		t.Fatalf("Error when adding PAT to user: %s", err)
	}

	assert.Equal(t, mockTokenID1, pat.ID)
	assert.Equal(t, mockToken1, pat.HashedToken)
}

func TestUser_GetAllPATs(t *testing.T) {
	store := newStore(t)
	account := newAccountWithId(mockAccountID, mockUserID, "")
	account.Users[mockUserID] = &User{
		Id: mockUserID,
		PATs: map[string]*PersonalAccessToken{
			mockTokenID1: {
				ID:          mockTokenID1,
				HashedToken: mockToken1,
			},
			mockTokenID2: {
				ID:          mockTokenID2,
				HashedToken: mockToken2,
			},
		},
	}
	err := store.SaveAccount(account)
	if err != nil {
		t.Fatalf("Error when saving account: %s", err)
	}

	am := DefaultAccountManager{
		Store:      store,
		eventStore: &activity.InMemoryEventStore{},
	}

	pats, err := am.GetAllPATs(mockAccountID, mockUserID, mockUserID)
	if err != nil {
		t.Fatalf("Error when adding PAT to user: %s", err)
	}

	assert.Equal(t, 2, len(pats))
}

func TestUser_Copy(t *testing.T) {
	// this is an imaginary case which will never be in DB this way
	user := User{
		Id:              "userId",
		Role:            "role",
		IsServiceUser:   true,
		ServiceUserName: "servicename",
		AutoGroups:      []string{"group1", "group2"},
		PATs: map[string]*PersonalAccessToken{
			"pat1": {
				ID:             "pat1",
				Name:           "First PAT",
				HashedToken:    "SoMeHaShEdToKeN",
				ExpirationDate: time.Now().AddDate(0, 0, 7),
				CreatedBy:      "userId",
				CreatedAt:      time.Now(),
				LastUsed:       time.Now(),
			},
		},
		Blocked: false,
	}

	err := validateStruct(user)
	if err != nil {
		t.Fatalf("Test needs update: dummy struct has not all fields set : %s", err)
	}

	copiedUser := user.Copy()

	assert.True(t, cmp.Equal(user, *copiedUser))
}

// based on https://medium.com/@anajankow/fast-check-if-all-struct-fields-are-set-in-golang-bba1917213d2
func validateStruct(s interface{}) (err error) {

	structType := reflect.TypeOf(s)
	structVal := reflect.ValueOf(s)
	fieldNum := structVal.NumField()

	for i := 0; i < fieldNum; i++ {
		field := structVal.Field(i)
		fieldName := structType.Field(i).Name

		isSet := field.IsValid() && (!field.IsZero() || field.Type().String() == "bool")

		if !isSet {
			err = fmt.Errorf("%v%s in not set; ", err, fieldName)
		}

	}

	return err
}

func TestUser_CreateServiceUser(t *testing.T) {
	store := newStore(t)
	account := newAccountWithId(mockAccountID, mockUserID, "")

	err := store.SaveAccount(account)
	if err != nil {
		t.Fatalf("Error when saving account: %s", err)
	}

	am := DefaultAccountManager{
		Store:      store,
		eventStore: &activity.InMemoryEventStore{},
	}

	user, err := am.createServiceUser(mockAccountID, mockUserID, mockRole, mockServiceUserName, []string{"group1", "group2"})
	if err != nil {
		t.Fatalf("Error when creating service user: %s", err)
	}

	assert.Equal(t, 2, len(store.Accounts[mockAccountID].Users))
	assert.NotNil(t, store.Accounts[mockAccountID].Users[user.ID])
	assert.True(t, store.Accounts[mockAccountID].Users[user.ID].IsServiceUser)
	assert.Equal(t, mockServiceUserName, store.Accounts[mockAccountID].Users[user.ID].ServiceUserName)
	assert.Equal(t, UserRole(mockRole), store.Accounts[mockAccountID].Users[user.ID].Role)
	assert.Equal(t, []string{"group1", "group2"}, store.Accounts[mockAccountID].Users[user.ID].AutoGroups)
	assert.Equal(t, map[string]*PersonalAccessToken{}, store.Accounts[mockAccountID].Users[user.ID].PATs)

	assert.Zero(t, user.Email)
	assert.True(t, user.IsServiceUser)
	assert.Equal(t, "active", user.Status)
}

func TestUser_CreateUser_ServiceUser(t *testing.T) {
	store := newStore(t)
	account := newAccountWithId(mockAccountID, mockUserID, "")

	err := store.SaveAccount(account)
	if err != nil {
		t.Fatalf("Error when saving account: %s", err)
	}

	am := DefaultAccountManager{
		Store:      store,
		eventStore: &activity.InMemoryEventStore{},
	}

	user, err := am.CreateUser(mockAccountID, mockUserID, &UserInfo{
		Name:          mockServiceUserName,
		Role:          mockRole,
		IsServiceUser: true,
		AutoGroups:    []string{"group1", "group2"},
	})

	if err != nil {
		t.Fatalf("Error when creating user: %s", err)
	}

	assert.True(t, user.IsServiceUser)
	assert.Equal(t, 2, len(store.Accounts[mockAccountID].Users))
	assert.True(t, store.Accounts[mockAccountID].Users[user.ID].IsServiceUser)
	assert.Equal(t, mockServiceUserName, store.Accounts[mockAccountID].Users[user.ID].ServiceUserName)
	assert.Equal(t, UserRole(mockRole), store.Accounts[mockAccountID].Users[user.ID].Role)
	assert.Equal(t, []string{"group1", "group2"}, store.Accounts[mockAccountID].Users[user.ID].AutoGroups)

	assert.Equal(t, mockServiceUserName, user.Name)
	assert.Equal(t, mockRole, user.Role)
	assert.Equal(t, []string{"group1", "group2"}, user.AutoGroups)
	assert.Equal(t, "active", user.Status)
}

func TestUser_CreateUser_RegularUser(t *testing.T) {
	store := newStore(t)
	account := newAccountWithId(mockAccountID, mockUserID, "")

	err := store.SaveAccount(account)
	if err != nil {
		t.Fatalf("Error when saving account: %s", err)
	}

	am := DefaultAccountManager{
		Store:      store,
		eventStore: &activity.InMemoryEventStore{},
	}

	_, err = am.CreateUser(mockAccountID, mockUserID, &UserInfo{
		Name:          mockServiceUserName,
		Role:          mockRole,
		IsServiceUser: false,
		AutoGroups:    []string{"group1", "group2"},
	})

	assert.Errorf(t, err, "Not configured IDP will throw error but right path used")
}

func TestUser_DeleteUser_ServiceUser(t *testing.T) {
	store := newStore(t)
	account := newAccountWithId(mockAccountID, mockUserID, "")
	account.Users[mockServiceUserID] = &User{
		Id:              mockServiceUserID,
		IsServiceUser:   true,
		ServiceUserName: mockServiceUserName,
	}

	err := store.SaveAccount(account)
	if err != nil {
		t.Fatalf("Error when saving account: %s", err)
	}

	am := DefaultAccountManager{
		Store:      store,
		eventStore: &activity.InMemoryEventStore{},
	}

	err = am.DeleteUser(mockAccountID, mockUserID, mockServiceUserID)
	if err != nil {
		t.Fatalf("Error when deleting user: %s", err)
	}

	assert.Equal(t, 1, len(store.Accounts[mockAccountID].Users))
	assert.Nil(t, store.Accounts[mockAccountID].Users[mockServiceUserID])
}

func TestUser_DeleteUser_regularUser(t *testing.T) {
	store := newStore(t)
	account := newAccountWithId(mockAccountID, mockUserID, "")

	err := store.SaveAccount(account)
	if err != nil {
		t.Fatalf("Error when saving account: %s", err)
	}

	am := DefaultAccountManager{
		Store:      store,
		eventStore: &activity.InMemoryEventStore{},
	}

	err = am.DeleteUser(mockAccountID, mockUserID, mockUserID)

	assert.Errorf(t, err, "Regular users can not be deleted (yet)")
}

func TestDefaultAccountManager_GetUser(t *testing.T) {
	store := newStore(t)
	account := newAccountWithId(mockAccountID, mockUserID, "")

	err := store.SaveAccount(account)
	if err != nil {
		t.Fatalf("Error when saving account: %s", err)
	}

	am := DefaultAccountManager{
		Store:      store,
		eventStore: &activity.InMemoryEventStore{},
	}

	claims := jwtclaims.AuthorizationClaims{
		UserId: mockUserID,
	}

	user, err := am.GetUser(claims)
	if err != nil {
		t.Fatalf("Error when checking user role: %s", err)
	}

	assert.Equal(t, mockUserID, user.Id)
	assert.True(t, user.IsAdmin())
	assert.False(t, user.IsBlocked())
}

func TestUser_IsAdmin(t *testing.T) {

	user := NewAdminUser(mockUserID)
	assert.True(t, user.IsAdmin())

	user = NewRegularUser(mockUserID)
	assert.False(t, user.IsAdmin())
}

func TestUser_GetUsersFromAccount_ForAdmin(t *testing.T) {
	store := newStore(t)
	account := newAccountWithId(mockAccountID, mockUserID, "")
	account.Users[mockServiceUserID] = &User{
		Id:            mockServiceUserID,
		Role:          "user",
		IsServiceUser: true,
	}

	err := store.SaveAccount(account)
	if err != nil {
		t.Fatalf("Error when saving account: %s", err)
	}

	am := DefaultAccountManager{
		Store:      store,
		eventStore: &activity.InMemoryEventStore{},
	}

	users, err := am.GetUsersFromAccount(mockAccountID, mockUserID)
	if err != nil {
		t.Fatalf("Error when getting users from account: %s", err)
	}

	assert.Equal(t, 2, len(users))
}

func TestUser_GetUsersFromAccount_ForUser(t *testing.T) {
	store := newStore(t)
	account := newAccountWithId(mockAccountID, mockUserID, "")
	account.Users[mockServiceUserID] = &User{
		Id:            mockServiceUserID,
		Role:          "user",
		IsServiceUser: true,
	}

	err := store.SaveAccount(account)
	if err != nil {
		t.Fatalf("Error when saving account: %s", err)
	}

	am := DefaultAccountManager{
		Store:      store,
		eventStore: &activity.InMemoryEventStore{},
	}

	users, err := am.GetUsersFromAccount(mockAccountID, mockServiceUserID)
	if err != nil {
		t.Fatalf("Error when getting users from account: %s", err)
	}

	assert.Equal(t, 1, len(users))
	assert.Equal(t, mockServiceUserID, users[0].ID)
}

func TestDefaultAccountManager_SaveUser(t *testing.T) {
	manager, err := createManager(t)
	if err != nil {
		t.Fatal(err)
		return
	}

	regularUserID := "regularUser"

	tt := []struct {
		name           string
		adminInitiator bool
		update         *User
		expectedErr    bool
	}{
		{
			name:           "Should_Fail_To_Update_Admin_Role",
			expectedErr:    true,
			adminInitiator: true,
			update: &User{
				Id:      userID,
				Role:    UserRoleUser,
				Blocked: false,
			},
		}, {
			name:           "Should_Fail_When_Admin_Blocks_Themselves",
			expectedErr:    true,
			adminInitiator: true,
			update: &User{
				Id:      userID,
				Role:    UserRoleAdmin,
				Blocked: true,
			},
		},
		{
			name:           "Should_Fail_To_Update_Non_Existing_User",
			expectedErr:    true,
			adminInitiator: true,
			update: &User{
				Id:      userID,
				Role:    UserRoleAdmin,
				Blocked: true,
			},
		},
		{
			name:           "Should_Fail_To_Update_When_Initiator_Is_Not_An_Admin",
			expectedErr:    true,
			adminInitiator: false,
			update: &User{
				Id:      userID,
				Role:    UserRoleAdmin,
				Blocked: true,
			},
		},
		{
			name:           "Should_Update_User",
			expectedErr:    false,
			adminInitiator: true,
			update: &User{
				Id:      regularUserID,
				Role:    UserRoleAdmin,
				Blocked: true,
			},
		},
	}

	for _, tc := range tt {

		// create an account and an admin user
		account, err := manager.GetOrCreateAccountByUser(userID, "netbird.io")
		if err != nil {
			t.Fatal(err)
		}

		// create a regular user
		account.Users[regularUserID] = NewRegularUser(regularUserID)
		err = manager.Store.SaveAccount(account)
		if err != nil {
			t.Fatal(err)
		}

		initiatorID := userID
		if !tc.adminInitiator {
			initiatorID = regularUserID
		}

		updated, err := manager.SaveUser(account.Id, initiatorID, tc.update)
		if tc.expectedErr {
			require.Errorf(t, err, "expecting SaveUser to throw an error")
		} else {
			require.NoError(t, err, "expecting SaveUser not to throw an error")
			assert.NotNil(t, updated)

			assert.Equal(t, string(tc.update.Role), updated.Role)
			assert.Equal(t, tc.update.IsBlocked(), updated.IsBlocked)
		}
	}

}
