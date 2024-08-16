package server

import (
	"context"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/eko/gocache/v3/cache"
	cacheStore "github.com/eko/gocache/v3/store"
	"github.com/google/go-cmp/cmp"
	nbgroup "github.com/netbirdio/netbird/management/server/group"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	gocache "github.com/patrickmn/go-cache"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/netbirdio/netbird/management/server/activity"
	"github.com/netbirdio/netbird/management/server/idp"
	"github.com/netbirdio/netbird/management/server/integration_reference"
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
	defer store.Close(context.Background())
	account := newAccountWithId(context.Background(), mockAccountID, mockUserID, "")

	err := store.SaveAccount(context.Background(), account)
	if err != nil {
		t.Fatalf("Error when saving account: %s", err)
	}

	am := DefaultAccountManager{
		Store:      store,
		eventStore: &activity.InMemoryEventStore{},
	}

	pat, err := am.CreatePAT(context.Background(), mockAccountID, mockUserID, mockUserID, mockTokenName, mockExpiresIn)
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
	defer store.Close(context.Background())
	account := newAccountWithId(context.Background(), mockAccountID, mockUserID, "")
	account.Users[mockTargetUserId] = &User{
		Id:            mockTargetUserId,
		IsServiceUser: false,
	}
	err := store.SaveAccount(context.Background(), account)
	if err != nil {
		t.Fatalf("Error when saving account: %s", err)
	}

	am := DefaultAccountManager{
		Store:      store,
		eventStore: &activity.InMemoryEventStore{},
	}

	_, err = am.CreatePAT(context.Background(), mockAccountID, mockUserID, mockTargetUserId, mockTokenName, mockExpiresIn)
	assert.Errorf(t, err, "Creating PAT for different user should thorw error")
}

func TestUser_CreatePAT_ForServiceUser(t *testing.T) {
	store := newStore(t)
	defer store.Close(context.Background())
	account := newAccountWithId(context.Background(), mockAccountID, mockUserID, "")
	account.Users[mockTargetUserId] = &User{
		Id:            mockTargetUserId,
		IsServiceUser: true,
	}
	err := store.SaveAccount(context.Background(), account)
	if err != nil {
		t.Fatalf("Error when saving account: %s", err)
	}

	am := DefaultAccountManager{
		Store:      store,
		eventStore: &activity.InMemoryEventStore{},
	}

	pat, err := am.CreatePAT(context.Background(), mockAccountID, mockUserID, mockTargetUserId, mockTokenName, mockExpiresIn)
	if err != nil {
		t.Fatalf("Error when adding PAT to user: %s", err)
	}

	assert.Equal(t, pat.CreatedBy, mockUserID)
}

func TestUser_CreatePAT_WithWrongExpiration(t *testing.T) {
	store := newStore(t)
	defer store.Close(context.Background())
	account := newAccountWithId(context.Background(), mockAccountID, mockUserID, "")

	err := store.SaveAccount(context.Background(), account)
	if err != nil {
		t.Fatalf("Error when saving account: %s", err)
	}

	am := DefaultAccountManager{
		Store:      store,
		eventStore: &activity.InMemoryEventStore{},
	}

	_, err = am.CreatePAT(context.Background(), mockAccountID, mockUserID, mockUserID, mockTokenName, mockWrongExpiresIn)
	assert.Errorf(t, err, "Wrong expiration should thorw error")
}

func TestUser_CreatePAT_WithEmptyName(t *testing.T) {
	store := newStore(t)
	defer store.Close(context.Background())
	account := newAccountWithId(context.Background(), mockAccountID, mockUserID, "")

	err := store.SaveAccount(context.Background(), account)
	if err != nil {
		t.Fatalf("Error when saving account: %s", err)
	}

	am := DefaultAccountManager{
		Store:      store,
		eventStore: &activity.InMemoryEventStore{},
	}

	_, err = am.CreatePAT(context.Background(), mockAccountID, mockUserID, mockUserID, mockEmptyTokenName, mockExpiresIn)
	assert.Errorf(t, err, "Wrong expiration should thorw error")
}

func TestUser_DeletePAT(t *testing.T) {
	store := newStore(t)
	defer store.Close(context.Background())
	account := newAccountWithId(context.Background(), mockAccountID, mockUserID, "")
	account.Users[mockUserID] = &User{
		Id: mockUserID,
		PATs: map[string]*PersonalAccessToken{
			mockTokenID1: {
				ID:          mockTokenID1,
				HashedToken: mockToken1,
			},
		},
	}
	err := store.SaveAccount(context.Background(), account)
	if err != nil {
		t.Fatalf("Error when saving account: %s", err)
	}

	am := DefaultAccountManager{
		Store:      store,
		eventStore: &activity.InMemoryEventStore{},
	}

	err = am.DeletePAT(context.Background(), mockAccountID, mockUserID, mockUserID, mockTokenID1)
	if err != nil {
		t.Fatalf("Error when adding PAT to user: %s", err)
	}

	assert.Nil(t, store.Accounts[mockAccountID].Users[mockUserID].PATs[mockTokenID1])
	assert.Empty(t, store.HashedPAT2TokenID[mockToken1])
	assert.Empty(t, store.TokenID2UserID[mockTokenID1])
}

func TestUser_GetPAT(t *testing.T) {
	store := newStore(t)
	defer store.Close(context.Background())
	account := newAccountWithId(context.Background(), mockAccountID, mockUserID, "")
	account.Users[mockUserID] = &User{
		Id: mockUserID,
		PATs: map[string]*PersonalAccessToken{
			mockTokenID1: {
				ID:          mockTokenID1,
				HashedToken: mockToken1,
			},
		},
	}
	err := store.SaveAccount(context.Background(), account)
	if err != nil {
		t.Fatalf("Error when saving account: %s", err)
	}

	am := DefaultAccountManager{
		Store:      store,
		eventStore: &activity.InMemoryEventStore{},
	}

	pat, err := am.GetPAT(context.Background(), mockAccountID, mockUserID, mockUserID, mockTokenID1)
	if err != nil {
		t.Fatalf("Error when adding PAT to user: %s", err)
	}

	assert.Equal(t, mockTokenID1, pat.ID)
	assert.Equal(t, mockToken1, pat.HashedToken)
}

func TestUser_GetAllPATs(t *testing.T) {
	store := newStore(t)
	defer store.Close(context.Background())
	account := newAccountWithId(context.Background(), mockAccountID, mockUserID, "")
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
	err := store.SaveAccount(context.Background(), account)
	if err != nil {
		t.Fatalf("Error when saving account: %s", err)
	}

	am := DefaultAccountManager{
		Store:      store,
		eventStore: &activity.InMemoryEventStore{},
	}

	pats, err := am.GetAllPATs(context.Background(), mockAccountID, mockUserID, mockUserID)
	if err != nil {
		t.Fatalf("Error when adding PAT to user: %s", err)
	}

	assert.Equal(t, 2, len(pats))
}

func TestUser_Copy(t *testing.T) {
	// this is an imaginary case which will never be in DB this way
	user := User{
		Id:              "userId",
		AccountID:       "accountId",
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
		Blocked:   false,
		LastLogin: time.Now().UTC(),
		CreatedAt: time.Now().UTC(),
		Issued:    "test",
		IntegrationReference: integration_reference.IntegrationReference{
			ID:              0,
			IntegrationType: "test",
		},
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

		// skip gorm internal fields
		if json, ok := structType.Field(i).Tag.Lookup("json"); ok && json == "-" {
			continue
		}

		isSet := field.IsValid() && (!field.IsZero() || field.Type().String() == "bool")

		if !isSet {
			err = fmt.Errorf("%v%s in not set; ", err, fieldName)
		}

	}

	return err
}

func TestUser_CreateServiceUser(t *testing.T) {
	store := newStore(t)
	defer store.Close(context.Background())
	account := newAccountWithId(context.Background(), mockAccountID, mockUserID, "")

	err := store.SaveAccount(context.Background(), account)
	if err != nil {
		t.Fatalf("Error when saving account: %s", err)
	}

	am := DefaultAccountManager{
		Store:      store,
		eventStore: &activity.InMemoryEventStore{},
	}

	user, err := am.createServiceUser(context.Background(), mockAccountID, mockUserID, mockRole, mockServiceUserName, false, []string{"group1", "group2"})
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

	_, err = am.createServiceUser(context.Background(), mockAccountID, mockUserID, UserRoleOwner, mockServiceUserName, false, nil)
	if err == nil {
		t.Fatal("should return error when creating service user with owner role")
	}
}

func TestUser_CreateUser_ServiceUser(t *testing.T) {
	store := newStore(t)
	defer store.Close(context.Background())
	account := newAccountWithId(context.Background(), mockAccountID, mockUserID, "")

	err := store.SaveAccount(context.Background(), account)
	if err != nil {
		t.Fatalf("Error when saving account: %s", err)
	}

	am := DefaultAccountManager{
		Store:      store,
		eventStore: &activity.InMemoryEventStore{},
	}

	user, err := am.CreateUser(context.Background(), mockAccountID, mockUserID, &UserInfo{
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
	defer store.Close(context.Background())
	account := newAccountWithId(context.Background(), mockAccountID, mockUserID, "")

	err := store.SaveAccount(context.Background(), account)
	if err != nil {
		t.Fatalf("Error when saving account: %s", err)
	}

	am := DefaultAccountManager{
		Store:      store,
		eventStore: &activity.InMemoryEventStore{},
	}

	_, err = am.CreateUser(context.Background(), mockAccountID, mockUserID, &UserInfo{
		Name:          mockServiceUserName,
		Role:          mockRole,
		IsServiceUser: false,
		AutoGroups:    []string{"group1", "group2"},
	})

	assert.Errorf(t, err, "Not configured IDP will throw error but right path used")
}

func TestUser_InviteNewUser(t *testing.T) {
	store := newStore(t)
	defer store.Close(context.Background())
	account := newAccountWithId(context.Background(), mockAccountID, mockUserID, "")

	err := store.SaveAccount(context.Background(), account)
	if err != nil {
		t.Fatalf("Error when saving account: %s", err)
	}

	am := DefaultAccountManager{
		Store:        store,
		eventStore:   &activity.InMemoryEventStore{},
		cacheLoading: map[string]chan struct{}{},
	}

	goCacheClient := gocache.New(CacheExpirationMax, 30*time.Minute)
	goCacheStore := cacheStore.NewGoCache(goCacheClient)
	am.cacheManager = cache.NewLoadable[[]*idp.UserData](am.loadAccount, cache.New[[]*idp.UserData](goCacheStore))

	mockData := []*idp.UserData{
		{
			Email: "user@test.com",
			Name:  "user",
			ID:    mockUserID,
		},
	}

	idpMock := idp.MockIDP{
		CreateUserFunc: func(_ context.Context, email, name, accountID, invitedByEmail string) (*idp.UserData, error) {
			newData := &idp.UserData{
				Email: email,
				Name:  name,
				ID:    "id",
			}

			mockData = append(mockData, newData)

			return newData, nil
		},
		GetAccountFunc: func(_ context.Context, accountId string) ([]*idp.UserData, error) {
			return mockData, nil
		},
	}

	am.idpManager = &idpMock

	// test if new invite with regular role works
	_, err = am.inviteNewUser(context.Background(), mockAccountID, mockUserID, &UserInfo{
		Name:          mockServiceUserName,
		Role:          mockRole,
		Email:         "test@teste.com",
		IsServiceUser: false,
		AutoGroups:    []string{"group1", "group2"},
	})

	assert.NoErrorf(t, err, "Invite user should not throw error")

	// test if new invite with owner role fails
	_, err = am.inviteNewUser(context.Background(), mockAccountID, mockUserID, &UserInfo{
		Name:          mockServiceUserName,
		Role:          string(UserRoleOwner),
		Email:         "test2@teste.com",
		IsServiceUser: false,
		AutoGroups:    []string{"group1", "group2"},
	})

	assert.Errorf(t, err, "Invite user with owner role should throw error")
}

func TestUser_DeleteUser_ServiceUser(t *testing.T) {
	tests := []struct {
		name             string
		serviceUser      *User
		assertErrFunc    assert.ErrorAssertionFunc
		assertErrMessage string
	}{
		{
			name: "Can delete service user",
			serviceUser: &User{
				Id:              mockServiceUserID,
				IsServiceUser:   true,
				ServiceUserName: mockServiceUserName,
			},
			assertErrFunc: assert.NoError,
		},
		{
			name: "Cannot delete non-deletable service user",
			serviceUser: &User{
				Id:              mockServiceUserID,
				IsServiceUser:   true,
				ServiceUserName: mockServiceUserName,
				NonDeletable:    true,
			},
			assertErrFunc:    assert.Error,
			assertErrMessage: "service user is marked as non-deletable",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := newStore(t)
			account := newAccountWithId(context.Background(), mockAccountID, mockUserID, "")
			account.Users[mockServiceUserID] = tt.serviceUser

			err := store.SaveAccount(context.Background(), account)
			if err != nil {
				t.Fatalf("Error when saving account: %s", err)
			}

			am := DefaultAccountManager{
				Store:      store,
				eventStore: &activity.InMemoryEventStore{},
			}

			err = am.DeleteUser(context.Background(), mockAccountID, mockUserID, mockServiceUserID)
			tt.assertErrFunc(t, err, tt.assertErrMessage)

			if err != nil {
				assert.Equal(t, 2, len(store.Accounts[mockAccountID].Users))
				assert.NotNil(t, store.Accounts[mockAccountID].Users[mockServiceUserID])
			} else {
				assert.Equal(t, 1, len(store.Accounts[mockAccountID].Users))
				assert.Nil(t, store.Accounts[mockAccountID].Users[mockServiceUserID])
			}
		})
	}
}

func TestUser_DeleteUser_SelfDelete(t *testing.T) {
	store := newStore(t)
	defer store.Close(context.Background())
	account := newAccountWithId(context.Background(), mockAccountID, mockUserID, "")

	err := store.SaveAccount(context.Background(), account)
	if err != nil {
		t.Fatalf("Error when saving account: %s", err)
	}

	am := DefaultAccountManager{
		Store:      store,
		eventStore: &activity.InMemoryEventStore{},
	}

	err = am.DeleteUser(context.Background(), mockAccountID, mockUserID, mockUserID)
	if err == nil {
		t.Fatalf("failed to prevent self deletion")
	}
}

func TestUser_DeleteUser_regularUser(t *testing.T) {
	store := newStore(t)
	defer store.Close(context.Background())
	account := newAccountWithId(context.Background(), mockAccountID, mockUserID, "")

	targetId := "user2"
	account.Users[targetId] = &User{
		Id:              targetId,
		IsServiceUser:   true,
		ServiceUserName: "user2username",
	}
	targetId = "user3"
	account.Users[targetId] = &User{
		Id:            targetId,
		IsServiceUser: false,
		Issued:        UserIssuedAPI,
	}
	targetId = "user4"
	account.Users[targetId] = &User{
		Id:            targetId,
		IsServiceUser: false,
		Issued:        UserIssuedIntegration,
	}

	targetId = "user5"
	account.Users[targetId] = &User{
		Id:            targetId,
		IsServiceUser: false,
		Issued:        UserIssuedAPI,
		Role:          UserRoleOwner,
	}

	err := store.SaveAccount(context.Background(), account)
	if err != nil {
		t.Fatalf("Error when saving account: %s", err)
	}

	am := DefaultAccountManager{
		Store:                   store,
		eventStore:              &activity.InMemoryEventStore{},
		integratedPeerValidator: MocIntegratedValidator{},
	}

	testCases := []struct {
		name             string
		userID           string
		assertErrFunc    assert.ErrorAssertionFunc
		assertErrMessage string
	}{
		{
			name:          "Delete service user successfully ",
			userID:        "user2",
			assertErrFunc: assert.NoError,
		},
		{
			name:          "Delete regular user successfully ",
			userID:        "user3",
			assertErrFunc: assert.NoError,
		},
		{
			name:             "Delete integration regular user permission denied ",
			userID:           "user4",
			assertErrFunc:    assert.Error,
			assertErrMessage: "only admin service user can delete this user",
		},
		{
			name:             "Delete user with owner role should return permission denied ",
			userID:           "user5",
			assertErrFunc:    assert.Error,
			assertErrMessage: "unable to delete a user with owner role",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			err = am.DeleteUser(context.Background(), mockAccountID, mockUserID, testCase.userID)
			testCase.assertErrFunc(t, err, testCase.assertErrMessage)
		})
	}

}

func TestUser_DeleteUser_RegularUsers(t *testing.T) {
	store := newStore(t)
	defer store.Close(context.Background())
	account := newAccountWithId(context.Background(), mockAccountID, mockUserID, "")

	targetId := "user2"
	account.Users[targetId] = &User{
		Id:              targetId,
		IsServiceUser:   true,
		ServiceUserName: "user2username",
	}
	targetId = "user3"
	account.Users[targetId] = &User{
		Id:            targetId,
		IsServiceUser: false,
		Issued:        UserIssuedAPI,
	}
	targetId = "user4"
	account.Users[targetId] = &User{
		Id:            targetId,
		IsServiceUser: false,
		Issued:        UserIssuedIntegration,
	}

	targetId = "user5"
	account.Users[targetId] = &User{
		Id:            targetId,
		IsServiceUser: false,
		Issued:        UserIssuedAPI,
		Role:          UserRoleOwner,
	}
	account.Users["user6"] = &User{
		Id:            "user6",
		IsServiceUser: false,
		Issued:        UserIssuedAPI,
	}
	account.Users["user7"] = &User{
		Id:            "user7",
		IsServiceUser: false,
		Issued:        UserIssuedAPI,
	}
	account.Users["user8"] = &User{
		Id:            "user8",
		IsServiceUser: false,
		Issued:        UserIssuedAPI,
		Role:          UserRoleAdmin,
	}
	account.Users["user9"] = &User{
		Id:            "user9",
		IsServiceUser: false,
		Issued:        UserIssuedAPI,
		Role:          UserRoleAdmin,
	}

	err := store.SaveAccount(context.Background(), account)
	if err != nil {
		t.Fatalf("Error when saving account: %s", err)
	}

	am := DefaultAccountManager{
		Store:                   store,
		eventStore:              &activity.InMemoryEventStore{},
		integratedPeerValidator: MocIntegratedValidator{},
	}

	testCases := []struct {
		name               string
		userIDs            []string
		expectedReasons    []string
		expectedDeleted    []string
		expectedNotDeleted []string
	}{
		{
			name:            "Delete service user successfully ",
			userIDs:         []string{"user2"},
			expectedDeleted: []string{"user2"},
		},
		{
			name:            "Delete regular user successfully",
			userIDs:         []string{"user3"},
			expectedDeleted: []string{"user3"},
		},
		{
			name:               "Delete integration regular user permission denied",
			userIDs:            []string{"user4"},
			expectedReasons:    []string{"only integration service user can delete this user"},
			expectedNotDeleted: []string{"user4"},
		},
		{
			name:               "Delete user with owner role should return permission denied",
			userIDs:            []string{"user5"},
			expectedReasons:    []string{"unable to delete a user: user5 with owner role"},
			expectedNotDeleted: []string{"user5"},
		},
		{
			name:               "Delete multiple users with mixed results",
			userIDs:            []string{"user5", "user5", "user6", "user7"},
			expectedReasons:    []string{"only integration service user can delete this user", "unable to delete a user: user5 with owner role"},
			expectedDeleted:    []string{"user6", "user7"},
			expectedNotDeleted: []string{"user4", "user5"},
		},
		{
			name:               "Delete non-existent user",
			userIDs:            []string{"non-existent-user"},
			expectedReasons:    []string{"target user: non-existent-user not found"},
			expectedNotDeleted: []string{},
		},
		{
			name:            "Delete multiple regular users successfully",
			userIDs:         []string{"user8", "user9"},
			expectedDeleted: []string{"user8", "user9"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err = am.DeleteRegularUsers(context.Background(), mockAccountID, mockUserID, tc.userIDs)
			if len(tc.expectedReasons) > 0 {
				assert.Error(t, err)
				var foundExpectedErrors int

				wrappedErr, ok := err.(interface{ Unwrap() []error })
				assert.Equal(t, ok, true)

				for _, e := range wrappedErr.Unwrap() {
					assert.Contains(t, tc.expectedReasons, e.Error(), "unexpected error message")
					foundExpectedErrors++
				}

				assert.Equal(t, len(tc.expectedReasons), foundExpectedErrors, "not all expected errors were found")
			} else {
				assert.NoError(t, err)
			}

			acc, err := am.GetAccountByUserOrAccountID(context.Background(), "", account.Id, "")
			assert.NoError(t, err)

			for _, id := range tc.expectedDeleted {
				_, exists := acc.Users[id]
				assert.False(t, exists, "user should have been deleted: %s", id)
			}

			for _, id := range tc.expectedNotDeleted {
				user, exists := acc.Users[id]
				assert.True(t, exists, "user should not have been deleted: %s", id)
				assert.NotNil(t, user, "user should exist: %s", id)
			}
		})
	}
}

func TestDefaultAccountManager_GetUser(t *testing.T) {
	store := newStore(t)
	defer store.Close(context.Background())
	account := newAccountWithId(context.Background(), mockAccountID, mockUserID, "")

	err := store.SaveAccount(context.Background(), account)
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

	user, err := am.GetUser(context.Background(), claims)
	if err != nil {
		t.Fatalf("Error when checking user role: %s", err)
	}

	assert.Equal(t, mockUserID, user.Id)
	assert.True(t, user.HasAdminPower())
	assert.False(t, user.IsBlocked())
}

func TestDefaultAccountManager_ListUsers(t *testing.T) {
	store := newStore(t)
	defer store.Close(context.Background())
	account := newAccountWithId(context.Background(), mockAccountID, mockUserID, "")
	account.Users["normal_user1"] = NewRegularUser("normal_user1")
	account.Users["normal_user2"] = NewRegularUser("normal_user2")

	err := store.SaveAccount(context.Background(), account)
	if err != nil {
		t.Fatalf("Error when saving account: %s", err)
	}

	am := DefaultAccountManager{
		Store:      store,
		eventStore: &activity.InMemoryEventStore{},
	}

	users, err := am.ListUsers(context.Background(), mockAccountID)
	if err != nil {
		t.Fatalf("Error when checking user role: %s", err)
	}

	admins := 0
	regular := 0
	for _, user := range users {
		if user.HasAdminPower() {
			admins++
			continue
		}
		regular++
	}
	assert.Equal(t, 3, len(users))
	assert.Equal(t, 1, admins)
	assert.Equal(t, 2, regular)
}

func TestDefaultAccountManager_ListUsers_DashboardPermissions(t *testing.T) {
	testCases := []struct {
		name                         string
		role                         UserRole
		limitedViewSettings          bool
		expectedDashboardPermissions string
	}{
		{
			name:                         "Regular user, no limited view settings",
			role:                         UserRoleUser,
			limitedViewSettings:          false,
			expectedDashboardPermissions: "limited",
		},
		{
			name:                         "Admin user, no limited view settings",
			role:                         UserRoleAdmin,
			limitedViewSettings:          false,
			expectedDashboardPermissions: "full",
		},
		{
			name:                         "Owner, no limited view settings",
			role:                         UserRoleOwner,
			limitedViewSettings:          false,
			expectedDashboardPermissions: "full",
		},
		{
			name:                         "Regular user, limited view settings",
			role:                         UserRoleUser,
			limitedViewSettings:          true,
			expectedDashboardPermissions: "blocked",
		},
		{
			name:                         "Admin user, limited view settings",
			role:                         UserRoleAdmin,
			limitedViewSettings:          true,
			expectedDashboardPermissions: "full",
		},
		{
			name:                         "Owner, limited view settings",
			role:                         UserRoleOwner,
			limitedViewSettings:          true,
			expectedDashboardPermissions: "full",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			store := newStore(t)
			account := newAccountWithId(context.Background(), mockAccountID, mockUserID, "")
			account.Users["normal_user1"] = NewUser("normal_user1", testCase.role, false, false, "", []string{}, UserIssuedAPI)
			account.Settings.RegularUsersViewBlocked = testCase.limitedViewSettings
			delete(account.Users, mockUserID)

			err := store.SaveAccount(context.Background(), account)
			if err != nil {
				t.Fatalf("Error when saving account: %s", err)
			}

			am := DefaultAccountManager{
				Store:      store,
				eventStore: &activity.InMemoryEventStore{},
			}

			users, err := am.ListUsers(context.Background(), mockAccountID)
			if err != nil {
				t.Fatalf("Error when checking user role: %s", err)
			}

			assert.Equal(t, 1, len(users))

			userInfo, _ := users[0].ToUserInfo(nil, account.Settings)
			assert.Equal(t, testCase.expectedDashboardPermissions, userInfo.Permissions.DashboardView)
		})
	}

}

func TestDefaultAccountManager_ExternalCache(t *testing.T) {
	store := newStore(t)
	defer store.Close(context.Background())
	account := newAccountWithId(context.Background(), mockAccountID, mockUserID, "")
	externalUser := &User{
		Id:     "externalUser",
		Role:   UserRoleUser,
		Issued: UserIssuedIntegration,
		IntegrationReference: integration_reference.IntegrationReference{
			ID:              1,
			IntegrationType: "external",
		},
	}
	account.Users[externalUser.Id] = externalUser

	err := store.SaveAccount(context.Background(), account)
	if err != nil {
		t.Fatalf("Error when saving account: %s", err)
	}

	am := DefaultAccountManager{
		Store:        store,
		eventStore:   &activity.InMemoryEventStore{},
		idpManager:   &idp.GoogleWorkspaceManager{}, // empty manager
		cacheLoading: map[string]chan struct{}{},
		cacheManager: cache.New[[]*idp.UserData](
			cacheStore.NewGoCache(gocache.New(CacheExpirationMax, 30*time.Minute)),
		),
		externalCacheManager: cache.New[*idp.UserData](
			cacheStore.NewGoCache(gocache.New(CacheExpirationMax, 30*time.Minute)),
		),
	}

	// pretend that we receive mockUserID from IDP
	err = am.cacheManager.Set(am.ctx, mockAccountID, []*idp.UserData{{Name: mockUserID, ID: mockUserID}})
	assert.NoError(t, err)

	cacheManager := am.GetExternalCacheManager()
	cacheKey := externalUser.IntegrationReference.CacheKey(mockAccountID, externalUser.Id)
	err = cacheManager.Set(context.Background(), cacheKey, &idp.UserData{ID: externalUser.Id, Name: "Test User", Email: "user@example.com"})
	assert.NoError(t, err)

	infos, err := am.GetUsersFromAccount(context.Background(), mockAccountID, mockUserID)
	assert.NoError(t, err)
	assert.Equal(t, 2, len(infos))
	var user *UserInfo
	for _, info := range infos {
		if info.ID == externalUser.Id {
			user = info
		}
	}
	assert.NotNil(t, user)
	assert.Equal(t, "user@example.com", user.Email)
}

func TestUser_IsAdmin(t *testing.T) {

	user := NewAdminUser(mockUserID)
	assert.True(t, user.HasAdminPower())

	user = NewRegularUser(mockUserID)
	assert.False(t, user.HasAdminPower())
}

func TestUser_GetUsersFromAccount_ForAdmin(t *testing.T) {
	store := newStore(t)
	defer store.Close(context.Background())
	account := newAccountWithId(context.Background(), mockAccountID, mockUserID, "")
	account.Users[mockServiceUserID] = &User{
		Id:            mockServiceUserID,
		Role:          "user",
		IsServiceUser: true,
	}

	err := store.SaveAccount(context.Background(), account)
	if err != nil {
		t.Fatalf("Error when saving account: %s", err)
	}

	am := DefaultAccountManager{
		Store:      store,
		eventStore: &activity.InMemoryEventStore{},
	}

	users, err := am.GetUsersFromAccount(context.Background(), mockAccountID, mockUserID)
	if err != nil {
		t.Fatalf("Error when getting users from account: %s", err)
	}

	assert.Equal(t, 2, len(users))
}

func TestUser_GetUsersFromAccount_ForUser(t *testing.T) {
	store := newStore(t)
	defer store.Close(context.Background())

	account := newAccountWithId(context.Background(), mockAccountID, mockUserID, "")
	account.Users[mockServiceUserID] = &User{
		Id:            mockServiceUserID,
		Role:          "user",
		IsServiceUser: true,
	}

	err := store.SaveAccount(context.Background(), account)
	if err != nil {
		t.Fatalf("Error when saving account: %s", err)
	}

	am := DefaultAccountManager{
		Store:      store,
		eventStore: &activity.InMemoryEventStore{},
	}

	users, err := am.GetUsersFromAccount(context.Background(), mockAccountID, mockServiceUserID)
	if err != nil {
		t.Fatalf("Error when getting users from account: %s", err)
	}

	// Service users should see all users
	assert.Equal(t, 2, len(users))
}

func TestDefaultAccountManager_SaveUser(t *testing.T) {
	manager, err := createManager(t)
	if err != nil {
		t.Fatal(err)
		return
	}

	regularUserID := "regularUser"
	serviceUserID := "serviceUser"
	adminUserID := "adminUser"
	ownerUserID := "ownerUser"

	tt := []struct {
		name        string
		initiatorID string
		update      *User
		expectedErr bool
	}{
		{
			name:        "Should_Fail_To_Update_Admin_Role",
			expectedErr: true,
			initiatorID: adminUserID,
			update: &User{
				Id:      adminUserID,
				Role:    UserRoleUser,
				Blocked: false,
			},
		}, {
			name:        "Should_Fail_When_Admin_Blocks_Themselves",
			expectedErr: true,
			initiatorID: adminUserID,
			update: &User{
				Id:      adminUserID,
				Role:    UserRoleAdmin,
				Blocked: true,
			},
		},
		{
			name:        "Should_Fail_To_Update_Non_Existing_User",
			expectedErr: true,
			initiatorID: adminUserID,
			update: &User{
				Id:      userID,
				Role:    UserRoleAdmin,
				Blocked: true,
			},
		},
		{
			name:        "Should_Fail_To_Update_When_Initiator_Is_Not_An_Admin",
			expectedErr: true,
			initiatorID: regularUserID,
			update: &User{
				Id:      adminUserID,
				Role:    UserRoleAdmin,
				Blocked: true,
			},
		},
		{
			name:        "Should_Update_User",
			expectedErr: false,
			initiatorID: adminUserID,
			update: &User{
				Id:      regularUserID,
				Role:    UserRoleAdmin,
				Blocked: true,
			},
		},
		{
			name:        "Should_Transfer_Owner_Role_To_User",
			expectedErr: false,
			initiatorID: ownerUserID,
			update: &User{
				Id:      adminUserID,
				Role:    UserRoleAdmin,
				Blocked: false,
			},
		},
		{
			name:        "Should_Fail_To_Transfer_Owner_Role_To_Service_User",
			expectedErr: true,
			initiatorID: ownerUserID,
			update: &User{
				Id:      serviceUserID,
				Role:    UserRoleOwner,
				Blocked: false,
			},
		},
		{
			name:        "Should_Fail_To_Update_Owner_User_Role_By_Admin",
			expectedErr: true,
			initiatorID: adminUserID,
			update: &User{
				Id:      ownerUserID,
				Role:    UserRoleAdmin,
				Blocked: false,
			},
		},
		{
			name:        "Should_Fail_To_Update_Owner_User_Role_By_User",
			expectedErr: true,
			initiatorID: regularUserID,
			update: &User{
				Id:      ownerUserID,
				Role:    UserRoleAdmin,
				Blocked: false,
			},
		},
		{
			name:        "Should_Fail_To_Update_Owner_User_Role_By_Service_User",
			expectedErr: true,
			initiatorID: serviceUserID,
			update: &User{
				Id:      ownerUserID,
				Role:    UserRoleAdmin,
				Blocked: false,
			},
		},
		{
			name:        "Should_Fail_To_Update_Owner_Role_By_Admin",
			expectedErr: true,
			initiatorID: adminUserID,
			update: &User{
				Id:      regularUserID,
				Role:    UserRoleOwner,
				Blocked: false,
			},
		},
		{
			name:        "Should_Fail_To_Block_Owner_Role_By_Admin",
			expectedErr: true,
			initiatorID: adminUserID,
			update: &User{
				Id:      ownerUserID,
				Role:    UserRoleOwner,
				Blocked: true,
			},
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {

			// create an account and an admin user
			account, err := manager.GetOrCreateAccountByUser(context.Background(), ownerUserID, "netbird.io")
			if err != nil {
				t.Fatal(err)
			}

			// create other users
			account.Users[regularUserID] = NewRegularUser(regularUserID)
			account.Users[adminUserID] = NewAdminUser(adminUserID)
			account.Users[serviceUserID] = &User{IsServiceUser: true, Id: serviceUserID, Role: UserRoleAdmin, ServiceUserName: "service"}
			err = manager.Store.SaveAccount(context.Background(), account)
			if err != nil {
				t.Fatal(err)
			}

			updated, err := manager.SaveUser(context.Background(), account.Id, tc.initiatorID, tc.update)
			if tc.expectedErr {
				require.Errorf(t, err, "expecting SaveUser to throw an error")
			} else {
				require.NoError(t, err, "expecting SaveUser not to throw an error")
				assert.NotNil(t, updated)

				assert.Equal(t, string(tc.update.Role), updated.Role)
				assert.Equal(t, tc.update.IsBlocked(), updated.IsBlocked)
			}
		})
	}
}

func TestUserAccountPeerUpdate(t *testing.T) {
	// account groups propagation is enabled
	manager, account, peer1, peer2, peer3 := setupNetworkMapTest(t)

	err := manager.SaveGroup(context.Background(), account.Id, userID, &nbgroup.Group{
		ID:    "group-id",
		Name:  "GroupA",
		Peers: []string{peer1.ID, peer2.ID, peer3.ID},
	})
	require.NoError(t, err)

	policy := Policy{
		ID:      "policy",
		Enabled: true,
		Rules: []*PolicyRule{
			{
				Enabled:       true,
				Sources:       []string{"group-id"},
				Destinations:  []string{"group-id"},
				Bidirectional: true,
				Action:        PolicyTrafficActionAccept,
			},
		},
	}
	err = manager.SavePolicy(context.Background(), account.Id, userID, &policy)
	require.NoError(t, err)

	updMsg := manager.peersUpdateManager.CreateChannel(context.Background(), peer1.ID)
	t.Cleanup(func() {
		manager.peersUpdateManager.CloseChannel(context.Background(), peer1.ID)
	})

	// Creating a new regular user should not update account peers and not send peer update
	t.Run("creating new regular user", func(t *testing.T) {
		done := make(chan struct{})
		go func() {
			peerShouldNotReceiveUpdate(t, updMsg)
			close(done)
		}()

		_, err = manager.SaveOrAddUser(context.Background(), account.Id, userID, &User{
			Id:        "regularUser1",
			AccountID: account.Id,
			Role:      UserRoleUser,
			Issued:    UserIssuedAPI,
		}, true)
		require.NoError(t, err)

		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("timeout waiting for peerShouldNotReceiveUpdate")
		}
	})

	// updating user with no linked peers should not update account peers and not send peer update
	t.Run("updating user with no linked peers", func(t *testing.T) {
		done := make(chan struct{})
		go func() {
			peerShouldNotReceiveUpdate(t, updMsg)
			close(done)
		}()

		_, err = manager.SaveOrAddUser(context.Background(), account.Id, userID, &User{
			Id:        "regularUser1",
			AccountID: account.Id,
			Role:      UserRoleUser,
			Issued:    UserIssuedAPI,
		}, false)
		require.NoError(t, err)

		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("timeout waiting for peerShouldNotReceiveUpdate")
		}
	})

	// deleting user with no linked peers should not update account peers and not send peer update
	t.Run("deleting user with no linked peers", func(t *testing.T) {
		done := make(chan struct{})
		go func() {
			peerShouldNotReceiveUpdate(t, updMsg)
			close(done)
		}()

		err = manager.DeleteUser(context.Background(), account.Id, userID, "regularUser1")
		require.NoError(t, err)

		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("timeout waiting for peerShouldNotReceiveUpdate")
		}
	})

	// create a user and add new peer with the user
	_, err = manager.SaveOrAddUser(context.Background(), account.Id, userID, &User{
		Id:        "regularUser2",
		AccountID: account.Id,
		Role:      UserRoleAdmin,
		Issued:    UserIssuedAPI,
	}, true)
	require.NoError(t, err)

	key, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)

	expectedPeerKey := key.PublicKey().String()
	peer4, _, _, err := manager.AddPeer(context.Background(), "", "regularUser2", &nbpeer.Peer{
		Key:  expectedPeerKey,
		Meta: nbpeer.PeerSystemMeta{Hostname: expectedPeerKey},
	})
	require.NoError(t, err)

	// updating user with linked peers should update account peers and send peer update
	t.Run("updating user with no linked peers", func(t *testing.T) {
		done := make(chan struct{})
		go func() {
			peerShouldReceiveUpdate(t, updMsg)
			close(done)
		}()

		_, err = manager.SaveOrAddUser(context.Background(), account.Id, userID, &User{
			Id:        "regularUser2",
			AccountID: account.Id,
			Role:      UserRoleAdmin,
			Issued:    UserIssuedAPI,
		}, false)
		require.NoError(t, err)

		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("timeout waiting for peerShouldReceiveUpdate")
		}
	})

	_ = peer4

	peer4UpdMsg := manager.peersUpdateManager.CreateChannel(context.Background(), peer4.ID)
	t.Cleanup(func() {
		manager.peersUpdateManager.CloseChannel(context.Background(), peer4.ID)
	})

	// deleting user with linked peers should update account peers and no send peer update
	t.Run("deleting user with linked peers", func(t *testing.T) {
		done := make(chan struct{})
		go func() {
			peerShouldReceiveUpdate(t, peer4UpdMsg)
			close(done)
		}()

		err = manager.DeleteUser(context.Background(), account.Id, userID, "regularUser2")
		require.NoError(t, err)

		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("timeout waiting for peerShouldReceiveUpdate")
		}
	})
}
