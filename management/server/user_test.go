package server

import (
	"context"
	"fmt"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"go.uber.org/mock/gomock"
	"golang.org/x/exp/maps"

	"github.com/netbirdio/netbird/management/internals/controllers/network_map"
	nbcache "github.com/netbirdio/netbird/management/server/cache"
	"github.com/netbirdio/netbird/management/server/permissions"
	"github.com/netbirdio/netbird/management/server/permissions/modules"
	"github.com/netbirdio/netbird/management/server/permissions/roles"
	"github.com/netbirdio/netbird/management/server/users"
	"github.com/netbirdio/netbird/management/server/util"
	"github.com/netbirdio/netbird/shared/auth"
	"github.com/netbirdio/netbird/shared/management/status"

	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/netbirdio/netbird/idp/dex"
	"github.com/netbirdio/netbird/management/server/activity"
	"github.com/netbirdio/netbird/management/server/idp"
	"github.com/netbirdio/netbird/management/server/integration_reference"
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
	s, cleanup, err := store.NewTestStoreFromSQL(context.Background(), "", t.TempDir())
	if err != nil {
		t.Fatalf("Error when creating store: %s", err)
	}
	t.Cleanup(cleanup)

	account := newAccountWithId(context.Background(), mockAccountID, mockUserID, "", "", "", false)

	err = s.SaveAccount(context.Background(), account)
	if err != nil {
		t.Fatalf("Error when saving account: %s", err)
	}

	permissionsManager := permissions.NewManager(s)
	am := DefaultAccountManager{
		Store:              s,
		eventStore:         &activity.InMemoryEventStore{},
		permissionsManager: permissionsManager,
	}

	pat, err := am.CreatePAT(context.Background(), mockAccountID, mockUserID, mockUserID, mockTokenName, mockExpiresIn)
	if err != nil {
		t.Fatalf("Error when adding PAT to user: %s", err)
	}

	assert.Equal(t, pat.CreatedBy, mockUserID)

	tokenID, err := am.Store.GetTokenIDByHashedToken(context.Background(), pat.HashedToken)
	if err != nil {
		t.Fatalf("Error when getting token ID by hashed token: %s", err)
	}

	if tokenID == "" {
		t.Fatal("GetTokenIDByHashedToken failed after adding PAT")
	}

	assert.Equal(t, pat.ID, tokenID)

	user, err := am.Store.GetUserByPATID(context.Background(), store.LockingStrengthNone, tokenID)
	if err != nil {
		t.Fatalf("Error when getting user by token ID: %s", err)
	}

	assert.Equal(t, mockUserID, user.Id)
}

func TestUser_CreatePAT_ForDifferentUser(t *testing.T) {
	store, cleanup, err := store.NewTestStoreFromSQL(context.Background(), "", t.TempDir())
	if err != nil {
		t.Fatalf("Error when creating store: %s", err)
	}
	t.Cleanup(cleanup)

	account := newAccountWithId(context.Background(), mockAccountID, mockUserID, "", "", "", false)
	account.Users[mockTargetUserId] = &types.User{
		Id:            mockTargetUserId,
		IsServiceUser: false,
	}
	err = store.SaveAccount(context.Background(), account)
	if err != nil {
		t.Fatalf("Error when saving account: %s", err)
	}

	permissionsManager := permissions.NewManager(store)
	am := DefaultAccountManager{
		Store:              store,
		eventStore:         &activity.InMemoryEventStore{},
		permissionsManager: permissionsManager,
	}

	_, err = am.CreatePAT(context.Background(), mockAccountID, mockUserID, mockTargetUserId, mockTokenName, mockExpiresIn)
	assert.Errorf(t, err, "Creating PAT for different user should thorw error")
}

func TestUser_CreatePAT_ForServiceUser(t *testing.T) {
	store, cleanup, err := store.NewTestStoreFromSQL(context.Background(), "", t.TempDir())
	if err != nil {
		t.Fatalf("Error when creating store: %s", err)
	}
	t.Cleanup(cleanup)

	account := newAccountWithId(context.Background(), mockAccountID, mockUserID, "", "", "", false)
	account.Users[mockTargetUserId] = &types.User{
		Id:            mockTargetUserId,
		IsServiceUser: true,
	}
	err = store.SaveAccount(context.Background(), account)
	if err != nil {
		t.Fatalf("Error when saving account: %s", err)
	}

	permissionsManager := permissions.NewManager(store)
	am := DefaultAccountManager{
		Store:              store,
		eventStore:         &activity.InMemoryEventStore{},
		permissionsManager: permissionsManager,
	}

	pat, err := am.CreatePAT(context.Background(), mockAccountID, mockUserID, mockTargetUserId, mockTokenName, mockExpiresIn)
	if err != nil {
		t.Fatalf("Error when adding PAT to user: %s", err)
	}

	assert.Equal(t, pat.CreatedBy, mockUserID)
}

func TestUser_CreatePAT_WithWrongExpiration(t *testing.T) {
	store, cleanup, err := store.NewTestStoreFromSQL(context.Background(), "", t.TempDir())
	if err != nil {
		t.Fatalf("Error when creating store: %s", err)
	}
	t.Cleanup(cleanup)

	account := newAccountWithId(context.Background(), mockAccountID, mockUserID, "", "", "", false)

	err = store.SaveAccount(context.Background(), account)
	if err != nil {
		t.Fatalf("Error when saving account: %s", err)
	}

	permissionsManager := permissions.NewManager(store)
	am := DefaultAccountManager{
		Store:              store,
		eventStore:         &activity.InMemoryEventStore{},
		permissionsManager: permissionsManager,
	}

	_, err = am.CreatePAT(context.Background(), mockAccountID, mockUserID, mockUserID, mockTokenName, mockWrongExpiresIn)
	assert.Errorf(t, err, "Wrong expiration should thorw error")
}

func TestUser_CreatePAT_WithEmptyName(t *testing.T) {
	store, cleanup, err := store.NewTestStoreFromSQL(context.Background(), "", t.TempDir())
	if err != nil {
		t.Fatalf("Error when creating store: %s", err)
	}
	t.Cleanup(cleanup)

	account := newAccountWithId(context.Background(), mockAccountID, mockUserID, "", "", "", false)

	err = store.SaveAccount(context.Background(), account)
	if err != nil {
		t.Fatalf("Error when saving account: %s", err)
	}

	permissionsManager := permissions.NewManager(store)
	am := DefaultAccountManager{
		Store:              store,
		eventStore:         &activity.InMemoryEventStore{},
		permissionsManager: permissionsManager,
	}

	_, err = am.CreatePAT(context.Background(), mockAccountID, mockUserID, mockUserID, mockEmptyTokenName, mockExpiresIn)
	assert.Errorf(t, err, "Wrong expiration should thorw error")
}

func TestUser_DeletePAT(t *testing.T) {
	store, cleanup, err := store.NewTestStoreFromSQL(context.Background(), "", t.TempDir())
	if err != nil {
		t.Fatalf("Error when creating store: %s", err)
	}
	t.Cleanup(cleanup)

	account := newAccountWithId(context.Background(), mockAccountID, mockUserID, "", "", "", false)
	account.Users[mockUserID] = &types.User{
		Id: mockUserID,
		PATs: map[string]*types.PersonalAccessToken{
			mockTokenID1: {
				ID:          mockTokenID1,
				HashedToken: mockToken1,
			},
		},
		Role: types.UserRoleAdmin,
	}
	err = store.SaveAccount(context.Background(), account)
	if err != nil {
		t.Fatalf("Error when saving account: %s", err)
	}

	permissionsManager := permissions.NewManager(store)
	am := DefaultAccountManager{
		Store:              store,
		eventStore:         &activity.InMemoryEventStore{},
		permissionsManager: permissionsManager,
	}

	err = am.DeletePAT(context.Background(), mockAccountID, mockUserID, mockUserID, mockTokenID1)
	if err != nil {
		t.Fatalf("Error when adding PAT to user: %s", err)
	}

	account, err = store.GetAccount(context.Background(), mockAccountID)
	if err != nil {
		t.Fatalf("Error when getting account: %s", err)
	}

	assert.Nil(t, account.Users[mockUserID].PATs[mockTokenID1])
}

func TestUser_GetPAT(t *testing.T) {
	store, cleanup, err := store.NewTestStoreFromSQL(context.Background(), "", t.TempDir())
	if err != nil {
		t.Fatalf("Error when creating store: %s", err)
	}
	t.Cleanup(cleanup)

	account := newAccountWithId(context.Background(), mockAccountID, mockUserID, "", "", "", false)
	account.Users[mockUserID] = &types.User{
		Id:        mockUserID,
		AccountID: mockAccountID,
		PATs: map[string]*types.PersonalAccessToken{
			mockTokenID1: {
				ID:          mockTokenID1,
				HashedToken: mockToken1,
			},
		},
		Role: types.UserRoleAdmin,
	}
	err = store.SaveAccount(context.Background(), account)
	if err != nil {
		t.Fatalf("Error when saving account: %s", err)
	}

	permissionsManager := permissions.NewManager(store)
	am := DefaultAccountManager{
		Store:              store,
		eventStore:         &activity.InMemoryEventStore{},
		permissionsManager: permissionsManager,
	}

	pat, err := am.GetPAT(context.Background(), mockAccountID, mockUserID, mockUserID, mockTokenID1)
	if err != nil {
		t.Fatalf("Error when adding PAT to user: %s", err)
	}

	assert.Equal(t, mockTokenID1, pat.ID)
	assert.Equal(t, mockToken1, pat.HashedToken)
}

func TestUser_GetAllPATs(t *testing.T) {
	store, cleanup, err := store.NewTestStoreFromSQL(context.Background(), "", t.TempDir())
	if err != nil {
		t.Fatalf("Error when creating store: %s", err)
	}
	t.Cleanup(cleanup)

	account := newAccountWithId(context.Background(), mockAccountID, mockUserID, "", "", "", false)
	account.Users[mockUserID] = &types.User{
		Id:        mockUserID,
		AccountID: mockAccountID,
		PATs: map[string]*types.PersonalAccessToken{
			mockTokenID1: {
				ID:          mockTokenID1,
				HashedToken: mockToken1,
			},
			mockTokenID2: {
				ID:          mockTokenID2,
				HashedToken: mockToken2,
			},
		},
		Role: types.UserRoleAdmin,
	}
	err = store.SaveAccount(context.Background(), account)
	if err != nil {
		t.Fatalf("Error when saving account: %s", err)
	}

	permissionsManager := permissions.NewManager(store)
	am := DefaultAccountManager{
		Store:              store,
		eventStore:         &activity.InMemoryEventStore{},
		permissionsManager: permissionsManager,
	}

	pats, err := am.GetAllPATs(context.Background(), mockAccountID, mockUserID, mockUserID)
	if err != nil {
		t.Fatalf("Error when adding PAT to user: %s", err)
	}

	assert.Equal(t, 2, len(pats))
}

func TestUser_Copy(t *testing.T) {
	// this is an imaginary case which will never be in DB this way
	user := types.User{
		Id:              "userId",
		AccountID:       "accountId",
		Role:            "role",
		IsServiceUser:   true,
		ServiceUserName: "servicename",
		AutoGroups:      []string{"group1", "group2"},
		PATs: map[string]*types.PersonalAccessToken{
			"pat1": {
				ID:             "pat1",
				Name:           "First PAT",
				HashedToken:    "SoMeHaShEdToKeN",
				ExpirationDate: util.ToPtr(time.Now().AddDate(0, 0, 7)),
				CreatedBy:      "userId",
				CreatedAt:      time.Now(),
				LastUsed:       util.ToPtr(time.Now()),
			},
		},
		Blocked:   false,
		LastLogin: util.ToPtr(time.Now().UTC()),
		CreatedAt: time.Now().UTC(),
		Issued:    "test",
		IntegrationReference: integration_reference.IntegrationReference{
			ID:              0,
			IntegrationType: "test",
		},
		Email: "whatever@gmail.com",
		Name:  "John Doe",
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
	store, cleanup, err := store.NewTestStoreFromSQL(context.Background(), "", t.TempDir())
	if err != nil {
		t.Fatalf("Error when creating store: %s", err)
	}
	t.Cleanup(cleanup)

	account := newAccountWithId(context.Background(), mockAccountID, mockUserID, "", "", "", false)

	err = store.SaveAccount(context.Background(), account)
	if err != nil {
		t.Fatalf("Error when saving account: %s", err)
	}

	permissionsManager := permissions.NewManager(store)
	am := DefaultAccountManager{
		Store:              store,
		eventStore:         &activity.InMemoryEventStore{},
		permissionsManager: permissionsManager,
	}

	user, err := am.createServiceUser(context.Background(), mockAccountID, mockUserID, mockRole, mockServiceUserName, false, []string{"group1", "group2"})
	if err != nil {
		t.Fatalf("Error when creating service user: %s", err)
	}

	account, err = store.GetAccount(context.Background(), mockAccountID)
	assert.NoError(t, err)

	assert.Equal(t, 2, len(account.Users))
	assert.NotNil(t, account.Users[user.ID])
	assert.True(t, account.Users[user.ID].IsServiceUser)
	assert.Equal(t, mockServiceUserName, account.Users[user.ID].ServiceUserName)
	assert.Equal(t, types.UserRole(mockRole), account.Users[user.ID].Role)
	assert.Equal(t, []string{"group1", "group2"}, account.Users[user.ID].AutoGroups)
	assert.Equal(t, map[string]*types.PersonalAccessToken{}, account.Users[user.ID].PATs)

	assert.Zero(t, user.Email)
	assert.True(t, user.IsServiceUser)
	assert.Equal(t, "active", user.Status)

	_, err = am.createServiceUser(context.Background(), mockAccountID, mockUserID, types.UserRoleOwner, mockServiceUserName, false, nil)
	if err == nil {
		t.Fatal("should return error when creating service user with owner role")
	}
}

func TestUser_CreateUser_ServiceUser(t *testing.T) {
	store, cleanup, err := store.NewTestStoreFromSQL(context.Background(), "", t.TempDir())
	if err != nil {
		t.Fatalf("Error when creating store: %s", err)
	}
	t.Cleanup(cleanup)

	account := newAccountWithId(context.Background(), mockAccountID, mockUserID, "", "", "", false)

	err = store.SaveAccount(context.Background(), account)
	if err != nil {
		t.Fatalf("Error when saving account: %s", err)
	}

	permissionsManager := permissions.NewManager(store)
	am := DefaultAccountManager{
		Store:              store,
		eventStore:         &activity.InMemoryEventStore{},
		permissionsManager: permissionsManager,
	}

	user, err := am.CreateUser(context.Background(), mockAccountID, mockUserID, &types.UserInfo{
		Name:          mockServiceUserName,
		Role:          mockRole,
		IsServiceUser: true,
		AutoGroups:    []string{"group1", "group2"},
	})

	if err != nil {
		t.Fatalf("Error when creating user: %s", err)
	}

	account, err = store.GetAccount(context.Background(), mockAccountID)
	assert.NoError(t, err)

	assert.True(t, user.IsServiceUser)
	assert.Equal(t, 2, len(account.Users))
	assert.True(t, account.Users[user.ID].IsServiceUser)
	assert.Equal(t, mockServiceUserName, account.Users[user.ID].ServiceUserName)
	assert.Equal(t, types.UserRole(mockRole), account.Users[user.ID].Role)
	assert.Equal(t, []string{"group1", "group2"}, account.Users[user.ID].AutoGroups)

	assert.Equal(t, mockServiceUserName, user.Name)
	assert.Equal(t, mockRole, user.Role)
	assert.Equal(t, []string{"group1", "group2"}, user.AutoGroups)
	assert.Equal(t, "active", user.Status)
}

func TestUser_CreateUser_RegularUser(t *testing.T) {
	store, cleanup, err := store.NewTestStoreFromSQL(context.Background(), "", t.TempDir())
	if err != nil {
		t.Fatalf("Error when creating store: %s", err)
	}
	t.Cleanup(cleanup)

	account := newAccountWithId(context.Background(), mockAccountID, mockUserID, "", "", "", false)

	err = store.SaveAccount(context.Background(), account)
	if err != nil {
		t.Fatalf("Error when saving account: %s", err)
	}

	permissionsManager := permissions.NewManager(store)
	am := DefaultAccountManager{
		Store:              store,
		eventStore:         &activity.InMemoryEventStore{},
		permissionsManager: permissionsManager,
	}

	_, err = am.CreateUser(context.Background(), mockAccountID, mockUserID, &types.UserInfo{
		Name:          mockServiceUserName,
		Role:          mockRole,
		IsServiceUser: false,
		AutoGroups:    []string{"group1", "group2"},
	})

	assert.Errorf(t, err, "Not configured IDP will throw error but right path used")
}

func TestUser_InviteNewUser(t *testing.T) {
	store, cleanup, err := store.NewTestStoreFromSQL(context.Background(), "", t.TempDir())
	if err != nil {
		t.Fatalf("Error when creating store: %s", err)
	}
	t.Cleanup(cleanup)

	account := newAccountWithId(context.Background(), mockAccountID, mockUserID, "", "", "", false)

	err = store.SaveAccount(context.Background(), account)
	if err != nil {
		t.Fatalf("Error when saving account: %s", err)
	}

	permissionsManager := permissions.NewManager(store)
	am := DefaultAccountManager{
		Store:              store,
		eventStore:         &activity.InMemoryEventStore{},
		cacheLoading:       map[string]chan struct{}{},
		permissionsManager: permissionsManager,
	}

	cs, err := nbcache.NewStore(context.Background(), nbcache.DefaultIDPCacheExpirationMax, nbcache.DefaultIDPCacheCleanupInterval, nbcache.DefaultIDPCacheOpenConn)
	require.NoError(t, err)

	am.cacheManager = nbcache.NewAccountUserDataCache(am.loadAccount, cs)

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
	_, err = am.inviteNewUser(context.Background(), mockAccountID, mockUserID, &types.UserInfo{
		Name:          mockServiceUserName,
		Role:          mockRole,
		Email:         "test@teste.com",
		IsServiceUser: false,
		AutoGroups:    []string{"group1", "group2"},
	})

	assert.NoErrorf(t, err, "Invite user should not throw error")

	// test if new invite with owner role fails
	_, err = am.inviteNewUser(context.Background(), mockAccountID, mockUserID, &types.UserInfo{
		Name:          mockServiceUserName,
		Role:          string(types.UserRoleOwner),
		Email:         "test2@teste.com",
		IsServiceUser: false,
		AutoGroups:    []string{"group1", "group2"},
	})

	assert.Errorf(t, err, "Invite user with owner role should throw error")
}

func TestUser_DeleteUser_ServiceUser(t *testing.T) {
	tests := []struct {
		name             string
		serviceUser      *types.User
		assertErrFunc    assert.ErrorAssertionFunc
		assertErrMessage string
	}{
		{
			name: "Can delete service user",
			serviceUser: &types.User{
				Id:              mockServiceUserID,
				IsServiceUser:   true,
				ServiceUserName: mockServiceUserName,
			},
			assertErrFunc: assert.NoError,
		},
		{
			name: "Cannot delete non-deletable service user",
			serviceUser: &types.User{
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
			store, cleanup, err := store.NewTestStoreFromSQL(context.Background(), "", t.TempDir())
			if err != nil {
				t.Fatalf("Error when creating store: %s", err)
			}
			t.Cleanup(cleanup)

			account := newAccountWithId(context.Background(), mockAccountID, mockUserID, "", "", "", false)
			account.Users[mockServiceUserID] = tt.serviceUser

			err = store.SaveAccount(context.Background(), account)
			if err != nil {
				t.Fatalf("Error when saving account: %s", err)
			}

			permissionsManager := permissions.NewManager(store)
			am := DefaultAccountManager{
				Store:              store,
				eventStore:         &activity.InMemoryEventStore{},
				permissionsManager: permissionsManager,
			}

			err = am.DeleteUser(context.Background(), mockAccountID, mockUserID, mockServiceUserID)
			tt.assertErrFunc(t, err, tt.assertErrMessage)

			account, err2 := store.GetAccount(context.Background(), mockAccountID)
			assert.NoError(t, err2)

			if err != nil {
				assert.Equal(t, 2, len(account.Users))
				assert.NotNil(t, account.Users[mockServiceUserID])
			} else {
				assert.Equal(t, 1, len(account.Users))
				assert.Nil(t, account.Users[mockServiceUserID])
			}
		})
	}
}

func TestUser_DeleteUser_SelfDelete(t *testing.T) {
	store, cleanup, err := store.NewTestStoreFromSQL(context.Background(), "", t.TempDir())
	if err != nil {
		t.Fatalf("Error when creating store: %s", err)
	}
	t.Cleanup(cleanup)

	account := newAccountWithId(context.Background(), mockAccountID, mockUserID, "", "", "", false)

	err = store.SaveAccount(context.Background(), account)
	if err != nil {
		t.Fatalf("Error when saving account: %s", err)
	}

	permissionsManager := permissions.NewManager(store)
	am := DefaultAccountManager{
		Store:              store,
		eventStore:         &activity.InMemoryEventStore{},
		permissionsManager: permissionsManager,
	}

	err = am.DeleteUser(context.Background(), mockAccountID, mockUserID, mockUserID)
	if err == nil {
		t.Fatalf("failed to prevent self deletion")
	}
}

func TestUser_DeleteUser_regularUser(t *testing.T) {
	store, cleanup, err := store.NewTestStoreFromSQL(context.Background(), "", t.TempDir())
	if err != nil {
		t.Fatalf("Error when creating store: %s", err)
	}
	t.Cleanup(cleanup)

	account := newAccountWithId(context.Background(), mockAccountID, mockUserID, "", "", "", false)

	targetId := "user2"
	account.Users[targetId] = &types.User{
		Id:              targetId,
		IsServiceUser:   true,
		ServiceUserName: "user2username",
	}
	targetId = "user3"
	account.Users[targetId] = &types.User{
		Id:            targetId,
		IsServiceUser: false,
		Issued:        types.UserIssuedAPI,
	}
	targetId = "user4"
	account.Users[targetId] = &types.User{
		Id:            targetId,
		IsServiceUser: false,
		Issued:        types.UserIssuedIntegration,
	}

	targetId = "user5"
	account.Users[targetId] = &types.User{
		Id:            targetId,
		IsServiceUser: false,
		Issued:        types.UserIssuedAPI,
		Role:          types.UserRoleOwner,
	}

	err = store.SaveAccount(context.Background(), account)
	if err != nil {
		t.Fatalf("Error when saving account: %s", err)
	}

	ctrl := gomock.NewController(t)
	networkMapControllerMock := network_map.NewMockController(ctrl)
	networkMapControllerMock.EXPECT().
		OnPeersDeleted(gomock.Any(), gomock.Any(), gomock.Any()).
		Return(nil)

	permissionsManager := permissions.NewManager(store)
	am := DefaultAccountManager{
		Store:                store,
		eventStore:           &activity.InMemoryEventStore{},
		permissionsManager:   permissionsManager,
		networkMapController: networkMapControllerMock,
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
	store, cleanup, err := store.NewTestStoreFromSQL(context.Background(), "", t.TempDir())
	if err != nil {
		t.Fatalf("Error when creating store: %s", err)
	}
	t.Cleanup(cleanup)

	account := newAccountWithId(context.Background(), mockAccountID, mockUserID, "", "", "", false)

	targetId := "user2"
	account.Users[targetId] = &types.User{
		Id:              targetId,
		IsServiceUser:   true,
		ServiceUserName: "user2username",
	}
	targetId = "user3"
	account.Users[targetId] = &types.User{
		Id:            targetId,
		IsServiceUser: false,
		Issued:        types.UserIssuedAPI,
	}
	targetId = "user4"
	account.Users[targetId] = &types.User{
		Id:            targetId,
		IsServiceUser: false,
		Issued:        types.UserIssuedIntegration,
	}

	targetId = "user5"
	account.Users[targetId] = &types.User{
		Id:            targetId,
		IsServiceUser: false,
		Issued:        types.UserIssuedAPI,
		Role:          types.UserRoleOwner,
	}
	account.Users["user6"] = &types.User{
		Id:            "user6",
		IsServiceUser: false,
		Issued:        types.UserIssuedAPI,
	}
	account.Users["user7"] = &types.User{
		Id:            "user7",
		IsServiceUser: false,
		Issued:        types.UserIssuedAPI,
	}
	account.Users["user8"] = &types.User{
		Id:            "user8",
		IsServiceUser: false,
		Issued:        types.UserIssuedAPI,
		Role:          types.UserRoleAdmin,
	}
	account.Users["user9"] = &types.User{
		Id:            "user9",
		IsServiceUser: false,
		Issued:        types.UserIssuedAPI,
		Role:          types.UserRoleAdmin,
	}

	err = store.SaveAccount(context.Background(), account)
	if err != nil {
		t.Fatalf("Error when saving account: %s", err)
	}

	ctrl := gomock.NewController(t)
	networkMapControllerMock := network_map.NewMockController(ctrl)
	networkMapControllerMock.EXPECT().
		OnPeersDeleted(gomock.Any(), gomock.Any(), gomock.Any()).
		Return(nil).
		AnyTimes()

	permissionsManager := permissions.NewManager(store)
	am := DefaultAccountManager{
		Store:                   store,
		eventStore:              &activity.InMemoryEventStore{},
		integratedPeerValidator: MockIntegratedValidator{},
		permissionsManager:      permissionsManager,
		networkMapController:    networkMapControllerMock,
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
			expectedReasons:    []string{"user: non-existent-user not found"},
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
			userInfos, err := am.BuildUserInfosForAccount(context.Background(), mockAccountID, mockUserID, maps.Values(account.Users))
			assert.NoError(t, err)

			err = am.DeleteRegularUsers(context.Background(), mockAccountID, mockUserID, tc.userIDs, userInfos)
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

			acc, err := am.Store.GetAccount(context.Background(), account.Id)
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
	store, cleanup, err := store.NewTestStoreFromSQL(context.Background(), "", t.TempDir())
	if err != nil {
		t.Fatalf("Error when creating store: %s", err)
	}
	t.Cleanup(cleanup)

	account := newAccountWithId(context.Background(), mockAccountID, mockUserID, "", "", "", false)

	err = store.SaveAccount(context.Background(), account)
	if err != nil {
		t.Fatalf("Error when saving account: %s", err)
	}

	permissionsManager := permissions.NewManager(store)
	am := DefaultAccountManager{
		Store:              store,
		eventStore:         &activity.InMemoryEventStore{},
		permissionsManager: permissionsManager,
	}

	claims := auth.UserAuth{
		UserId:    mockUserID,
		AccountId: mockAccountID,
	}

	user, err := am.GetUserFromUserAuth(context.Background(), claims)
	if err != nil {
		t.Fatalf("Error when checking user role: %s", err)
	}

	assert.Equal(t, mockUserID, user.Id)
	assert.True(t, user.HasAdminPower())
	assert.False(t, user.IsBlocked())
}

func TestDefaultAccountManager_ListUsers(t *testing.T) {
	store, cleanup, err := store.NewTestStoreFromSQL(context.Background(), "", t.TempDir())
	if err != nil {
		t.Fatalf("Error when creating store: %s", err)
	}
	t.Cleanup(cleanup)

	account := newAccountWithId(context.Background(), mockAccountID, mockUserID, "", "", "", false)
	account.Users["normal_user1"] = types.NewRegularUser("normal_user1", "", "")
	account.Users["normal_user2"] = types.NewRegularUser("normal_user2", "", "")

	err = store.SaveAccount(context.Background(), account)
	if err != nil {
		t.Fatalf("Error when saving account: %s", err)
	}

	permissionsManager := permissions.NewManager(store)
	am := DefaultAccountManager{
		Store:              store,
		eventStore:         &activity.InMemoryEventStore{},
		permissionsManager: permissionsManager,
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

func TestDefaultAccountManager_ExternalCache(t *testing.T) {
	store, cleanup, err := store.NewTestStoreFromSQL(context.Background(), "", t.TempDir())
	if err != nil {
		t.Fatalf("Error when creating store: %s", err)
	}
	t.Cleanup(cleanup)

	account := newAccountWithId(context.Background(), mockAccountID, mockUserID, "", "", "", false)
	externalUser := &types.User{
		Id:     "externalUser",
		Role:   types.UserRoleUser,
		Issued: types.UserIssuedIntegration,
		IntegrationReference: integration_reference.IntegrationReference{
			ID:              1,
			IntegrationType: "external",
		},
	}
	account.Users[externalUser.Id] = externalUser

	err = store.SaveAccount(context.Background(), account)
	if err != nil {
		t.Fatalf("Error when saving account: %s", err)
	}

	permissionsManager := permissions.NewManager(store)
	am := DefaultAccountManager{
		Store:              store,
		eventStore:         &activity.InMemoryEventStore{},
		idpManager:         &idp.GoogleWorkspaceManager{}, // empty manager
		cacheLoading:       map[string]chan struct{}{},
		permissionsManager: permissionsManager,
	}

	cacheStore, err := nbcache.NewStore(context.Background(), nbcache.DefaultIDPCacheExpirationMax, nbcache.DefaultIDPCacheCleanupInterval, nbcache.DefaultIDPCacheOpenConn)
	assert.NoError(t, err)
	am.externalCacheManager = nbcache.NewUserDataCache(cacheStore)
	am.cacheManager = nbcache.NewAccountUserDataCache(am.loadAccount, cacheStore)
	// pretend that we receive mockUserID from IDP
	err = am.cacheManager.Set(am.ctx, mockAccountID, []*idp.UserData{{Name: mockUserID, ID: mockUserID}}, time.Minute)
	assert.NoError(t, err)

	cacheManager := am.GetExternalCacheManager()
	tud := &idp.UserData{ID: externalUser.Id, Name: "Test User", Email: "user@example.com"}
	cacheKeyUser := externalUser.IntegrationReference.CacheKey(mockAccountID, externalUser.Id)
	err = cacheManager.Set(context.Background(), cacheKeyUser, tud, time.Minute)
	assert.NoError(t, err)
	cacheKeyAccount := externalUser.IntegrationReference.CacheKey(mockAccountID)
	err = cacheManager.SetUsers(context.Background(), cacheKeyAccount, []*idp.UserData{tud}, time.Minute)
	assert.NoError(t, err)

	infos, err := am.GetUsersFromAccount(context.Background(), mockAccountID, mockUserID)
	assert.NoError(t, err)
	assert.Equal(t, 2, len(infos))
	var user *types.UserInfo
	for _, info := range infos {
		if info.ID == externalUser.Id {
			user = info
		}
	}
	assert.NotNil(t, user)
	assert.Equal(t, "user@example.com", user.Email)
}

func TestUser_IsAdmin(t *testing.T) {

	user := types.NewAdminUser(mockUserID)
	assert.True(t, user.HasAdminPower())

	user = types.NewRegularUser(mockUserID, "", "")
	assert.False(t, user.HasAdminPower())
}

func TestUser_GetUsersFromAccount_ForAdmin(t *testing.T) {
	store, cleanup, err := store.NewTestStoreFromSQL(context.Background(), "", t.TempDir())
	if err != nil {
		t.Fatalf("Error when creating store: %s", err)
	}
	t.Cleanup(cleanup)

	account := newAccountWithId(context.Background(), mockAccountID, mockUserID, "", "", "", false)
	account.Users[mockServiceUserID] = &types.User{
		Id:            mockServiceUserID,
		Role:          "user",
		IsServiceUser: true,
	}

	err = store.SaveAccount(context.Background(), account)
	if err != nil {
		t.Fatalf("Error when saving account: %s", err)
	}

	permissionsManager := permissions.NewManager(store)
	am := DefaultAccountManager{
		Store:              store,
		eventStore:         &activity.InMemoryEventStore{},
		permissionsManager: permissionsManager,
	}

	users, err := am.GetUsersFromAccount(context.Background(), mockAccountID, mockUserID)
	if err != nil {
		t.Fatalf("Error when getting users from account: %s", err)
	}

	assert.Equal(t, 2, len(users))
}

func TestUser_GetUsersFromAccount_ForUser(t *testing.T) {
	store, cleanup, err := store.NewTestStoreFromSQL(context.Background(), "", t.TempDir())
	if err != nil {
		t.Fatalf("Error when creating store: %s", err)
	}
	t.Cleanup(cleanup)

	account := newAccountWithId(context.Background(), mockAccountID, mockUserID, "", "", "", false)
	account.Users[mockServiceUserID] = &types.User{
		Id:            mockServiceUserID,
		Role:          "user",
		IsServiceUser: true,
	}

	err = store.SaveAccount(context.Background(), account)
	if err != nil {
		t.Fatalf("Error when saving account: %s", err)
	}

	permissionsManager := permissions.NewManager(store)
	am := DefaultAccountManager{
		Store:              store,
		eventStore:         &activity.InMemoryEventStore{},
		permissionsManager: permissionsManager,
	}

	users, err := am.GetUsersFromAccount(context.Background(), mockAccountID, mockServiceUserID)
	if err != nil {
		t.Fatalf("Error when getting users from account: %s", err)
	}

	// Service users should see all users
	assert.Equal(t, 2, len(users))
}

func TestDefaultAccountManager_SaveUser(t *testing.T) {
	manager, _, err := createManager(t)
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
		update      *types.User
		expectedErr bool
	}{
		{
			name:        "Should_Fail_To_Update_Admin_Role",
			expectedErr: true,
			initiatorID: adminUserID,
			update: &types.User{
				Id:      adminUserID,
				Role:    types.UserRoleUser,
				Blocked: false,
			},
		}, {
			name:        "Should_Fail_When_Admin_Blocks_Themselves",
			expectedErr: true,
			initiatorID: adminUserID,
			update: &types.User{
				Id:      adminUserID,
				Role:    types.UserRoleAdmin,
				Blocked: true,
			},
		},
		{
			name:        "Should_Fail_To_Update_Non_Existing_User",
			expectedErr: true,
			initiatorID: adminUserID,
			update: &types.User{
				Id:      userID,
				Role:    types.UserRoleAdmin,
				Blocked: true,
			},
		},
		{
			name:        "Should_Fail_To_Update_When_Initiator_Is_Not_An_Admin",
			expectedErr: true,
			initiatorID: regularUserID,
			update: &types.User{
				Id:      adminUserID,
				Role:    types.UserRoleAdmin,
				Blocked: true,
			},
		},
		{
			name:        "Should_Update_User",
			expectedErr: false,
			initiatorID: adminUserID,
			update: &types.User{
				Id:      regularUserID,
				Role:    types.UserRoleAdmin,
				Blocked: true,
			},
		},
		{
			name:        "Should_Transfer_Owner_Role_To_User",
			expectedErr: false,
			initiatorID: ownerUserID,
			update: &types.User{
				Id:      adminUserID,
				Role:    types.UserRoleAdmin,
				Blocked: false,
			},
		},
		{
			name:        "Should_Fail_To_Transfer_Owner_Role_To_Service_User",
			expectedErr: true,
			initiatorID: ownerUserID,
			update: &types.User{
				Id:      serviceUserID,
				Role:    types.UserRoleOwner,
				Blocked: false,
			},
		},
		{
			name:        "Should_Fail_To_Update_Owner_User_Role_By_Admin",
			expectedErr: true,
			initiatorID: adminUserID,
			update: &types.User{
				Id:      ownerUserID,
				Role:    types.UserRoleAdmin,
				Blocked: false,
			},
		},
		{
			name:        "Should_Fail_To_Update_Owner_User_Role_By_User",
			expectedErr: true,
			initiatorID: regularUserID,
			update: &types.User{
				Id:      ownerUserID,
				Role:    types.UserRoleAdmin,
				Blocked: false,
			},
		},
		{
			name:        "Should_Fail_To_Update_Owner_User_Role_By_Service_User",
			expectedErr: true,
			initiatorID: serviceUserID,
			update: &types.User{
				Id:      ownerUserID,
				Role:    types.UserRoleAdmin,
				Blocked: false,
			},
		},
		{
			name:        "Should_Fail_To_Update_Owner_Role_By_Admin",
			expectedErr: true,
			initiatorID: adminUserID,
			update: &types.User{
				Id:      regularUserID,
				Role:    types.UserRoleOwner,
				Blocked: false,
			},
		},
		{
			name:        "Should_Fail_To_Block_Owner_Role_By_Admin",
			expectedErr: true,
			initiatorID: adminUserID,
			update: &types.User{
				Id:      ownerUserID,
				Role:    types.UserRoleOwner,
				Blocked: true,
			},
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {

			// create an account and an admin user
			account, err := manager.GetOrCreateAccountByUser(context.Background(), auth.UserAuth{UserId: ownerUserID, Domain: "netbird.io"})
			if err != nil {
				t.Fatal(err)
			}

			// create other users
			account.Users[regularUserID] = types.NewRegularUser(regularUserID, "", "")
			account.Users[adminUserID] = types.NewAdminUser(adminUserID)
			account.Users[serviceUserID] = &types.User{IsServiceUser: true, Id: serviceUserID, Role: types.UserRoleAdmin, ServiceUserName: "service"}
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

func TestUserAccountPeersUpdate(t *testing.T) {
	// account groups propagation is enabled
	manager, updateManager, account, peer1, peer2, peer3 := setupNetworkMapTest(t)

	err := manager.CreateGroup(context.Background(), account.Id, userID, &types.Group{
		ID:    "groupA",
		Name:  "GroupA",
		Peers: []string{peer1.ID, peer2.ID, peer3.ID},
	})
	require.NoError(t, err)

	policy := &types.Policy{
		Enabled: true,
		Rules: []*types.PolicyRule{
			{
				Enabled:       true,
				Sources:       []string{"groupA"},
				Destinations:  []string{"groupA"},
				Bidirectional: true,
				Action:        types.PolicyTrafficActionAccept,
			},
		},
	}
	_, err = manager.SavePolicy(context.Background(), account.Id, userID, policy, true)
	require.NoError(t, err)

	updMsg := updateManager.CreateChannel(context.Background(), peer1.ID)
	t.Cleanup(func() {
		updateManager.CloseChannel(context.Background(), peer1.ID)
	})

	// Creating a new regular user should send peer update (as users are not filtered yet)
	t.Run("creating new regular user with no groups", func(t *testing.T) {
		done := make(chan struct{})
		go func() {
			peerShouldReceiveUpdate(t, updMsg)
			close(done)
		}()

		_, err = manager.SaveOrAddUser(context.Background(), account.Id, userID, &types.User{
			Id:        "regularUser1",
			AccountID: account.Id,
			Role:      types.UserRoleUser,
			Issued:    types.UserIssuedAPI,
		}, true)
		require.NoError(t, err)

		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("timeout waiting for peerShouldNotReceiveUpdate")
		}
	})

	// updating user with no linked peers should update account peers and send peer update (as users are not filtered yet)
	t.Run("updating user with no linked peers", func(t *testing.T) {
		done := make(chan struct{})
		go func() {
			peerShouldReceiveUpdate(t, updMsg)
			close(done)
		}()

		_, err = manager.SaveOrAddUser(context.Background(), account.Id, userID, &types.User{
			Id:        "regularUser1",
			AccountID: account.Id,
			Role:      types.UserRoleUser,
			Issued:    types.UserIssuedAPI,
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
			peerShouldReceiveUpdate(t, updMsg)
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
	_, err = manager.SaveOrAddUser(context.Background(), account.Id, userID, &types.User{
		Id:        "regularUser2",
		AccountID: account.Id,
		Role:      types.UserRoleAdmin,
		Issued:    types.UserIssuedAPI,
	}, true)
	require.NoError(t, err)

	key, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)

	expectedPeerKey := key.PublicKey().String()
	peer4, _, _, err := manager.AddPeer(context.Background(), "", "", "regularUser2", &nbpeer.Peer{
		Key:  expectedPeerKey,
		Meta: nbpeer.PeerSystemMeta{Hostname: expectedPeerKey},
	}, false)
	require.NoError(t, err)

	// updating user with linked peers should update account peers and send peer update
	t.Run("updating user with linked peers", func(t *testing.T) {
		done := make(chan struct{})
		go func() {
			peerShouldReceiveUpdate(t, updMsg)
			close(done)
		}()

		_, err = manager.SaveOrAddUser(context.Background(), account.Id, userID, &types.User{
			Id:        "regularUser2",
			AccountID: account.Id,
			Role:      types.UserRoleAdmin,
			Issued:    types.UserIssuedAPI,
		}, false)
		require.NoError(t, err)

		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("timeout waiting for peerShouldReceiveUpdate")
		}
	})

	peer4UpdMsg := updateManager.CreateChannel(context.Background(), peer4.ID)
	t.Cleanup(func() {
		updateManager.CloseChannel(context.Background(), peer4.ID)
	})

	// deleting user with linked peers should update account peers and send peer update
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

func TestSaveOrAddUser_PreventAccountSwitch(t *testing.T) {
	s, cleanup, err := store.NewTestStoreFromSQL(context.Background(), "", t.TempDir())
	if err != nil {
		t.Fatalf("Error when creating store: %s", err)
	}
	t.Cleanup(cleanup)

	account1 := newAccountWithId(context.Background(), "account1", "ownerAccount1", "", "", "", false)
	targetId := "user2"
	account1.Users[targetId] = &types.User{
		Id:              targetId,
		AccountID:       account1.Id,
		ServiceUserName: "user2username",
	}
	require.NoError(t, s.SaveAccount(context.Background(), account1))

	account2 := newAccountWithId(context.Background(), "account2", "ownerAccount2", "", "", "", false)
	require.NoError(t, s.SaveAccount(context.Background(), account2))

	permissionsManager := permissions.NewManager(s)
	am := DefaultAccountManager{
		Store:              s,
		eventStore:         &activity.InMemoryEventStore{},
		permissionsManager: permissionsManager,
	}

	_, err = am.SaveOrAddUser(context.Background(), "account2", "ownerAccount2", account1.Users[targetId], true)
	assert.Error(t, err, "update user to another account should fail")

	user, err := s.GetUserByUserID(context.Background(), store.LockingStrengthNone, targetId)
	require.NoError(t, err)
	assert.Equal(t, account1.Users[targetId].Id, user.Id)
	assert.Equal(t, account1.Users[targetId].AccountID, user.AccountID)
	assert.Equal(t, account1.Users[targetId].AutoGroups, user.AutoGroups)
}

func TestDefaultAccountManager_GetCurrentUserInfo(t *testing.T) {
	store, cleanup, err := store.NewTestStoreFromSQL(context.Background(), "", t.TempDir())
	if err != nil {
		t.Fatalf("Error when creating store: %s", err)
	}
	t.Cleanup(cleanup)

	account1 := newAccountWithId(context.Background(), "account1", "account1Owner", "", "", "", false)
	account1.Settings.RegularUsersViewBlocked = false
	account1.Users["blocked-user"] = &types.User{
		Id:        "blocked-user",
		AccountID: account1.Id,
		Blocked:   true,
	}
	account1.Users["service-user"] = &types.User{
		Id:              "service-user",
		IsServiceUser:   true,
		ServiceUserName: "service-user",
	}
	account1.Users["regular-user"] = &types.User{
		Id:   "regular-user",
		Role: types.UserRoleUser,
	}
	account1.Users["admin-user"] = &types.User{
		Id:   "admin-user",
		Role: types.UserRoleAdmin,
	}
	require.NoError(t, store.SaveAccount(context.Background(), account1))

	account2 := newAccountWithId(context.Background(), "account2", "account2Owner", "", "", "", false)
	account2.Users["settings-blocked-user"] = &types.User{
		Id:   "settings-blocked-user",
		Role: types.UserRoleUser,
	}
	require.NoError(t, store.SaveAccount(context.Background(), account2))

	permissionsManager := permissions.NewManager(store)
	am := DefaultAccountManager{
		Store:              store,
		eventStore:         &activity.InMemoryEventStore{},
		permissionsManager: permissionsManager,
	}

	tt := []struct {
		name           string
		userAuth       auth.UserAuth
		expectedErr    error
		expectedResult *users.UserInfoWithPermissions
	}{
		{
			name:        "not found",
			userAuth:    auth.UserAuth{AccountId: account1.Id, UserId: "not-found"},
			expectedErr: status.NewUserNotFoundError("not-found"),
		},
		{
			name:        "not part of account",
			userAuth:    auth.UserAuth{AccountId: account1.Id, UserId: "account2Owner"},
			expectedErr: status.NewUserNotPartOfAccountError(),
		},
		{
			name:        "blocked",
			userAuth:    auth.UserAuth{AccountId: account1.Id, UserId: "blocked-user"},
			expectedErr: status.NewUserBlockedError(),
		},
		{
			name:        "service user",
			userAuth:    auth.UserAuth{AccountId: account1.Id, UserId: "service-user"},
			expectedErr: status.NewPermissionDeniedError(),
		},
		{
			name:     "owner user",
			userAuth: auth.UserAuth{AccountId: account1.Id, UserId: "account1Owner"},
			expectedResult: &users.UserInfoWithPermissions{
				UserInfo: &types.UserInfo{
					ID:                   "account1Owner",
					Name:                 "",
					Role:                 "owner",
					AutoGroups:           []string{},
					Status:               "active",
					IsServiceUser:        false,
					IsBlocked:            false,
					NonDeletable:         false,
					LastLogin:            time.Time{},
					Issued:               "api",
					IntegrationReference: integration_reference.IntegrationReference{},
				},
				Permissions: mergeRolePermissions(roles.Owner),
			},
		},
		{
			name:     "regular user",
			userAuth: auth.UserAuth{AccountId: account1.Id, UserId: "regular-user"},
			expectedResult: &users.UserInfoWithPermissions{
				UserInfo: &types.UserInfo{
					ID:                   "regular-user",
					Name:                 "",
					Role:                 "user",
					Status:               "active",
					IsServiceUser:        false,
					IsBlocked:            false,
					NonDeletable:         false,
					LastLogin:            time.Time{},
					Issued:               "api",
					IntegrationReference: integration_reference.IntegrationReference{},
				},
				Permissions: mergeRolePermissions(roles.User),
			},
		},
		{
			name:     "admin user",
			userAuth: auth.UserAuth{AccountId: account1.Id, UserId: "admin-user"},
			expectedResult: &users.UserInfoWithPermissions{
				UserInfo: &types.UserInfo{
					ID:                   "admin-user",
					Name:                 "",
					Role:                 "admin",
					Status:               "active",
					IsServiceUser:        false,
					IsBlocked:            false,
					NonDeletable:         false,
					LastLogin:            time.Time{},
					Issued:               "api",
					IntegrationReference: integration_reference.IntegrationReference{},
				},
				Permissions: mergeRolePermissions(roles.Admin),
			},
		},
		{
			name:     "settings blocked regular user",
			userAuth: auth.UserAuth{AccountId: account2.Id, UserId: "settings-blocked-user"},
			expectedResult: &users.UserInfoWithPermissions{
				UserInfo: &types.UserInfo{
					ID:                   "settings-blocked-user",
					Name:                 "",
					Role:                 "user",
					Status:               "active",
					IsServiceUser:        false,
					IsBlocked:            false,
					NonDeletable:         false,
					LastLogin:            time.Time{},
					Issued:               "api",
					IntegrationReference: integration_reference.IntegrationReference{},
				},
				Permissions: mergeRolePermissions(roles.User),
				Restricted:  true,
			},
		},

		{
			name:     "settings blocked regular user child account",
			userAuth: auth.UserAuth{AccountId: account2.Id, UserId: "settings-blocked-user", IsChild: true},
			expectedResult: &users.UserInfoWithPermissions{
				UserInfo: &types.UserInfo{
					ID:                   "settings-blocked-user",
					Name:                 "",
					Role:                 "user",
					Status:               "active",
					IsServiceUser:        false,
					IsBlocked:            false,
					NonDeletable:         false,
					LastLogin:            time.Time{},
					Issued:               "api",
					IntegrationReference: integration_reference.IntegrationReference{},
				},
				Permissions: mergeRolePermissions(roles.User),
				Restricted:  false,
			},
		},
		{
			name:     "settings blocked owner user",
			userAuth: auth.UserAuth{AccountId: account2.Id, UserId: "account2Owner"},
			expectedResult: &users.UserInfoWithPermissions{
				UserInfo: &types.UserInfo{
					ID:                   "account2Owner",
					Name:                 "",
					Role:                 "owner",
					AutoGroups:           []string{},
					Status:               "active",
					IsServiceUser:        false,
					IsBlocked:            false,
					NonDeletable:         false,
					LastLogin:            time.Time{},
					Issued:               "api",
					IntegrationReference: integration_reference.IntegrationReference{},
				},
				Permissions: mergeRolePermissions(roles.Owner),
			},
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			result, err := am.GetCurrentUserInfo(context.Background(), tc.userAuth)

			if tc.expectedErr != nil {
				assert.Equal(t, err, tc.expectedErr)
				return
			}

			require.NoError(t, err)
			assert.EqualValues(t, tc.expectedResult, result)
		})
	}
}

func mergeRolePermissions(role roles.RolePermissions) roles.Permissions {
	permissions := roles.Permissions{}

	for k := range modules.All {
		if rolePermissions, ok := role.Permissions[k]; ok {
			permissions[k] = rolePermissions
			continue
		}
		permissions[k] = role.AutoAllowNew
	}

	return permissions
}

func TestApproveUser(t *testing.T) {
	manager, _, err := createManager(t)
	if err != nil {
		t.Fatal(err)
	}

	// Create account with admin and pending approval user
	account := newAccountWithId(context.Background(), "account-1", "admin-user", "example.com", "", "", false)
	err = manager.Store.SaveAccount(context.Background(), account)
	require.NoError(t, err)

	// Create admin user
	adminUser := types.NewAdminUser("admin-user")
	adminUser.AccountID = account.Id
	err = manager.Store.SaveUser(context.Background(), adminUser)
	require.NoError(t, err)

	// Create user pending approval
	pendingUser := types.NewRegularUser("pending-user", "", "")
	pendingUser.AccountID = account.Id
	pendingUser.Blocked = true
	pendingUser.PendingApproval = true
	err = manager.Store.SaveUser(context.Background(), pendingUser)
	require.NoError(t, err)

	// Test successful approval
	approvedUser, err := manager.ApproveUser(context.Background(), account.Id, adminUser.Id, pendingUser.Id)
	require.NoError(t, err)
	assert.False(t, approvedUser.IsBlocked)
	assert.False(t, approvedUser.PendingApproval)

	// Verify user is updated in store
	updatedUser, err := manager.Store.GetUserByUserID(context.Background(), store.LockingStrengthNone, pendingUser.Id)
	require.NoError(t, err)
	assert.False(t, updatedUser.Blocked)
	assert.False(t, updatedUser.PendingApproval)

	// Test approval of non-pending user should fail
	_, err = manager.ApproveUser(context.Background(), account.Id, adminUser.Id, pendingUser.Id)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not pending approval")

	// Test approval by non-admin should fail
	regularUser := types.NewRegularUser("regular-user", "", "")
	regularUser.AccountID = account.Id
	err = manager.Store.SaveUser(context.Background(), regularUser)
	require.NoError(t, err)

	pendingUser2 := types.NewRegularUser("pending-user-2", "", "")
	pendingUser2.AccountID = account.Id
	pendingUser2.Blocked = true
	pendingUser2.PendingApproval = true
	err = manager.Store.SaveUser(context.Background(), pendingUser2)
	require.NoError(t, err)

	_, err = manager.ApproveUser(context.Background(), account.Id, regularUser.Id, pendingUser2.Id)
	require.Error(t, err)
}

func TestRejectUser(t *testing.T) {
	manager, _, err := createManager(t)
	if err != nil {
		t.Fatal(err)
	}

	// Create account with admin and pending approval user
	account := newAccountWithId(context.Background(), "account-1", "admin-user", "example.com", "", "", false)
	err = manager.Store.SaveAccount(context.Background(), account)
	require.NoError(t, err)

	// Create admin user
	adminUser := types.NewAdminUser("admin-user")
	adminUser.AccountID = account.Id
	err = manager.Store.SaveUser(context.Background(), adminUser)
	require.NoError(t, err)

	// Create user pending approval
	pendingUser := types.NewRegularUser("pending-user", "", "")
	pendingUser.AccountID = account.Id
	pendingUser.Blocked = true
	pendingUser.PendingApproval = true
	err = manager.Store.SaveUser(context.Background(), pendingUser)
	require.NoError(t, err)

	// Test successful rejection
	err = manager.RejectUser(context.Background(), account.Id, adminUser.Id, pendingUser.Id)
	require.NoError(t, err)

	// Verify user is deleted from store
	_, err = manager.Store.GetUserByUserID(context.Background(), store.LockingStrengthNone, pendingUser.Id)
	require.Error(t, err)

	// Test rejection of non-pending user should fail
	regularUser := types.NewRegularUser("regular-user", "", "")
	regularUser.AccountID = account.Id
	err = manager.Store.SaveUser(context.Background(), regularUser)
	require.NoError(t, err)

	err = manager.RejectUser(context.Background(), account.Id, adminUser.Id, regularUser.Id)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not pending approval")

	// Test rejection by non-admin should fail
	pendingUser2 := types.NewRegularUser("pending-user-2", "", "")
	pendingUser2.AccountID = account.Id
	pendingUser2.Blocked = true
	pendingUser2.PendingApproval = true
	err = manager.Store.SaveUser(context.Background(), pendingUser2)
	require.NoError(t, err)

	err = manager.RejectUser(context.Background(), account.Id, regularUser.Id, pendingUser2.Id)
	require.Error(t, err)
}

func TestUser_Operations_WithEmbeddedIDP(t *testing.T) {
	ctx := context.Background()

	// Create temporary directory for Dex
	tmpDir := t.TempDir()
	dexDataDir := tmpDir + "/dex"
	require.NoError(t, os.MkdirAll(dexDataDir, 0700))

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
	defer func() { _ = embeddedIdp.Stop(ctx) }()

	// Create test store
	testStore, cleanup, err := store.NewTestStoreFromSQL(ctx, "", tmpDir)
	require.NoError(t, err)
	defer cleanup()

	// Create account with owner user
	account := newAccountWithId(ctx, mockAccountID, mockUserID, "", "owner@test.com", "Owner User", false)
	require.NoError(t, testStore.SaveAccount(ctx, account))

	// Create mock network map controller
	ctrl := gomock.NewController(t)
	networkMapControllerMock := network_map.NewMockController(ctrl)
	networkMapControllerMock.EXPECT().
		OnPeersDeleted(gomock.Any(), gomock.Any(), gomock.Any()).
		Return(nil).
		AnyTimes()

	// Create account manager with embedded IDP
	permissionsManager := permissions.NewManager(testStore)
	am := DefaultAccountManager{
		Store:                testStore,
		eventStore:           &activity.InMemoryEventStore{},
		permissionsManager:   permissionsManager,
		idpManager:           embeddedIdp,
		cacheLoading:         map[string]chan struct{}{},
		networkMapController: networkMapControllerMock,
	}

	// Initialize cache manager
	cacheStore, err := nbcache.NewStore(ctx, nbcache.DefaultIDPCacheExpirationMax, nbcache.DefaultIDPCacheCleanupInterval, nbcache.DefaultIDPCacheOpenConn)
	require.NoError(t, err)
	am.cacheManager = nbcache.NewAccountUserDataCache(am.loadAccount, cacheStore)
	am.externalCacheManager = nbcache.NewUserDataCache(cacheStore)

	t.Run("create regular user returns password", func(t *testing.T) {
		userInfo, err := am.CreateUser(ctx, mockAccountID, mockUserID, &types.UserInfo{
			Email:         "newuser@test.com",
			Name:          "New User",
			Role:          "user",
			AutoGroups:    []string{},
			IsServiceUser: false,
		})
		require.NoError(t, err)
		require.NotNil(t, userInfo)

		// Verify user data
		assert.Equal(t, "newuser@test.com", userInfo.Email)
		assert.Equal(t, "New User", userInfo.Name)
		assert.Equal(t, "user", userInfo.Role)
		assert.NotEmpty(t, userInfo.ID)

		// IMPORTANT: Password should be returned for embedded IDP
		assert.NotEmpty(t, userInfo.Password, "Password should be returned for embedded IDP user")
		t.Logf("Created user: ID=%s, Email=%s, Password=%s", userInfo.ID, userInfo.Email, userInfo.Password)

		// Verify user ID is in Dex encoded format
		rawUserID, connectorID, err := dex.DecodeDexUserID(userInfo.ID)
		require.NoError(t, err)
		assert.NotEmpty(t, rawUserID)
		assert.Equal(t, "local", connectorID)
		t.Logf("Decoded user ID: rawUserID=%s, connectorID=%s", rawUserID, connectorID)

		// Verify user exists in database with correct data
		dbUser, err := testStore.GetUserByUserID(ctx, store.LockingStrengthNone, userInfo.ID)
		require.NoError(t, err)
		assert.Equal(t, "newuser@test.com", dbUser.Email)
		assert.Equal(t, "New User", dbUser.Name)

		// Store user ID for delete test
		createdUserID := userInfo.ID

		t.Run("delete user works", func(t *testing.T) {
			err := am.DeleteUser(ctx, mockAccountID, mockUserID, createdUserID)
			require.NoError(t, err)

			// Verify user is deleted from database
			_, err = testStore.GetUserByUserID(ctx, store.LockingStrengthNone, createdUserID)
			assert.Error(t, err, "User should be deleted from database")
		})
	})

	t.Run("create service user does not return password", func(t *testing.T) {
		userInfo, err := am.CreateUser(ctx, mockAccountID, mockUserID, &types.UserInfo{
			Name:          "Service User",
			Role:          "user",
			AutoGroups:    []string{},
			IsServiceUser: true,
		})
		require.NoError(t, err)
		require.NotNil(t, userInfo)

		assert.True(t, userInfo.IsServiceUser)
		assert.Equal(t, "Service User", userInfo.Name)
		// Service users don't have passwords
		assert.Empty(t, userInfo.Password, "Service users should not have passwords")
	})

	t.Run("duplicate email fails", func(t *testing.T) {
		// Create first user
		_, err := am.CreateUser(ctx, mockAccountID, mockUserID, &types.UserInfo{
			Email:         "duplicate@test.com",
			Name:          "First User",
			Role:          "user",
			AutoGroups:    []string{},
			IsServiceUser: false,
		})
		require.NoError(t, err)

		// Try to create second user with same email
		_, err = am.CreateUser(ctx, mockAccountID, mockUserID, &types.UserInfo{
			Email:         "duplicate@test.com",
			Name:          "Second User",
			Role:          "user",
			AutoGroups:    []string{},
			IsServiceUser: false,
		})
		assert.Error(t, err, "Creating user with duplicate email should fail")
		t.Logf("Duplicate email error: %v", err)
	})
}
