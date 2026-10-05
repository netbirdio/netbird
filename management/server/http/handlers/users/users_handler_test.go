package users

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	nbcontext "github.com/netbirdio/netbird/management/server/context"
	"github.com/netbirdio/netbird/management/server/mock_server"
	"github.com/netbirdio/netbird/management/server/permissions/modules"
	"github.com/netbirdio/netbird/management/server/permissions/roles"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/management/server/users"
	"github.com/netbirdio/netbird/shared/auth"
	"github.com/netbirdio/netbird/shared/management/http/api"
	"github.com/netbirdio/netbird/shared/management/status"
)

const (
	serviceUserID             = "serviceUserID"
	nonDeletableServiceUserID = "nonDeletableServiceUserID"
	regularUserID             = "regularUserID"
)

var usersTestAccount = &types.Account{
	Id:     existingAccountID,
	Domain: testDomain,
	Users: map[string]*types.User{
		existingUserID: {
			Id:            existingUserID,
			Role:          "admin",
			IsServiceUser: false,
			AutoGroups:    []string{"group_1"},
			Issued:        types.UserIssuedAPI,
		},
		regularUserID: {
			Id:            regularUserID,
			Role:          "user",
			IsServiceUser: false,
			AutoGroups:    []string{"group_1"},
			Issued:        types.UserIssuedAPI,
		},
		serviceUserID: {
			Id:            serviceUserID,
			Role:          "user",
			IsServiceUser: true,
			AutoGroups:    []string{"group_1"},
			Issued:        types.UserIssuedAPI,
		},
		nonDeletableServiceUserID: {
			Id:            nonDeletableServiceUserID,
			Role:          "admin",
			IsServiceUser: true,
			NonDeletable:  true,
			Issued:        types.UserIssuedIntegration,
		},
	},
}

func initUsersTestData() *handler {
	return &handler{
		accountManager: &mock_server.MockAccountManager{
			GetUserByIDFunc: func(ctx context.Context, id string) (*types.User, error) {
				return usersTestAccount.Users[id], nil
			},
			GetUsersFromAccountFunc: func(_ context.Context, accountID, userID string) (map[string]*types.UserInfo, error) {
				usersInfos := make(map[string]*types.UserInfo)
				for _, v := range usersTestAccount.Users {
					usersInfos[v.Id] = &types.UserInfo{
						ID:            v.Id,
						Role:          string(v.Role),
						Name:          "",
						Email:         "",
						IsServiceUser: v.IsServiceUser,
						NonDeletable:  v.NonDeletable,
						Issued:        v.Issued,
					}
				}
				return usersInfos, nil
			},
			CreateUserFunc: func(_ context.Context, accountID, userID string, key *types.UserInfo) (*types.UserInfo, error) {
				if userID != existingUserID {
					return nil, status.Errorf(status.NotFound, "user with ID %s does not exists", userID)
				}
				return key, nil
			},
			DeleteUserFunc: func(_ context.Context, accountID string, initiatorUserID string, targetUserID string) error {
				if targetUserID == notFoundUserID {
					return status.Errorf(status.NotFound, "user with ID %s does not exists", targetUserID)
				}
				if !usersTestAccount.Users[targetUserID].IsServiceUser {
					return status.Errorf(status.PermissionDenied, "user with ID %s is not a service user and can not be deleted", targetUserID)
				}
				return nil
			},
			SaveUserFunc: func(_ context.Context, accountID, userID string, update *types.User) (*types.UserInfo, error) {
				if update.Id == notFoundUserID {
					return nil, status.Errorf(status.NotFound, "user with ID %s does not exists", update.Id)
				}

				if userID != existingUserID {
					return nil, status.Errorf(status.NotFound, "user with ID %s does not exists", userID)
				}

				info, err := update.Copy().ToUserInfo(nil)
				if err != nil {
					return nil, err
				}
				return info, nil
			},
			InviteUserFunc: func(_ context.Context, accountID string, initiatorUserID string, targetUserID string) error {
				if initiatorUserID != existingUserID {
					return status.Errorf(status.NotFound, "user with ID %s does not exists", initiatorUserID)
				}

				if targetUserID == notFoundUserID {
					return status.Errorf(status.NotFound, "user with ID %s does not exists", targetUserID)
				}

				return nil
			},
			GetCurrentUserInfoFunc: func(ctx context.Context, userAuth auth.UserAuth) (*users.UserInfoWithPermissions, error) {
				switch userAuth.UserId {
				case "not-found":
					return nil, status.NewUserNotFoundError("not-found")
				case "not-of-account":
					return nil, status.NewUserNotPartOfAccountError()
				case "blocked-user":
					return nil, status.NewUserBlockedError()
				case "service-user":
					return nil, status.NewPermissionDeniedError()
				case "owner":
					return &users.UserInfoWithPermissions{
						UserInfo: &types.UserInfo{
							ID:            "owner",
							Name:          "",
							Role:          "owner",
							Status:        "active",
							IsServiceUser: false,
							IsBlocked:     false,
							NonDeletable:  false,
							Issued:        "api",
						},
						Permissions: mergeRolePermissions(roles.Owner),
					}, nil
				case "regular-user":
					return &users.UserInfoWithPermissions{
						UserInfo: &types.UserInfo{
							ID:            "regular-user",
							Name:          "",
							Role:          "user",
							Status:        "active",
							IsServiceUser: false,
							IsBlocked:     false,
							NonDeletable:  false,
							Issued:        "api",
						},
						Permissions: mergeRolePermissions(roles.User),
					}, nil

				case "admin-user":
					return &users.UserInfoWithPermissions{
						UserInfo: &types.UserInfo{
							ID:            "admin-user",
							Name:          "",
							Role:          "admin",
							Status:        "active",
							IsServiceUser: false,
							IsBlocked:     false,
							NonDeletable:  false,
							LastLogin:     time.Time{},
							Issued:        "api",
						},
						Permissions: mergeRolePermissions(roles.Admin),
					}, nil
				case "restricted-user":
					return &users.UserInfoWithPermissions{
						UserInfo: &types.UserInfo{
							ID:            "restricted-user",
							Name:          "",
							Role:          "user",
							Status:        "active",
							IsServiceUser: false,
							IsBlocked:     false,
							NonDeletable:  false,
							LastLogin:     time.Time{},
							Issued:        "api",
						},
						Permissions: mergeRolePermissions(roles.User),
						Restricted:  true,
					}, nil
				}

				return nil, fmt.Errorf("user id %s not handled", userAuth.UserId)
			},
		},
	}
}

func TestGetUsers(t *testing.T) {
	tt := []struct {
		name            string
		expectedStatus  int
		requestType     string
		requestPath     string
		expectedUserIDs []string
	}{
		{name: "getAllUsers", requestType: http.MethodGet, requestPath: "/api/users", expectedStatus: http.StatusOK, expectedUserIDs: []string{existingUserID, regularUserID, serviceUserID}},
		{name: "GetOnlyServiceUsers", requestType: http.MethodGet, requestPath: "/api/users?service_user=true", expectedStatus: http.StatusOK, expectedUserIDs: []string{serviceUserID}},
		{name: "GetOnlyRegularUsers", requestType: http.MethodGet, requestPath: "/api/users?service_user=false", expectedStatus: http.StatusOK, expectedUserIDs: []string{existingUserID, regularUserID}},
	}

	userHandler := initUsersTestData()

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			req := httptest.NewRequest(tc.requestType, tc.requestPath, nil)
			req = nbcontext.SetUserAuthInRequest(req, auth.UserAuth{
				UserId:    existingUserID,
				Domain:    testDomain,
				AccountId: existingAccountID,
			})

			userHandler.getAllUsers(recorder, req)

			res := recorder.Result()
			defer res.Body.Close()

			content, err := io.ReadAll(res.Body)
			if err != nil {
				t.Fatalf("I don't know what I expected; %v", err)
			}

			if status := recorder.Code; status != tc.expectedStatus {
				t.Errorf("handler returned wrong status code: got %v want %v, content: %s",
					status, tc.expectedStatus, string(content))
				return
			}

			respBody := []*types.UserInfo{}
			err = json.Unmarshal(content, &respBody)
			if err != nil {
				t.Fatalf("Sent content is not in correct json format; %v", err)
			}

			assert.Equal(t, len(respBody), len(tc.expectedUserIDs))
			for _, v := range respBody {
				assert.Contains(t, tc.expectedUserIDs, v.ID)
				assert.Equal(t, v.ID, usersTestAccount.Users[v.ID].Id)
				assert.Equal(t, v.Role, string(usersTestAccount.Users[v.ID].Role))
				assert.Equal(t, v.IsServiceUser, usersTestAccount.Users[v.ID].IsServiceUser)
				assert.Equal(t, v.Issued, usersTestAccount.Users[v.ID].Issued)
			}
		})
	}
}

func TestUpdateUser(t *testing.T) {
	tt := []struct {
		name                  string
		expectedStatusCode    int
		requestType           string
		requestPath           string
		requestBody           io.Reader
		expectedUserID        string
		expectedRole          string
		expectedStatus        string
		expectedBlocked       bool
		expectedIsServiceUser bool
		expectedGroups        []string
	}{
		{
			name:               "Update_Block_User",
			requestType:        http.MethodPut,
			requestPath:        "/api/users/" + regularUserID,
			expectedStatusCode: http.StatusOK,
			expectedUserID:     regularUserID,
			expectedBlocked:    true,
			expectedRole:       "user",
			expectedStatus:     "blocked",
			expectedGroups:     []string{"group_1"},
			requestBody:        bytes.NewBufferString("{\"role\":\"user\",\"auto_groups\":[\"group_1\"],\"is_service_user\":false, \"is_blocked\": true}"),
		},
		{
			name:               "Update_Change_Role_To_Admin",
			requestType:        http.MethodPut,
			requestPath:        "/api/users/" + regularUserID,
			expectedStatusCode: http.StatusOK,
			expectedUserID:     regularUserID,
			expectedBlocked:    false,
			expectedRole:       "admin",
			expectedStatus:     "blocked",
			expectedGroups:     []string{"group_1"},
			requestBody:        bytes.NewBufferString("{\"role\":\"admin\",\"auto_groups\":[\"group_1\"],\"is_service_user\":false, \"is_blocked\": false}"),
		},
		{
			name:               "Update_Groups",
			requestType:        http.MethodPut,
			requestPath:        "/api/users/" + regularUserID,
			expectedStatusCode: http.StatusOK,
			expectedUserID:     regularUserID,
			expectedBlocked:    false,
			expectedRole:       "admin",
			expectedStatus:     "blocked",
			expectedGroups:     []string{"group_2", "group_3"},
			requestBody:        bytes.NewBufferString("{\"role\":\"admin\",\"auto_groups\":[\"group_3\", \"group_2\"],\"is_service_user\":false, \"is_blocked\": false}"),
		},
		{
			name:               "Should_Fail_Because_AutoGroups_Is_Absent",
			requestType:        http.MethodPut,
			requestPath:        "/api/users/" + regularUserID,
			expectedStatusCode: http.StatusBadRequest,
			expectedUserID:     regularUserID,
			expectedBlocked:    false,
			expectedRole:       "admin",
			expectedStatus:     "blocked",
			expectedGroups:     []string{"group_2", "group_3"},
			requestBody:        bytes.NewBufferString("{\"role\":\"admin\",\"is_service_user\":false, \"is_blocked\": false}"),
		},
	}

	userHandler := initUsersTestData()

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			req := httptest.NewRequest(tc.requestType, tc.requestPath, tc.requestBody)
			req = nbcontext.SetUserAuthInRequest(req, auth.UserAuth{
				UserId:    existingUserID,
				Domain:    testDomain,
				AccountId: existingAccountID,
			})

			router := mux.NewRouter()
			router.HandleFunc("/api/users/{userId}", userHandler.updateUser).Methods("PUT")
			router.ServeHTTP(recorder, req)

			res := recorder.Result()
			defer res.Body.Close()

			if status := recorder.Code; status != tc.expectedStatusCode {
				t.Fatalf("handler returned wrong status code: got %v want %v",
					status, http.StatusOK)
			}

			if tc.expectedStatusCode == 200 {

				content, err := io.ReadAll(res.Body)
				if err != nil {
					t.Fatalf("I don't know what I expected; %v", err)
				}

				respBody := &api.User{}
				err = json.Unmarshal(content, &respBody)
				if err != nil {
					t.Fatalf("response content is not in correct json format; %v", err)
				}

				assert.Equal(t, tc.expectedUserID, respBody.Id)
				assert.Equal(t, tc.expectedRole, respBody.Role)
				assert.Equal(t, tc.expectedIsServiceUser, *respBody.IsServiceUser)
				assert.Equal(t, tc.expectedBlocked, respBody.IsBlocked)
				assert.Len(t, respBody.AutoGroups, len(tc.expectedGroups))

				for _, expectedGroup := range tc.expectedGroups {
					exists := false
					for _, actualGroup := range respBody.AutoGroups {
						if expectedGroup == actualGroup {
							exists = true
						}
					}
					assert.True(t, exists, fmt.Sprintf("group %s not found in the response", expectedGroup))
				}
			}
		})
	}
}

func TestCreateUser(t *testing.T) {
	name := "name"
	email := "email"
	serviceUserToAdd := api.UserCreateRequest{
		AutoGroups:    []string{},
		Email:         nil,
		IsServiceUser: true,
		Name:          &name,
		Role:          "admin",
	}
	serviceUserString, err := json.Marshal(serviceUserToAdd)
	if err != nil {
		t.Fatal(err)
	}

	regularUserToAdd := api.UserCreateRequest{
		AutoGroups:    []string{},
		Email:         &email,
		IsServiceUser: true,
		Name:          &name,
		Role:          "admin",
	}
	regularUserString, err := json.Marshal(regularUserToAdd)
	if err != nil {
		t.Fatal(err)
	}

	tt := []struct {
		name           string
		expectedStatus int
		requestType    string
		requestPath    string
		requestBody    io.Reader
		expectedResult []*types.User
	}{
		{name: "CreateServiceUser", requestType: http.MethodPost, requestPath: "/api/users", expectedStatus: http.StatusOK, requestBody: bytes.NewBuffer(serviceUserString)},
		// right now creation is blocked in AC middleware, will be refactored in the future
		{name: "CreateRegularUser", requestType: http.MethodPost, requestPath: "/api/users", expectedStatus: http.StatusOK, requestBody: bytes.NewBuffer(regularUserString)},
	}

	userHandler := initUsersTestData()

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.requestType, tc.requestPath, tc.requestBody)
			rr := httptest.NewRecorder()
			req = nbcontext.SetUserAuthInRequest(req, auth.UserAuth{
				UserId:    existingUserID,
				Domain:    testDomain,
				AccountId: existingAccountID,
			})

			userHandler.createUser(rr, req)

			res := rr.Result()
			defer res.Body.Close()

			if status := rr.Code; status != tc.expectedStatus {
				t.Fatalf("handler returned wrong status code: got %v want %v",
					status, tc.expectedStatus)
			}
		})
	}
}

func TestInviteUser(t *testing.T) {
	tt := []struct {
		name           string
		expectedStatus int
		requestType    string
		requestPath    string
		requestVars    map[string]string
	}{
		{
			name:           "Invite User with Existing User",
			requestType:    http.MethodPost,
			requestPath:    "/api/users/" + existingUserID + "/invite",
			expectedStatus: http.StatusOK,
			requestVars:    map[string]string{"userId": existingUserID},
		},
		{
			name:           "Invite User with missing user_id",
			requestType:    http.MethodPost,
			requestPath:    "/api/users/" + notFoundUserID + "/invite",
			expectedStatus: http.StatusNotFound,
			requestVars:    map[string]string{"userId": notFoundUserID},
		},
	}

	userHandler := initUsersTestData()

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.requestType, tc.requestPath, nil)
			req = mux.SetURLVars(req, tc.requestVars)
			req = nbcontext.SetUserAuthInRequest(req, auth.UserAuth{
				UserId:    existingUserID,
				Domain:    testDomain,
				AccountId: existingAccountID,
			})

			rr := httptest.NewRecorder()

			userHandler.inviteUser(rr, req)

			res := rr.Result()
			defer res.Body.Close()

			if status := rr.Code; status != tc.expectedStatus {
				t.Fatalf("handler returned wrong status code: got %v want %v",
					status, tc.expectedStatus)
			}
		})
	}
}

func TestDeleteUser(t *testing.T) {
	tt := []struct {
		name           string
		expectedStatus int
		expectedBody   bool
		requestType    string
		requestPath    string
		requestVars    map[string]string
		requestBody    io.Reader
	}{
		{
			name:           "Delete Regular User",
			requestType:    http.MethodDelete,
			requestPath:    "/api/users/" + regularUserID,
			requestVars:    map[string]string{"userId": regularUserID},
			expectedStatus: http.StatusForbidden,
		},
		{
			name:           "Delete Service User",
			requestType:    http.MethodDelete,
			requestPath:    "/api/users/" + serviceUserID,
			requestVars:    map[string]string{"userId": serviceUserID},
			expectedStatus: http.StatusOK,
		},
		{
			name:           "Delete Not Existing User",
			requestType:    http.MethodDelete,
			requestPath:    "/api/users/" + notFoundUserID,
			requestVars:    map[string]string{"userId": notFoundUserID},
			expectedStatus: http.StatusNotFound,
		},
	}

	userHandler := initUsersTestData()
	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.requestType, tc.requestPath, nil)
			req = mux.SetURLVars(req, tc.requestVars)
			req = nbcontext.SetUserAuthInRequest(req, auth.UserAuth{
				UserId:    existingUserID,
				Domain:    testDomain,
				AccountId: existingAccountID,
			})

			rr := httptest.NewRecorder()

			userHandler.deleteUser(rr, req)

			res := rr.Result()
			defer res.Body.Close()

			if status := rr.Code; status != tc.expectedStatus {
				t.Fatalf("handler returned wrong status code: got %v want %v",
					status, tc.expectedStatus)
			}
		})
	}
}

func TestCurrentUser(t *testing.T) {
	tt := []struct {
		name           string
		expectedStatus int
		requestAuth    auth.UserAuth
		expectedResult *api.User
	}{
		{
			name:           "without auth",
			expectedStatus: http.StatusInternalServerError,
		},
		{
			name:           "user not found",
			requestAuth:    auth.UserAuth{UserId: "not-found"},
			expectedStatus: http.StatusNotFound,
		},
		{
			name:           "not of account",
			requestAuth:    auth.UserAuth{UserId: "not-of-account"},
			expectedStatus: http.StatusForbidden,
		},
		{
			name:           "blocked user",
			requestAuth:    auth.UserAuth{UserId: "blocked-user"},
			expectedStatus: http.StatusForbidden,
		},
		{
			name:           "service user",
			requestAuth:    auth.UserAuth{UserId: "service-user"},
			expectedStatus: http.StatusForbidden,
		},
		{
			name:           "owner",
			requestAuth:    auth.UserAuth{UserId: "owner"},
			expectedStatus: http.StatusOK,
			expectedResult: &api.User{
				Id:            "owner",
				Role:          "owner",
				Status:        "active",
				IsBlocked:     false,
				IsCurrent:     ptr(true),
				IsServiceUser: ptr(false),
				AutoGroups:    []string{},
				Issued:        ptr("api"),
				LastLogin:     ptr(time.Time{}),
				Permissions: &api.UserPermissions{
					Modules: stringifyPermissionsKeys(mergeRolePermissions(roles.Owner)),
				},
			},
		},
		{
			name:           "regular user",
			requestAuth:    auth.UserAuth{UserId: "regular-user"},
			expectedStatus: http.StatusOK,
			expectedResult: &api.User{
				Id:            "regular-user",
				Role:          "user",
				Status:        "active",
				IsBlocked:     false,
				IsCurrent:     ptr(true),
				IsServiceUser: ptr(false),
				AutoGroups:    []string{},
				Issued:        ptr("api"),
				LastLogin:     ptr(time.Time{}),
				Permissions: &api.UserPermissions{
					Modules: stringifyPermissionsKeys(mergeRolePermissions(roles.User)),
				},
			},
		},
		{
			name:           "admin user",
			requestAuth:    auth.UserAuth{UserId: "admin-user"},
			expectedStatus: http.StatusOK,
			expectedResult: &api.User{
				Id:            "admin-user",
				Role:          "admin",
				Status:        "active",
				IsBlocked:     false,
				IsCurrent:     ptr(true),
				IsServiceUser: ptr(false),
				AutoGroups:    []string{},
				Issued:        ptr("api"),
				LastLogin:     ptr(time.Time{}),
				Permissions: &api.UserPermissions{
					Modules: stringifyPermissionsKeys(mergeRolePermissions(roles.Admin)),
				},
			},
		},
		{
			name:           "restricted user",
			requestAuth:    auth.UserAuth{UserId: "restricted-user"},
			expectedStatus: http.StatusOK,
			expectedResult: &api.User{
				Id:            "restricted-user",
				Role:          "user",
				Status:        "active",
				IsBlocked:     false,
				IsCurrent:     ptr(true),
				IsServiceUser: ptr(false),
				AutoGroups:    []string{},
				Issued:        ptr("api"),
				LastLogin:     ptr(time.Time{}),
				Permissions: &api.UserPermissions{
					IsRestricted: true,
					Modules:      stringifyPermissionsKeys(mergeRolePermissions(roles.User)),
				},
			},
		},
	}

	userHandler := initUsersTestData()
	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/users/current", nil)
			if tc.requestAuth.UserId != "" {
				req = nbcontext.SetUserAuthInRequest(req, tc.requestAuth)
			}

			rr := httptest.NewRecorder()

			userHandler.getCurrentUser(rr, req)

			res := rr.Result()
			defer res.Body.Close()

			assert.Equal(t, tc.expectedStatus, rr.Code, "handler returned wrong status code")

			if tc.expectedResult != nil {
				var result api.User
				require.NoError(t, json.NewDecoder(res.Body).Decode(&result))
				assert.EqualValues(t, *tc.expectedResult, result)
			}
		})
	}
}

func ptr[T any, PT *T](x T) PT {
	return &x
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

func stringifyPermissionsKeys(permissions roles.Permissions) map[string]map[string]bool {
	modules := make(map[string]map[string]bool)
	for module, operations := range permissions {
		modules[string(module)] = make(map[string]bool)
		for op, val := range operations {
			modules[string(module)][string(op)] = val
		}
	}
	return modules
}

func TestApproveUserEndpoint(t *testing.T) {
	adminUser := &types.User{
		Id:         "admin-user",
		Role:       types.UserRoleAdmin,
		AccountID:  existingAccountID,
		AutoGroups: []string{},
	}

	pendingUser := &types.User{
		Id:              "pending-user",
		Role:            types.UserRoleUser,
		AccountID:       existingAccountID,
		Blocked:         true,
		PendingApproval: true,
		AutoGroups:      []string{},
	}

	tt := []struct {
		name           string
		expectedStatus int
		expectedBody   bool
		requestingUser *types.User
	}{
		{
			name:           "approve user as admin should return 200",
			expectedStatus: 200,
			expectedBody:   true,
			requestingUser: adminUser,
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			am := &mock_server.MockAccountManager{}
			am.ApproveUserFunc = func(ctx context.Context, accountID, initiatorUserID, targetUserID string) (*types.UserInfo, error) {
				approvedUserInfo := &types.UserInfo{
					ID:              pendingUser.Id,
					Email:           "pending@example.com",
					Name:            "Pending User",
					Role:            string(pendingUser.Role),
					AutoGroups:      []string{},
					IsServiceUser:   false,
					IsBlocked:       false,
					PendingApproval: false,
					LastLogin:       time.Now(),
					Issued:          types.UserIssuedAPI,
				}
				return approvedUserInfo, nil
			}

			handler := newHandler(am)
			router := mux.NewRouter()
			router.HandleFunc("/users/{userId}/approve", handler.approveUser).Methods("POST")

			req, err := http.NewRequest("POST", "/users/pending-user/approve", nil)
			require.NoError(t, err)

			userAuth := auth.UserAuth{
				AccountId: existingAccountID,
				UserId:    tc.requestingUser.Id,
			}
			ctx := nbcontext.SetUserAuthInContext(req.Context(), userAuth)
			req = req.WithContext(ctx)

			rr := httptest.NewRecorder()
			router.ServeHTTP(rr, req)

			assert.Equal(t, tc.expectedStatus, rr.Code)

			if tc.expectedBody {
				var response api.User
				err = json.Unmarshal(rr.Body.Bytes(), &response)
				require.NoError(t, err)
				assert.Equal(t, "pending-user", response.Id)
				assert.False(t, response.IsBlocked)
				assert.False(t, response.PendingApproval)
			}
		})
	}
}

func TestRejectUserEndpoint(t *testing.T) {
	adminUser := &types.User{
		Id:         "admin-user",
		Role:       types.UserRoleAdmin,
		AccountID:  existingAccountID,
		AutoGroups: []string{},
	}

	tt := []struct {
		name           string
		expectedStatus int
		requestingUser *types.User
	}{
		{
			name:           "reject user as admin should return 200",
			expectedStatus: 200,
			requestingUser: adminUser,
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			am := &mock_server.MockAccountManager{}
			am.RejectUserFunc = func(ctx context.Context, accountID, initiatorUserID, targetUserID string) error {
				return nil
			}

			handler := newHandler(am)
			router := mux.NewRouter()
			router.HandleFunc("/users/{userId}/reject", handler.rejectUser).Methods("DELETE")

			req, err := http.NewRequest("DELETE", "/users/pending-user/reject", nil)
			require.NoError(t, err)

			userAuth := auth.UserAuth{
				AccountId: existingAccountID,
				UserId:    tc.requestingUser.Id,
			}
			ctx := nbcontext.SetUserAuthInContext(req.Context(), userAuth)
			req = req.WithContext(ctx)

			rr := httptest.NewRecorder()
			router.ServeHTTP(rr, req)

			assert.Equal(t, tc.expectedStatus, rr.Code)
		})
	}
}

func TestChangePasswordEndpoint(t *testing.T) {
	tt := []struct {
		name                string
		expectedStatus      int
		requestBody         string
		targetUserID        string
		currentUserID       string
		mockError           error
		expectMockNotCalled bool
	}{
		{
			name:           "successful password change",
			expectedStatus: http.StatusOK,
			requestBody:    `{"old_password": "OldPass123!", "new_password": "NewPass456!"}`,
			targetUserID:   existingUserID,
			currentUserID:  existingUserID,
			mockError:      nil,
		},
		{
			name:           "missing old password",
			expectedStatus: http.StatusUnprocessableEntity,
			requestBody:    `{"new_password": "NewPass456!"}`,
			targetUserID:   existingUserID,
			currentUserID:  existingUserID,
			mockError:      status.Errorf(status.InvalidArgument, "old password is required"),
		},
		{
			name:           "missing new password",
			expectedStatus: http.StatusUnprocessableEntity,
			requestBody:    `{"old_password": "OldPass123!"}`,
			targetUserID:   existingUserID,
			currentUserID:  existingUserID,
			mockError:      status.Errorf(status.InvalidArgument, "new password is required"),
		},
		{
			name:           "wrong old password",
			expectedStatus: http.StatusUnprocessableEntity,
			requestBody:    `{"old_password": "WrongPass!", "new_password": "NewPass456!"}`,
			targetUserID:   existingUserID,
			currentUserID:  existingUserID,
			mockError:      status.Errorf(status.InvalidArgument, "invalid password"),
		},
		{
			name:           "embedded IDP not enabled",
			expectedStatus: http.StatusPreconditionFailed,
			requestBody:    `{"old_password": "OldPass123!", "new_password": "NewPass456!"}`,
			targetUserID:   existingUserID,
			currentUserID:  existingUserID,
			mockError:      status.Errorf(status.PreconditionFailed, "password change is only available with embedded identity provider"),
		},
		{
			name:                "invalid JSON request",
			expectedStatus:      http.StatusBadRequest,
			requestBody:         `{invalid json}`,
			targetUserID:        existingUserID,
			currentUserID:       existingUserID,
			expectMockNotCalled: true,
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			mockCalled := false
			am := &mock_server.MockAccountManager{}
			am.UpdateUserPasswordFunc = func(ctx context.Context, accountID, currentUserID, targetUserID string, oldPassword, newPassword string) error {
				mockCalled = true
				return tc.mockError
			}

			handler := newHandler(am)
			router := mux.NewRouter()
			router.HandleFunc("/users/{userId}/password", handler.changePassword).Methods("PUT")

			reqPath := "/users/" + tc.targetUserID + "/password"
			req, err := http.NewRequest("PUT", reqPath, bytes.NewBufferString(tc.requestBody))
			require.NoError(t, err)

			userAuth := auth.UserAuth{
				AccountId: existingAccountID,
				UserId:    tc.currentUserID,
			}
			ctx := nbcontext.SetUserAuthInContext(req.Context(), userAuth)
			req = req.WithContext(ctx)

			rr := httptest.NewRecorder()
			router.ServeHTTP(rr, req)

			assert.Equal(t, tc.expectedStatus, rr.Code)

			if tc.expectMockNotCalled {
				assert.False(t, mockCalled, "mock should not have been called")
			}
		})
	}
}

func TestChangePasswordEndpoint_WrongMethod(t *testing.T) {
	am := &mock_server.MockAccountManager{}
	handler := newHandler(am)

	req, err := http.NewRequest("POST", "/users/test-user/password", bytes.NewBufferString(`{}`))
	require.NoError(t, err)

	userAuth := auth.UserAuth{
		AccountId: existingAccountID,
		UserId:    existingUserID,
	}
	req = nbcontext.SetUserAuthInRequest(req, userAuth)

	rr := httptest.NewRecorder()
	handler.changePassword(rr, req)

	assert.Equal(t, http.StatusMethodNotAllowed, rr.Code)
}
