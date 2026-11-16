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

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"

	nbcontext "github.com/netbirdio/netbird/management/server/context"
	"github.com/netbirdio/netbird/management/server/mock_server"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/auth"
	"github.com/netbirdio/netbird/shared/management/http/apiv1alpha1"
	"github.com/netbirdio/netbird/shared/management/status"
)

const (
	existingAccountID         = "existingAccountID"
	notFoundAccountID         = "notFoundAccountID"
	testDomain                = "hotmail.com"
	existingUserID            = "existingUserID"
	notFoundUserID            = "notFoundUserID"
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

func initUsersTestData() *Handler {
	return &Handler{
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
		{name: "getAllUsers", requestType: http.MethodGet, requestPath: "/users", expectedStatus: http.StatusOK, expectedUserIDs: []string{existingUserID, regularUserID, serviceUserID}},
		{name: "GetOnlyServiceUsers", requestType: http.MethodGet, requestPath: "/users?service_user=true", expectedStatus: http.StatusOK, expectedUserIDs: []string{serviceUserID}},
		{name: "GetOnlyRegularUsers", requestType: http.MethodGet, requestPath: "/users?service_user=false", expectedStatus: http.StatusOK, expectedUserIDs: []string{existingUserID, regularUserID}},
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

			v1validator, err := apiv1alpha1.CreateV1ApiValidatingMiddleware()
			assert.NoError(t, err)
			router := mux.NewRouter()
			router.Use(v1validator.Handler)

			router = userHandler.WithEndpointsForRouter(router)
			router.ServeHTTP(recorder, req)

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
			requestPath:        "/users/" + regularUserID,
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
			requestPath:        "/users/" + regularUserID,
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
			requestPath:        "/users/" + regularUserID,
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
			requestPath:        "/users/" + regularUserID,
			expectedStatusCode: http.StatusUnprocessableEntity,
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
			req.Header.Set("Content-Type", "application/json")
			req = nbcontext.SetUserAuthInRequest(req, auth.UserAuth{
				UserId:    existingUserID,
				Domain:    testDomain,
				AccountId: existingAccountID,
			})

			v1validator, err := apiv1alpha1.CreateV1ApiValidatingMiddleware()
			assert.NoError(t, err)

			router := mux.NewRouter()
			router.Use(v1validator.Handler)

			router = userHandler.WithEndpointsForRouter(router)
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

				respBody := &apiv1alpha1.User{}
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
	serviceUserToAdd := apiv1alpha1.UserCreateRequest{
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

	regularUserToAdd := apiv1alpha1.UserCreateRequest{
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
		{name: "CreateServiceUser", requestType: http.MethodPost, requestPath: "/users", expectedStatus: http.StatusOK, requestBody: bytes.NewBuffer(serviceUserString)},
		// right now creation is blocked in AC middleware, will be refactored in the future
		{name: "CreateRegularUser", requestType: http.MethodPost, requestPath: "/users", expectedStatus: http.StatusOK, requestBody: bytes.NewBuffer(regularUserString)},
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
			req.Header.Set("Content-Type", "application/json")

			v1validator, err := apiv1alpha1.CreateV1ApiValidatingMiddleware()
			assert.NoError(t, err)

			router := mux.NewRouter()
			router.Use(v1validator.Handler)

			router = userHandler.WithEndpointsForRouter(router)
			router.ServeHTTP(rr, req)

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
			requestPath:    "/users/" + regularUserID,
			requestVars:    map[string]string{"userId": regularUserID},
			expectedStatus: http.StatusForbidden,
		},
		{
			name:           "Delete Service User",
			requestType:    http.MethodDelete,
			requestPath:    "/users/" + serviceUserID,
			requestVars:    map[string]string{"userId": serviceUserID},
			expectedStatus: http.StatusOK,
		},
		{
			name:           "Delete Not Existing User",
			requestType:    http.MethodDelete,
			requestPath:    "/users/" + notFoundUserID,
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

			v1validator, err := apiv1alpha1.CreateV1ApiValidatingMiddleware()
			assert.NoError(t, err)

			router := mux.NewRouter()
			router.Use(v1validator.Handler)
			router = userHandler.WithEndpointsForRouter(router)
			router.ServeHTTP(rr, req)

			res := rr.Result()
			defer res.Body.Close()

			if status := rr.Code; status != tc.expectedStatus {
				t.Fatalf("handler returned wrong status code: got %v want %v",
					status, tc.expectedStatus)
			}
		})
	}
}
