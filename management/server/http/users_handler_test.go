package http

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"

	"github.com/netbirdio/netbird/management/server"
	"github.com/netbirdio/netbird/management/server/http/api"
	"github.com/netbirdio/netbird/management/server/jwtclaims"
	"github.com/netbirdio/netbird/management/server/mock_server"
	"github.com/netbirdio/netbird/management/server/status"
)

const (
	serviceUserID             = "serviceUserID"
	nonDeletableServiceUserID = "nonDeletableServiceUserID"
	regularUserID             = "regularUserID"
)

var usersTestAccount = &server.Account{
	Id:     existingAccountID,
	Domain: domain,
	Users: map[string]*server.User{
		existingUserID: {
			Id:            existingUserID,
			Role:          "admin",
			IsServiceUser: false,
			AutoGroups:    []string{"group_1"},
			Issued:        server.UserIssuedAPI,
		},
		regularUserID: {
			Id:            regularUserID,
			Role:          "user",
			IsServiceUser: false,
			AutoGroups:    []string{"group_1"},
			Issued:        server.UserIssuedAPI,
		},
		serviceUserID: {
			Id:            serviceUserID,
			Role:          "user",
			IsServiceUser: true,
			AutoGroups:    []string{"group_1"},
			Issued:        server.UserIssuedAPI,
		},
		nonDeletableServiceUserID: {
			Id:            serviceUserID,
			Role:          "admin",
			IsServiceUser: true,
			NonDeletable:  true,
			Issued:        server.UserIssuedIntegration,
		},
	},
}

func initUsersTestData() *UsersHandler {
	return &UsersHandler{
		accountManager: &mock_server.MockAccountManager{
			GetAccountFromTokenFunc: func(claims jwtclaims.AuthorizationClaims) (*server.Account, *server.User, error) {
				return usersTestAccount, usersTestAccount.Users[claims.UserId], nil
			},
			GetUsersFromAccountFunc: func(accountID, userID string) ([]*server.UserInfo, error) {
				users := make([]*server.UserInfo, 0)
				for _, v := range usersTestAccount.Users {
					users = append(users, &server.UserInfo{
						ID:            v.Id,
						Role:          string(v.Role),
						Name:          "",
						Email:         "",
						IsServiceUser: v.IsServiceUser,
						NonDeletable:  v.NonDeletable,
						Issued:        v.Issued,
					})
				}
				return users, nil
			},
			CreateUserFunc: func(accountID, userID string, key *server.UserInfo) (*server.UserInfo, error) {
				if userID != existingUserID {
					return nil, status.Errorf(status.NotFound, "user with ID %s does not exists", userID)
				}
				return key, nil
			},
			DeleteUserFunc: func(accountID string, initiatorUserID string, targetUserID string) error {
				if targetUserID == notFoundUserID {
					return status.Errorf(status.NotFound, "user with ID %s does not exists", targetUserID)
				}
				if !usersTestAccount.Users[targetUserID].IsServiceUser {
					return status.Errorf(status.PermissionDenied, "user with ID %s is not a service user and can not be deleted", targetUserID)
				}
				return nil
			},
			SaveUserFunc: func(accountID, userID string, update *server.User) (*server.UserInfo, error) {
				if update.Id == notFoundUserID {
					return nil, status.Errorf(status.NotFound, "user with ID %s does not exists", update.Id)
				}

				if userID != existingUserID {
					return nil, status.Errorf(status.NotFound, "user with ID %s does not exists", userID)
				}

				info, err := update.Copy().ToUserInfo(nil, &server.Settings{RegularUsersViewBlocked: false})
				if err != nil {
					return nil, err
				}
				return info, nil
			},
			InviteUserFunc: func(accountID string, initiatorUserID string, targetUserID string) error {
				if initiatorUserID != existingUserID {
					return status.Errorf(status.NotFound, "user with ID %s does not exists", initiatorUserID)
				}

				if targetUserID == notFoundUserID {
					return status.Errorf(status.NotFound, "user with ID %s does not exists", targetUserID)
				}

				return nil
			},
		},
		claimsExtractor: jwtclaims.NewClaimsExtractor(
			jwtclaims.WithFromRequestContext(func(r *http.Request) jwtclaims.AuthorizationClaims {
				return jwtclaims.AuthorizationClaims{
					UserId:    existingUserID,
					Domain:    domain,
					AccountId: existingAccountID,
				}
			}),
		),
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
		{name: "GetAllUsers", requestType: http.MethodGet, requestPath: "/api/users", expectedStatus: http.StatusOK, expectedUserIDs: []string{existingUserID, regularUserID, serviceUserID}},
		{name: "GetOnlyServiceUsers", requestType: http.MethodGet, requestPath: "/api/users?service_user=true", expectedStatus: http.StatusOK, expectedUserIDs: []string{serviceUserID}},
		{name: "GetOnlyRegularUsers", requestType: http.MethodGet, requestPath: "/api/users?service_user=false", expectedStatus: http.StatusOK, expectedUserIDs: []string{existingUserID, regularUserID}},
	}

	userHandler := initUsersTestData()

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			req := httptest.NewRequest(tc.requestType, tc.requestPath, nil)

			userHandler.GetAllUsers(recorder, req)

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

			respBody := []*server.UserInfo{}
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

			router := mux.NewRouter()
			router.HandleFunc("/api/users/{userId}", userHandler.UpdateUser).Methods("PUT")
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
		expectedResult []*server.User
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

			userHandler.CreateUser(rr, req)

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
			rr := httptest.NewRecorder()

			userHandler.InviteUser(rr, req)

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
			rr := httptest.NewRecorder()

			userHandler.DeleteUser(rr, req)

			res := rr.Result()
			defer res.Body.Close()

			if status := rr.Code; status != tc.expectedStatus {
				t.Fatalf("handler returned wrong status code: got %v want %v",
					status, tc.expectedStatus)
			}
		})
	}
}
