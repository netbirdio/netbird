//go:build integration

package integration

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/netbirdio/netbird/management/server/http/testing/testing_tools"
	"github.com/netbirdio/netbird/management/server/http/testing/testing_tools/channel"
	"github.com/netbirdio/netbird/shared/management/http/api"
)

func Test_Users_GetAll(t *testing.T) {
	users := []struct {
		name           string
		userId         string
		expectResponse bool
	}{
		{"Regular user", testing_tools.TestUserId, true},
		{"Admin user", testing_tools.TestAdminId, true},
		{"Owner user", testing_tools.TestOwnerId, true},
		{"Regular service user", testing_tools.TestServiceUserId, true},
		{"Admin service user", testing_tools.TestServiceAdminId, true},
		{"Blocked user", testing_tools.BlockedUserId, false},
		{"Other user", testing_tools.OtherUserId, false},
		{"Invalid token", testing_tools.InvalidToken, false},
	}

	for _, user := range users {
		t.Run(user.name+" - Get all users", func(t *testing.T) {
			apiHandler, _, done := channel.BuildApiBlackBoxWithDBState(t, "../testdata/users_integration.sql", nil, true)

			req := testing_tools.BuildRequest(t, []byte{}, http.MethodGet, "/api/users", user.userId)
			recorder := httptest.NewRecorder()
			apiHandler.ServeHTTP(recorder, req)

			content, expectResponse := testing_tools.ReadResponse(t, recorder, http.StatusOK, user.expectResponse)
			if !expectResponse {
				return
			}

			got := []api.User{}
			if err := json.Unmarshal(content, &got); err != nil {
				t.Fatalf("Sent content is not in correct json format; %v", err)
			}

			assert.GreaterOrEqual(t, len(got), 1)

			select {
			case <-done:
			case <-time.After(time.Second):
				t.Error("timeout waiting for peerShouldNotReceiveUpdate")
			}
		})
	}
}

func Test_Users_GetAll_ServiceUsers(t *testing.T) {
	users := []struct {
		name           string
		userId         string
		expectResponse bool
	}{
		{"Regular user", testing_tools.TestUserId, false},
		{"Admin user", testing_tools.TestAdminId, true},
		{"Owner user", testing_tools.TestOwnerId, true},
		{"Regular service user", testing_tools.TestServiceUserId, false},
		{"Admin service user", testing_tools.TestServiceAdminId, true},
		{"Blocked user", testing_tools.BlockedUserId, false},
		{"Other user", testing_tools.OtherUserId, false},
		{"Invalid token", testing_tools.InvalidToken, false},
	}

	for _, user := range users {
		t.Run(user.name+" - Get all service users", func(t *testing.T) {
			apiHandler, _, done := channel.BuildApiBlackBoxWithDBState(t, "../testdata/users_integration.sql", nil, true)

			req := testing_tools.BuildRequest(t, []byte{}, http.MethodGet, "/api/users?service_user=true", user.userId)
			recorder := httptest.NewRecorder()
			apiHandler.ServeHTTP(recorder, req)

			content, expectResponse := testing_tools.ReadResponse(t, recorder, http.StatusOK, user.expectResponse)
			if !expectResponse {
				return
			}

			got := []api.User{}
			if err := json.Unmarshal(content, &got); err != nil {
				t.Fatalf("Sent content is not in correct json format; %v", err)
			}

			for _, u := range got {
				assert.NotNil(t, u.IsServiceUser)
				assert.Equal(t, true, *u.IsServiceUser)
			}

			select {
			case <-done:
			case <-time.After(time.Second):
				t.Error("timeout waiting for peerShouldNotReceiveUpdate")
			}
		})
	}
}

func Test_Users_Create_ServiceUser(t *testing.T) {
	users := []struct {
		name           string
		userId         string
		expectResponse bool
	}{
		{"Regular user", testing_tools.TestUserId, false},
		{"Admin user", testing_tools.TestAdminId, true},
		{"Owner user", testing_tools.TestOwnerId, true},
		{"Regular service user", testing_tools.TestServiceUserId, false},
		{"Admin service user", testing_tools.TestServiceAdminId, true},
		{"Blocked user", testing_tools.BlockedUserId, false},
		{"Other user", testing_tools.OtherUserId, false},
		{"Invalid token", testing_tools.InvalidToken, false},
	}

	tt := []struct {
		name           string
		requestBody    *api.UserCreateRequest
		expectedStatus int
		verifyResponse func(t *testing.T, user *api.User)
	}{
		{
			name: "Create service user with admin role",
			requestBody: &api.UserCreateRequest{
				Role:          "admin",
				IsServiceUser: true,
				AutoGroups:    []string{testing_tools.TestGroupId},
			},
			expectedStatus: http.StatusOK,
			verifyResponse: func(t *testing.T, user *api.User) {
				t.Helper()
				assert.NotEmpty(t, user.Id)
				assert.Equal(t, "admin", user.Role)
				assert.NotNil(t, user.IsServiceUser)
				assert.Equal(t, true, *user.IsServiceUser)
			},
		},
		{
			name: "Create service user with user role",
			requestBody: &api.UserCreateRequest{
				Role:          "user",
				IsServiceUser: true,
				AutoGroups:    []string{testing_tools.TestGroupId},
			},
			expectedStatus: http.StatusOK,
			verifyResponse: func(t *testing.T, user *api.User) {
				t.Helper()
				assert.NotEmpty(t, user.Id)
				assert.Equal(t, "user", user.Role)
			},
		},
		{
			name: "Create service user with empty auto_groups",
			requestBody: &api.UserCreateRequest{
				Role:          "admin",
				IsServiceUser: true,
				AutoGroups:    []string{},
			},
			expectedStatus: http.StatusOK,
			verifyResponse: func(t *testing.T, user *api.User) {
				t.Helper()
				assert.NotEmpty(t, user.Id)
			},
		},
	}

	for _, tc := range tt {
		for _, user := range users {
			t.Run(user.name+" - "+tc.name, func(t *testing.T) {
				apiHandler, am, done := channel.BuildApiBlackBoxWithDBState(t, "../testdata/users_integration.sql", nil, true)

				body, err := json.Marshal(tc.requestBody)
				if err != nil {
					t.Fatalf("Failed to marshal request body: %v", err)
				}

				req := testing_tools.BuildRequest(t, body, http.MethodPost, "/api/users", user.userId)
				recorder := httptest.NewRecorder()
				apiHandler.ServeHTTP(recorder, req)

				content, expectResponse := testing_tools.ReadResponse(t, recorder, tc.expectedStatus, user.expectResponse)
				if !expectResponse {
					return
				}

				if tc.verifyResponse != nil {
					got := &api.User{}
					if err := json.Unmarshal(content, got); err != nil {
						t.Fatalf("Sent content is not in correct json format; %v", err)
					}
					tc.verifyResponse(t, got)

					// Verify user in DB
					db := testing_tools.GetDB(t, am.GetStore())
					dbUser := testing_tools.VerifyUserInDB(t, db, got.Id)
					assert.True(t, dbUser.IsServiceUser)
					assert.Equal(t, string(dbUser.Role), string(tc.requestBody.Role))
				}

				select {
				case <-done:
				case <-time.After(time.Second):
					t.Error("timeout waiting for peerShouldNotReceiveUpdate")
				}
			})
		}
	}
}

func Test_Users_Update(t *testing.T) {
	users := []struct {
		name           string
		userId         string
		expectResponse bool
	}{
		{"Regular user", testing_tools.TestUserId, false},
		{"Admin user", testing_tools.TestAdminId, true},
		{"Owner user", testing_tools.TestOwnerId, true},
		{"Regular service user", testing_tools.TestServiceUserId, false},
		{"Admin service user", testing_tools.TestServiceAdminId, true},
		{"Blocked user", testing_tools.BlockedUserId, false},
		{"Other user", testing_tools.OtherUserId, false},
		{"Invalid token", testing_tools.InvalidToken, false},
	}

	tt := []struct {
		name           string
		targetUserId   string
		requestBody    *api.UserRequest
		expectedStatus int
		verifyResponse func(t *testing.T, user *api.User)
	}{
		{
			name:         "Update user role to admin",
			targetUserId: testing_tools.TestUserId,
			requestBody: &api.UserRequest{
				Role:       "admin",
				AutoGroups: []string{},
				IsBlocked:  false,
			},
			expectedStatus: http.StatusOK,
			verifyResponse: func(t *testing.T, user *api.User) {
				t.Helper()
				assert.Equal(t, "admin", user.Role)
			},
		},
		{
			name:         "Update user auto_groups",
			targetUserId: testing_tools.TestUserId,
			requestBody: &api.UserRequest{
				Role:       "user",
				AutoGroups: []string{testing_tools.TestGroupId},
				IsBlocked:  false,
			},
			expectedStatus: http.StatusOK,
			verifyResponse: func(t *testing.T, user *api.User) {
				t.Helper()
				assert.Equal(t, 1, len(user.AutoGroups))
			},
		},
		{
			name:         "Block user",
			targetUserId: testing_tools.TestUserId,
			requestBody: &api.UserRequest{
				Role:       "user",
				AutoGroups: []string{},
				IsBlocked:  true,
			},
			expectedStatus: http.StatusOK,
			verifyResponse: func(t *testing.T, user *api.User) {
				t.Helper()
				assert.Equal(t, true, user.IsBlocked)
			},
		},
		{
			name:         "Update non-existing user",
			targetUserId: "nonExistingUserId",
			requestBody: &api.UserRequest{
				Role:       "user",
				AutoGroups: []string{},
				IsBlocked:  false,
			},
			expectedStatus: http.StatusNotFound,
		},
	}

	for _, tc := range tt {
		for _, user := range users {
			t.Run(user.name+" - "+tc.name, func(t *testing.T) {
				apiHandler, am, _ := channel.BuildApiBlackBoxWithDBState(t, "../testdata/users_integration.sql", nil, false)

				body, err := json.Marshal(tc.requestBody)
				if err != nil {
					t.Fatalf("Failed to marshal request body: %v", err)
				}

				req := testing_tools.BuildRequest(t, body, http.MethodPut, strings.Replace("/api/users/{userId}", "{userId}", tc.targetUserId, 1), user.userId)
				recorder := httptest.NewRecorder()
				apiHandler.ServeHTTP(recorder, req)

				content, expectResponse := testing_tools.ReadResponse(t, recorder, tc.expectedStatus, user.expectResponse)
				if !expectResponse {
					return
				}

				if tc.verifyResponse != nil {
					got := &api.User{}
					if err := json.Unmarshal(content, got); err != nil {
						t.Fatalf("Sent content is not in correct json format; %v", err)
					}
					tc.verifyResponse(t, got)

					// Verify updated fields in DB
					if tc.expectedStatus == http.StatusOK {
						db := testing_tools.GetDB(t, am.GetStore())
						dbUser := testing_tools.VerifyUserInDB(t, db, tc.targetUserId)
						assert.Equal(t, string(dbUser.Role), string(tc.requestBody.Role))
						assert.Equal(t, dbUser.Blocked, tc.requestBody.IsBlocked)
						assert.ElementsMatch(t, dbUser.AutoGroups, tc.requestBody.AutoGroups)
					}
				}
			})
		}
	}
}

func Test_Users_Delete(t *testing.T) {
	users := []struct {
		name           string
		userId         string
		expectResponse bool
	}{
		{"Regular user", testing_tools.TestUserId, false},
		{"Admin user", testing_tools.TestAdminId, true},
		{"Owner user", testing_tools.TestOwnerId, true},
		{"Regular service user", testing_tools.TestServiceUserId, false},
		{"Admin service user", testing_tools.TestServiceAdminId, true},
		{"Blocked user", testing_tools.BlockedUserId, false},
		{"Other user", testing_tools.OtherUserId, false},
		{"Invalid token", testing_tools.InvalidToken, false},
	}

	tt := []struct {
		name           string
		targetUserId   string
		expectedStatus int
	}{
		{
			name:           "Delete existing service user",
			targetUserId:   "deletableServiceUserId",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "Delete non-existing user",
			targetUserId:   "nonExistingUserId",
			expectedStatus: http.StatusNotFound,
		},
	}

	for _, tc := range tt {
		for _, user := range users {
			t.Run(user.name+" - "+tc.name, func(t *testing.T) {
				apiHandler, am, done := channel.BuildApiBlackBoxWithDBState(t, "../testdata/users_integration.sql", nil, true)

				req := testing_tools.BuildRequest(t, []byte{}, http.MethodDelete, strings.Replace("/api/users/{userId}", "{userId}", tc.targetUserId, 1), user.userId)
				recorder := httptest.NewRecorder()
				apiHandler.ServeHTTP(recorder, req)

				_, expectResponse := testing_tools.ReadResponse(t, recorder, tc.expectedStatus, user.expectResponse)

				// Verify user deleted from DB for successful deletes
				if expectResponse && tc.expectedStatus == http.StatusOK {
					db := testing_tools.GetDB(t, am.GetStore())
					testing_tools.VerifyUserNotInDB(t, db, tc.targetUserId)
				}

				select {
				case <-done:
				case <-time.After(time.Second):
					t.Error("timeout waiting for peerShouldNotReceiveUpdate")
				}
			})
		}
	}
}

func Test_PATs_GetAll(t *testing.T) {
	users := []struct {
		name           string
		userId         string
		expectResponse bool
	}{
		{"Regular user", testing_tools.TestUserId, false},
		{"Admin user", testing_tools.TestAdminId, true},
		{"Owner user", testing_tools.TestOwnerId, true},
		{"Regular service user", testing_tools.TestServiceUserId, false},
		{"Admin service user", testing_tools.TestServiceAdminId, true},
		{"Blocked user", testing_tools.BlockedUserId, false},
		{"Other user", testing_tools.OtherUserId, false},
		{"Invalid token", testing_tools.InvalidToken, false},
	}

	for _, user := range users {
		t.Run(user.name+" - Get all PATs for service user", func(t *testing.T) {
			apiHandler, _, done := channel.BuildApiBlackBoxWithDBState(t, "../testdata/users_integration.sql", nil, true)

			req := testing_tools.BuildRequest(t, []byte{}, http.MethodGet, strings.Replace("/api/users/{userId}/tokens", "{userId}", testing_tools.TestServiceUserId, 1), user.userId)
			recorder := httptest.NewRecorder()
			apiHandler.ServeHTTP(recorder, req)

			content, expectResponse := testing_tools.ReadResponse(t, recorder, http.StatusOK, user.expectResponse)
			if !expectResponse {
				return
			}

			got := []api.PersonalAccessToken{}
			if err := json.Unmarshal(content, &got); err != nil {
				t.Fatalf("Sent content is not in correct json format; %v", err)
			}

			assert.Equal(t, 1, len(got))
			assert.Equal(t, "serviceToken", got[0].Name)

			select {
			case <-done:
			case <-time.After(time.Second):
				t.Error("timeout waiting for peerShouldNotReceiveUpdate")
			}
		})
	}
}

func Test_PATs_GetById(t *testing.T) {
	users := []struct {
		name           string
		userId         string
		expectResponse bool
	}{
		{"Regular user", testing_tools.TestUserId, false},
		{"Admin user", testing_tools.TestAdminId, true},
		{"Owner user", testing_tools.TestOwnerId, true},
		{"Regular service user", testing_tools.TestServiceUserId, false},
		{"Admin service user", testing_tools.TestServiceAdminId, true},
		{"Blocked user", testing_tools.BlockedUserId, false},
		{"Other user", testing_tools.OtherUserId, false},
		{"Invalid token", testing_tools.InvalidToken, false},
	}

	tt := []struct {
		name           string
		tokenId        string
		expectedStatus int
		expectToken    bool
	}{
		{
			name:           "Get existing PAT",
			tokenId:        "serviceTokenId",
			expectedStatus: http.StatusOK,
			expectToken:    true,
		},
		{
			name:           "Get non-existing PAT",
			tokenId:        "nonExistingTokenId",
			expectedStatus: http.StatusNotFound,
			expectToken:    false,
		},
	}

	for _, tc := range tt {
		for _, user := range users {
			t.Run(user.name+" - "+tc.name, func(t *testing.T) {
				apiHandler, _, done := channel.BuildApiBlackBoxWithDBState(t, "../testdata/users_integration.sql", nil, true)

				path := strings.Replace("/api/users/{userId}/tokens/{tokenId}", "{userId}", testing_tools.TestServiceUserId, 1)
				path = strings.Replace(path, "{tokenId}", tc.tokenId, 1)

				req := testing_tools.BuildRequest(t, []byte{}, http.MethodGet, path, user.userId)
				recorder := httptest.NewRecorder()
				apiHandler.ServeHTTP(recorder, req)

				content, expectResponse := testing_tools.ReadResponse(t, recorder, tc.expectedStatus, user.expectResponse)
				if !expectResponse {
					return
				}

				if tc.expectToken {
					got := &api.PersonalAccessToken{}
					if err := json.Unmarshal(content, got); err != nil {
						t.Fatalf("Sent content is not in correct json format; %v", err)
					}
					assert.Equal(t, "serviceTokenId", got.Id)
					assert.Equal(t, "serviceToken", got.Name)
				}

				select {
				case <-done:
				case <-time.After(time.Second):
					t.Error("timeout waiting for peerShouldNotReceiveUpdate")
				}
			})
		}
	}
}

func Test_PATs_Create(t *testing.T) {
	users := []struct {
		name           string
		userId         string
		expectResponse bool
	}{
		{"Regular user", testing_tools.TestUserId, false},
		{"Admin user", testing_tools.TestAdminId, true},
		{"Owner user", testing_tools.TestOwnerId, true},
		{"Regular service user", testing_tools.TestServiceUserId, false},
		{"Admin service user", testing_tools.TestServiceAdminId, true},
		{"Blocked user", testing_tools.BlockedUserId, false},
		{"Other user", testing_tools.OtherUserId, false},
		{"Invalid token", testing_tools.InvalidToken, false},
	}

	tt := []struct {
		name           string
		targetUserId   string
		requestBody    *api.PersonalAccessTokenRequest
		expectedStatus int
		verifyResponse func(t *testing.T, pat *api.PersonalAccessTokenGenerated)
	}{
		{
			name:         "Create PAT with 30 day expiry",
			targetUserId: testing_tools.TestServiceUserId,
			requestBody: &api.PersonalAccessTokenRequest{
				Name:      "newPAT",
				ExpiresIn: 30,
			},
			expectedStatus: http.StatusOK,
			verifyResponse: func(t *testing.T, pat *api.PersonalAccessTokenGenerated) {
				t.Helper()
				assert.NotEmpty(t, pat.PlainToken)
				assert.Equal(t, "newPAT", pat.PersonalAccessToken.Name)
			},
		},
		{
			name:         "Create PAT with 365 day expiry",
			targetUserId: testing_tools.TestServiceUserId,
			requestBody: &api.PersonalAccessTokenRequest{
				Name:      "longPAT",
				ExpiresIn: 365,
			},
			expectedStatus: http.StatusOK,
			verifyResponse: func(t *testing.T, pat *api.PersonalAccessTokenGenerated) {
				t.Helper()
				assert.NotEmpty(t, pat.PlainToken)
				assert.Equal(t, "longPAT", pat.PersonalAccessToken.Name)
			},
		},
		{
			name:         "Create PAT with empty name",
			targetUserId: testing_tools.TestServiceUserId,
			requestBody: &api.PersonalAccessTokenRequest{
				Name:      "",
				ExpiresIn: 30,
			},
			expectedStatus: http.StatusUnprocessableEntity,
		},
		{
			name:         "Create PAT with 0 day expiry",
			targetUserId: testing_tools.TestServiceUserId,
			requestBody: &api.PersonalAccessTokenRequest{
				Name:      "zeroPAT",
				ExpiresIn: 0,
			},
			expectedStatus: http.StatusUnprocessableEntity,
		},
		{
			name:         "Create PAT with expiry over 365 days",
			targetUserId: testing_tools.TestServiceUserId,
			requestBody: &api.PersonalAccessTokenRequest{
				Name:      "tooLongPAT",
				ExpiresIn: 400,
			},
			expectedStatus: http.StatusUnprocessableEntity,
		},
	}

	for _, tc := range tt {
		for _, user := range users {
			t.Run(user.name+" - "+tc.name, func(t *testing.T) {
				apiHandler, am, done := channel.BuildApiBlackBoxWithDBState(t, "../testdata/users_integration.sql", nil, true)

				body, err := json.Marshal(tc.requestBody)
				if err != nil {
					t.Fatalf("Failed to marshal request body: %v", err)
				}

				req := testing_tools.BuildRequest(t, body, http.MethodPost, strings.Replace("/api/users/{userId}/tokens", "{userId}", tc.targetUserId, 1), user.userId)
				recorder := httptest.NewRecorder()
				apiHandler.ServeHTTP(recorder, req)

				content, expectResponse := testing_tools.ReadResponse(t, recorder, tc.expectedStatus, user.expectResponse)
				if !expectResponse {
					return
				}

				if tc.verifyResponse != nil {
					got := &api.PersonalAccessTokenGenerated{}
					if err := json.Unmarshal(content, got); err != nil {
						t.Fatalf("Sent content is not in correct json format; %v", err)
					}
					tc.verifyResponse(t, got)

					// Verify PAT in DB
					db := testing_tools.GetDB(t, am.GetStore())
					dbPAT := testing_tools.VerifyPATInDB(t, db, got.PersonalAccessToken.Id)
					assert.Equal(t, tc.requestBody.Name, dbPAT.Name)
				}

				select {
				case <-done:
				case <-time.After(time.Second):
					t.Error("timeout waiting for peerShouldNotReceiveUpdate")
				}
			})
		}
	}
}

func Test_PATs_Delete(t *testing.T) {
	users := []struct {
		name           string
		userId         string
		expectResponse bool
	}{
		{"Regular user", testing_tools.TestUserId, false},
		{"Admin user", testing_tools.TestAdminId, true},
		{"Owner user", testing_tools.TestOwnerId, true},
		{"Regular service user", testing_tools.TestServiceUserId, false},
		{"Admin service user", testing_tools.TestServiceAdminId, true},
		{"Blocked user", testing_tools.BlockedUserId, false},
		{"Other user", testing_tools.OtherUserId, false},
		{"Invalid token", testing_tools.InvalidToken, false},
	}

	tt := []struct {
		name           string
		tokenId        string
		expectedStatus int
	}{
		{
			name:           "Delete existing PAT",
			tokenId:        "serviceTokenId",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "Delete non-existing PAT",
			tokenId:        "nonExistingTokenId",
			expectedStatus: http.StatusNotFound,
		},
	}

	for _, tc := range tt {
		for _, user := range users {
			t.Run(user.name+" - "+tc.name, func(t *testing.T) {
				apiHandler, am, done := channel.BuildApiBlackBoxWithDBState(t, "../testdata/users_integration.sql", nil, true)

				path := strings.Replace("/api/users/{userId}/tokens/{tokenId}", "{userId}", testing_tools.TestServiceUserId, 1)
				path = strings.Replace(path, "{tokenId}", tc.tokenId, 1)

				req := testing_tools.BuildRequest(t, []byte{}, http.MethodDelete, path, user.userId)
				recorder := httptest.NewRecorder()
				apiHandler.ServeHTTP(recorder, req)

				_, expectResponse := testing_tools.ReadResponse(t, recorder, tc.expectedStatus, user.expectResponse)

				// Verify PAT deleted from DB for successful deletes
				if expectResponse && tc.expectedStatus == http.StatusOK {
					db := testing_tools.GetDB(t, am.GetStore())
					testing_tools.VerifyPATNotInDB(t, db, tc.tokenId)
				}

				select {
				case <-done:
				case <-time.After(time.Second):
					t.Error("timeout waiting for peerShouldNotReceiveUpdate")
				}
			})
		}
	}
}
