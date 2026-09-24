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

func Test_PostureChecks_GetAll(t *testing.T) {
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
		t.Run(user.name+" - Get all posture checks", func(t *testing.T) {
			apiHandler, _, done := channel.BuildApiBlackBoxWithDBState(t, "../testdata/posture_checks.sql", nil, true)

			req := testing_tools.BuildRequest(t, []byte{}, http.MethodGet, "/api/posture-checks", user.userId)
			recorder := httptest.NewRecorder()
			apiHandler.ServeHTTP(recorder, req)

			content, expectResponse := testing_tools.ReadResponse(t, recorder, http.StatusOK, user.expectResponse)
			if !expectResponse {
				return
			}

			got := []*api.PostureCheck{}
			if err := json.Unmarshal(content, &got); err != nil {
				t.Fatalf("Sent content is not in correct json format; %v", err)
			}

			assert.Equal(t, 1, len(got))
			assert.Equal(t, "testPostureCheckId", got[0].Id)
			assert.Equal(t, "NetBird Version Check", got[0].Name)

			select {
			case <-done:
			case <-time.After(time.Second):
				t.Error("timeout waiting for peerShouldNotReceiveUpdate")
			}
		})
	}
}

func Test_PostureChecks_GetById(t *testing.T) {
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
		postureCheckId string
		expectedStatus int
		expectCheck    bool
	}{
		{
			name:           "Get existing posture check",
			postureCheckId: "testPostureCheckId",
			expectedStatus: http.StatusOK,
			expectCheck:    true,
		},
		{
			name:           "Get non-existing posture check",
			postureCheckId: "nonExistingPostureCheckId",
			expectedStatus: http.StatusNotFound,
			expectCheck:    false,
		},
	}

	for _, tc := range tt {
		for _, user := range users {
			t.Run(user.name+" - "+tc.name, func(t *testing.T) {
				apiHandler, _, done := channel.BuildApiBlackBoxWithDBState(t, "../testdata/posture_checks.sql", nil, true)

				req := testing_tools.BuildRequest(t, []byte{}, http.MethodGet, strings.Replace("/api/posture-checks/{postureCheckId}", "{postureCheckId}", tc.postureCheckId, 1), user.userId)
				recorder := httptest.NewRecorder()
				apiHandler.ServeHTTP(recorder, req)

				content, expectResponse := testing_tools.ReadResponse(t, recorder, tc.expectedStatus, user.expectResponse)
				if !expectResponse {
					return
				}

				if tc.expectCheck {
					got := &api.PostureCheck{}
					if err := json.Unmarshal(content, got); err != nil {
						t.Fatalf("Sent content is not in correct json format; %v", err)
					}
					assert.Equal(t, "testPostureCheckId", got.Id)
					assert.Equal(t, "NetBird Version Check", got.Name)
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

func Test_PostureChecks_Create(t *testing.T) {
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

	minVersion := "0.32.0"
	tt := []struct {
		name           string
		requestBody    *api.PostureCheckUpdate
		expectedStatus int
		verifyResponse func(t *testing.T, check *api.PostureCheck)
	}{
		{
			name: "Create posture check with NB version",
			requestBody: &api.PostureCheckUpdate{
				Name:        "New Version Check",
				Description: "check for new version",
				Checks: &api.Checks{
					NbVersionCheck: &api.NBVersionCheck{
						MinVersion: minVersion,
					},
				},
			},
			expectedStatus: http.StatusOK,
			verifyResponse: func(t *testing.T, check *api.PostureCheck) {
				t.Helper()
				assert.NotEmpty(t, check.Id)
				assert.Equal(t, "New Version Check", check.Name)
				assert.NotNil(t, check.Checks.NbVersionCheck)
				assert.Equal(t, minVersion, check.Checks.NbVersionCheck.MinVersion)
			},
		},
		{
			name: "Create posture check with empty name",
			requestBody: &api.PostureCheckUpdate{
				Name: "",
				Checks: &api.Checks{
					NbVersionCheck: &api.NBVersionCheck{
						MinVersion: "0.32.0",
					},
				},
			},
			expectedStatus: http.StatusUnprocessableEntity,
		},
	}

	for _, tc := range tt {
		for _, user := range users {
			t.Run(user.name+" - "+tc.name, func(t *testing.T) {
				apiHandler, am, _ := channel.BuildApiBlackBoxWithDBState(t, "../testdata/posture_checks.sql", nil, false)

				body, err := json.Marshal(tc.requestBody)
				if err != nil {
					t.Fatalf("Failed to marshal request body: %v", err)
				}

				req := testing_tools.BuildRequest(t, body, http.MethodPost, "/api/posture-checks", user.userId)
				recorder := httptest.NewRecorder()
				apiHandler.ServeHTTP(recorder, req)

				content, expectResponse := testing_tools.ReadResponse(t, recorder, tc.expectedStatus, user.expectResponse)
				if !expectResponse {
					return
				}

				if tc.verifyResponse != nil {
					got := &api.PostureCheck{}
					if err := json.Unmarshal(content, got); err != nil {
						t.Fatalf("Sent content is not in correct json format; %v", err)
					}
					tc.verifyResponse(t, got)

					db := testing_tools.GetDB(t, am.GetStore())
					dbCheck := testing_tools.VerifyPostureCheckInDB(t, db, got.Id)
					assert.Equal(t, got.Name, dbCheck.Name)
				}
			})
		}
	}
}

func Test_PostureChecks_Update(t *testing.T) {
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

	minVersion := "0.33.0"
	tt := []struct {
		name           string
		postureCheckId string
		requestBody    *api.PostureCheckUpdate
		expectedStatus int
		verifyResponse func(t *testing.T, check *api.PostureCheck)
	}{
		{
			name:           "Update posture check name and version",
			postureCheckId: "testPostureCheckId",
			requestBody: &api.PostureCheckUpdate{
				Name:        "Updated Version Check",
				Description: "updated description",
				Checks: &api.Checks{
					NbVersionCheck: &api.NBVersionCheck{
						MinVersion: minVersion,
					},
				},
			},
			expectedStatus: http.StatusOK,
			verifyResponse: func(t *testing.T, check *api.PostureCheck) {
				t.Helper()
				assert.Equal(t, "testPostureCheckId", check.Id)
				assert.Equal(t, "Updated Version Check", check.Name)
			},
		},
		{
			name:           "Update non-existing posture check",
			postureCheckId: "nonExistingPostureCheckId",
			requestBody: &api.PostureCheckUpdate{
				Name: "whatever",
				Checks: &api.Checks{
					NbVersionCheck: &api.NBVersionCheck{
						MinVersion: "0.33.0",
					},
				},
			},
			expectedStatus: http.StatusNotFound,
		},
	}

	for _, tc := range tt {
		for _, user := range users {
			t.Run(user.name+" - "+tc.name, func(t *testing.T) {
				apiHandler, am, _ := channel.BuildApiBlackBoxWithDBState(t, "../testdata/posture_checks.sql", nil, false)

				body, err := json.Marshal(tc.requestBody)
				if err != nil {
					t.Fatalf("Failed to marshal request body: %v", err)
				}

				req := testing_tools.BuildRequest(t, body, http.MethodPut, strings.Replace("/api/posture-checks/{postureCheckId}", "{postureCheckId}", tc.postureCheckId, 1), user.userId)
				recorder := httptest.NewRecorder()
				apiHandler.ServeHTTP(recorder, req)

				content, expectResponse := testing_tools.ReadResponse(t, recorder, tc.expectedStatus, user.expectResponse)
				if !expectResponse {
					return
				}

				if tc.verifyResponse != nil {
					got := &api.PostureCheck{}
					if err := json.Unmarshal(content, got); err != nil {
						t.Fatalf("Sent content is not in correct json format; %v", err)
					}
					tc.verifyResponse(t, got)

					db := testing_tools.GetDB(t, am.GetStore())
					dbCheck := testing_tools.VerifyPostureCheckInDB(t, db, tc.postureCheckId)
					assert.Equal(t, "Updated Version Check", dbCheck.Name)
				}
			})
		}
	}
}

func Test_PostureChecks_Delete(t *testing.T) {
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
		postureCheckId string
		expectedStatus int
	}{
		{
			name:           "Delete existing posture check",
			postureCheckId: "testPostureCheckId",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "Delete non-existing posture check",
			postureCheckId: "nonExistingPostureCheckId",
			expectedStatus: http.StatusNotFound,
		},
	}

	for _, tc := range tt {
		for _, user := range users {
			t.Run(user.name+" - "+tc.name, func(t *testing.T) {
				apiHandler, am, _ := channel.BuildApiBlackBoxWithDBState(t, "../testdata/posture_checks.sql", nil, false)

				req := testing_tools.BuildRequest(t, []byte{}, http.MethodDelete, strings.Replace("/api/posture-checks/{postureCheckId}", "{postureCheckId}", tc.postureCheckId, 1), user.userId)
				recorder := httptest.NewRecorder()
				apiHandler.ServeHTTP(recorder, req)

				testing_tools.ReadResponse(t, recorder, tc.expectedStatus, user.expectResponse)

				if tc.expectedStatus == http.StatusOK && user.expectResponse {
					db := testing_tools.GetDB(t, am.GetStore())
					testing_tools.VerifyPostureCheckNotInDB(t, db, tc.postureCheckId)
				}
			})
		}
	}
}
