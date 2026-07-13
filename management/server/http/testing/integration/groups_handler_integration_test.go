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

func Test_Groups_GetAll(t *testing.T) {
	users := []struct {
		name           string
		userId         string
		expectResponse bool
	}{
		{"Regular user", testing_tools.TestUserId, false},
		{"Admin user", testing_tools.TestAdminId, true},
		{"Owner user", testing_tools.TestOwnerId, true},
		{"Regular service user", testing_tools.TestServiceUserId, true},
		{"Admin service user", testing_tools.TestServiceAdminId, true},
		{"Blocked user", testing_tools.BlockedUserId, false},
		{"Other user", testing_tools.OtherUserId, false},
		{"Invalid token", testing_tools.InvalidToken, false},
	}

	for _, user := range users {
		t.Run(user.name+" - Get all groups", func(t *testing.T) {
			apiHandler, _, done := channel.BuildApiBlackBoxWithDBState(t, "../testdata/groups.sql", nil, true)

			req := testing_tools.BuildRequest(t, []byte{}, http.MethodGet, "/api/groups", user.userId)
			recorder := httptest.NewRecorder()
			apiHandler.ServeHTTP(recorder, req)

			content, expectResponse := testing_tools.ReadResponse(t, recorder, http.StatusOK, user.expectResponse)
			if !expectResponse {
				return
			}

			got := []api.Group{}
			if err := json.Unmarshal(content, &got); err != nil {
				t.Fatalf("Sent content is not in correct json format; %v", err)
			}

			assert.GreaterOrEqual(t, len(got), 2)

			select {
			case <-done:
			case <-time.After(time.Second):
				t.Error("timeout waiting for peerShouldNotReceiveUpdate")
			}
		})
	}
}

func Test_Groups_GetById(t *testing.T) {
	users := []struct {
		name           string
		userId         string
		expectResponse bool
	}{
		{"Regular user", testing_tools.TestUserId, false},
		{"Admin user", testing_tools.TestAdminId, true},
		{"Owner user", testing_tools.TestOwnerId, true},
		{"Regular service user", testing_tools.TestServiceUserId, true},
		{"Admin service user", testing_tools.TestServiceAdminId, true},
		{"Blocked user", testing_tools.BlockedUserId, false},
		{"Other user", testing_tools.OtherUserId, false},
		{"Invalid token", testing_tools.InvalidToken, false},
	}

	tt := []struct {
		name           string
		groupId        string
		expectedStatus int
		expectGroup    bool
	}{
		{
			name:           "Get existing group",
			groupId:        testing_tools.TestGroupId,
			expectedStatus: http.StatusOK,
			expectGroup:    true,
		},
		{
			name:           "Get non-existing group",
			groupId:        "nonExistingGroupId",
			expectedStatus: http.StatusNotFound,
			expectGroup:    false,
		},
	}

	for _, tc := range tt {
		for _, user := range users {
			t.Run(user.name+" - "+tc.name, func(t *testing.T) {
				apiHandler, _, done := channel.BuildApiBlackBoxWithDBState(t, "../testdata/groups.sql", nil, true)

				req := testing_tools.BuildRequest(t, []byte{}, http.MethodGet, strings.Replace("/api/groups/{groupId}", "{groupId}", tc.groupId, 1), user.userId)
				recorder := httptest.NewRecorder()
				apiHandler.ServeHTTP(recorder, req)

				content, expectResponse := testing_tools.ReadResponse(t, recorder, tc.expectedStatus, user.expectResponse)
				if !expectResponse {
					return
				}

				if tc.expectGroup {
					got := &api.Group{}
					if err := json.Unmarshal(content, got); err != nil {
						t.Fatalf("Sent content is not in correct json format; %v", err)
					}
					assert.Equal(t, tc.groupId, got.Id)
					assert.Equal(t, "testGroupName", got.Name)
					assert.Equal(t, 1, got.PeersCount)
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

func Test_Groups_Create(t *testing.T) {
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
		requestBody    *api.GroupRequest
		expectedStatus int
		verifyResponse func(t *testing.T, group *api.Group)
	}{
		{
			name: "Create group with valid name",
			requestBody: &api.GroupRequest{
				Name: "brandNewGroup",
			},
			expectedStatus: http.StatusOK,
			verifyResponse: func(t *testing.T, group *api.Group) {
				t.Helper()
				assert.NotEmpty(t, group.Id)
				assert.Equal(t, "brandNewGroup", group.Name)
				assert.Equal(t, 0, group.PeersCount)
			},
		},
		{
			name: "Create group with peers",
			requestBody: &api.GroupRequest{
				Name:  "groupWithPeers",
				Peers: &[]string{testing_tools.TestPeerId},
			},
			expectedStatus: http.StatusOK,
			verifyResponse: func(t *testing.T, group *api.Group) {
				t.Helper()
				assert.NotEmpty(t, group.Id)
				assert.Equal(t, "groupWithPeers", group.Name)
				assert.Equal(t, 1, group.PeersCount)
			},
		},
		{
			name: "Create group with empty name",
			requestBody: &api.GroupRequest{
				Name: "",
			},
			expectedStatus: http.StatusUnprocessableEntity,
		},
	}

	for _, tc := range tt {
		for _, user := range users {
			t.Run(user.name+" - "+tc.name, func(t *testing.T) {
				apiHandler, am, _ := channel.BuildApiBlackBoxWithDBState(t, "../testdata/groups.sql", nil, false)

				body, err := json.Marshal(tc.requestBody)
				if err != nil {
					t.Fatalf("Failed to marshal request body: %v", err)
				}

				req := testing_tools.BuildRequest(t, body, http.MethodPost, "/api/groups", user.userId)
				recorder := httptest.NewRecorder()
				apiHandler.ServeHTTP(recorder, req)

				content, expectResponse := testing_tools.ReadResponse(t, recorder, tc.expectedStatus, user.expectResponse)
				if !expectResponse {
					return
				}

				if tc.verifyResponse != nil {
					got := &api.Group{}
					if err := json.Unmarshal(content, got); err != nil {
						t.Fatalf("Sent content is not in correct json format; %v", err)
					}
					tc.verifyResponse(t, got)

					// Verify group exists in DB
					db := testing_tools.GetDB(t, am.GetStore())
					dbGroup := testing_tools.VerifyGroupInDB(t, db, got.Id)
					assert.Equal(t, tc.requestBody.Name, dbGroup.Name)
				}
			})
		}
	}
}

func Test_Groups_Update(t *testing.T) {
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
		groupId        string
		requestBody    *api.GroupRequest
		expectedStatus int
		verifyResponse func(t *testing.T, group *api.Group)
	}{
		{
			name:    "Update group name",
			groupId: testing_tools.TestGroupId,
			requestBody: &api.GroupRequest{
				Name: "updatedGroupName",
			},
			expectedStatus: http.StatusOK,
			verifyResponse: func(t *testing.T, group *api.Group) {
				t.Helper()
				assert.Equal(t, testing_tools.TestGroupId, group.Id)
				assert.Equal(t, "updatedGroupName", group.Name)
			},
		},
		{
			name:    "Update group peers",
			groupId: testing_tools.TestGroupId,
			requestBody: &api.GroupRequest{
				Name:  "testGroupName",
				Peers: &[]string{},
			},
			expectedStatus: http.StatusOK,
			verifyResponse: func(t *testing.T, group *api.Group) {
				t.Helper()
				assert.Equal(t, 0, group.PeersCount)
			},
		},
		{
			name:    "Update with empty name",
			groupId: testing_tools.TestGroupId,
			requestBody: &api.GroupRequest{
				Name: "",
			},
			expectedStatus: http.StatusUnprocessableEntity,
		},
		{
			name:    "Update non-existing group",
			groupId: "nonExistingGroupId",
			requestBody: &api.GroupRequest{
				Name: "someName",
			},
			expectedStatus: http.StatusNotFound,
		},
	}

	for _, tc := range tt {
		for _, user := range users {
			t.Run(user.name+" - "+tc.name, func(t *testing.T) {
				apiHandler, am, _ := channel.BuildApiBlackBoxWithDBState(t, "../testdata/groups.sql", nil, false)

				body, err := json.Marshal(tc.requestBody)
				if err != nil {
					t.Fatalf("Failed to marshal request body: %v", err)
				}

				req := testing_tools.BuildRequest(t, body, http.MethodPut, strings.Replace("/api/groups/{groupId}", "{groupId}", tc.groupId, 1), user.userId)
				recorder := httptest.NewRecorder()
				apiHandler.ServeHTTP(recorder, req)

				content, expectResponse := testing_tools.ReadResponse(t, recorder, tc.expectedStatus, user.expectResponse)
				if !expectResponse {
					return
				}

				if tc.verifyResponse != nil {
					got := &api.Group{}
					if err := json.Unmarshal(content, got); err != nil {
						t.Fatalf("Sent content is not in correct json format; %v", err)
					}
					tc.verifyResponse(t, got)

					// Verify updated group in DB
					db := testing_tools.GetDB(t, am.GetStore())
					dbGroup := testing_tools.VerifyGroupInDB(t, db, tc.groupId)
					assert.Equal(t, tc.requestBody.Name, dbGroup.Name)
				}
			})
		}
	}
}

func Test_Groups_Delete(t *testing.T) {
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
		groupId        string
		expectedStatus int
	}{
		{
			name:           "Delete existing group not in use",
			groupId:        testing_tools.NewGroupId,
			expectedStatus: http.StatusOK,
		},
		{
			name:           "Delete non-existing group",
			groupId:        "nonExistingGroupId",
			expectedStatus: http.StatusBadRequest,
		},
	}

	for _, tc := range tt {
		for _, user := range users {
			t.Run(user.name+" - "+tc.name, func(t *testing.T) {
				apiHandler, am, _ := channel.BuildApiBlackBoxWithDBState(t, "../testdata/groups.sql", nil, false)

				req := testing_tools.BuildRequest(t, []byte{}, http.MethodDelete, strings.Replace("/api/groups/{groupId}", "{groupId}", tc.groupId, 1), user.userId)
				recorder := httptest.NewRecorder()
				apiHandler.ServeHTTP(recorder, req)

				_, expectResponse := testing_tools.ReadResponse(t, recorder, tc.expectedStatus, user.expectResponse)
				if expectResponse && tc.expectedStatus == http.StatusOK {
					db := testing_tools.GetDB(t, am.GetStore())
					testing_tools.VerifyGroupNotInDB(t, db, tc.groupId)
				}
			})
		}
	}
}
