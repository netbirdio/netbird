//go:build integration

package integration

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/netbirdio/netbird/management/server/http/testing/testing_tools"
	"github.com/netbirdio/netbird/management/server/http/testing/testing_tools/channel"
)

func Test_Users_Approve(t *testing.T) {
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
			name:           "Approve pending user",
			targetUserId:   "pendingUserId",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "Approve non-existing user",
			targetUserId:   "nonExistingUserId",
			expectedStatus: http.StatusNotFound,
		},
		{
			name:           "Approve already active user",
			targetUserId:   testing_tools.TestUserId,
			expectedStatus: http.StatusUnprocessableEntity,
		},
	}

	for _, tc := range tt {
		for _, user := range users {
			t.Run(user.name+" - "+tc.name, func(t *testing.T) {
				apiHandler, _, _ := channel.BuildApiBlackBoxWithDBState(t, "../testdata/users_approve_reject.sql", nil, false)

				req := testing_tools.BuildRequest(t, []byte{}, http.MethodPost, strings.Replace("/api/users/{userId}/approve", "{userId}", tc.targetUserId, 1), user.userId)
				recorder := httptest.NewRecorder()
				apiHandler.ServeHTTP(recorder, req)

				testing_tools.ReadResponse(t, recorder, tc.expectedStatus, user.expectResponse)
			})
		}
	}
}

func Test_Users_Reject(t *testing.T) {
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
			name:           "Reject pending user",
			targetUserId:   "pendingUserId",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "Reject non-existing user",
			targetUserId:   "nonExistingUserId",
			expectedStatus: http.StatusNotFound,
		},
		{
			name:           "Reject non-pending user",
			targetUserId:   testing_tools.TestUserId,
			expectedStatus: http.StatusUnprocessableEntity,
		},
	}

	for _, tc := range tt {
		for _, user := range users {
			t.Run(user.name+" - "+tc.name, func(t *testing.T) {
				apiHandler, am, _ := channel.BuildApiBlackBoxWithDBState(t, "../testdata/users_approve_reject.sql", nil, false)

				req := testing_tools.BuildRequest(t, []byte{}, http.MethodDelete, strings.Replace("/api/users/{userId}/reject", "{userId}", tc.targetUserId, 1), user.userId)
				recorder := httptest.NewRecorder()
				apiHandler.ServeHTTP(recorder, req)

				_, expectResponse := testing_tools.ReadResponse(t, recorder, tc.expectedStatus, user.expectResponse)

				if expectResponse && tc.expectedStatus == http.StatusOK {
					db := testing_tools.GetDB(t, am.GetStore())
					testing_tools.VerifyUserNotInDB(t, db, tc.targetUserId)
				}
			})
		}
	}
}
