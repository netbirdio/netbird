//go:build integration

package integration

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/netbirdio/netbird/management/server/http/testing/testing_tools"
	"github.com/netbirdio/netbird/management/server/http/testing/testing_tools/channel"
	"github.com/netbirdio/netbird/shared/management/http/api"
)

// Note: The integration test infrastructure does not configure an embedded IDP,
// so actual invite operations will return PreconditionFailed (412) for authorized users.
// These tests verify that the permissions layer correctly denies regular users
// before the handler logic is reached.

func Test_Invites_List(t *testing.T) {
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
		t.Run(user.name+" - List invites", func(t *testing.T) {
			apiHandler, _, _ := channel.BuildApiBlackBoxWithDBState(t, "../testdata/users_integration.sql", nil, false)

			req := testing_tools.BuildRequest(t, []byte{}, http.MethodGet, "/api/users/invites", user.userId)
			recorder := httptest.NewRecorder()
			apiHandler.ServeHTTP(recorder, req)

			// Authorized users get PreconditionFailed (no embedded IDP configured)
			// Unauthorized users get rejected by the permissions middleware
			testing_tools.ReadResponse(t, recorder, http.StatusPreconditionFailed, user.expectResponse)
		})
	}
}

func Test_Invites_Create(t *testing.T) {
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
		t.Run(user.name+" - Create invite", func(t *testing.T) {
			apiHandler, _, _ := channel.BuildApiBlackBoxWithDBState(t, "../testdata/users_integration.sql", nil, false)

			body, err := json.Marshal(&api.UserInviteCreateRequest{
				Email:      "newuser@test.com",
				Name:       "New User",
				Role:       "user",
				AutoGroups: []string{},
			})
			if err != nil {
				t.Fatalf("Failed to marshal request body: %v", err)
			}

			req := testing_tools.BuildRequest(t, body, http.MethodPost, "/api/users/invites", user.userId)
			recorder := httptest.NewRecorder()
			apiHandler.ServeHTTP(recorder, req)

			// Authorized users get PreconditionFailed (no embedded IDP configured)
			// Unauthorized users get rejected by the permissions middleware
			testing_tools.ReadResponse(t, recorder, http.StatusPreconditionFailed, user.expectResponse)
		})
	}
}

func Test_Invites_Delete(t *testing.T) {
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
		t.Run(user.name+" - Delete invite", func(t *testing.T) {
			apiHandler, _, _ := channel.BuildApiBlackBoxWithDBState(t, "../testdata/users_integration.sql", nil, false)

			req := testing_tools.BuildRequest(t, []byte{}, http.MethodDelete, strings.Replace("/api/users/invites/{inviteId}", "{inviteId}", "someInviteId", 1), user.userId)
			recorder := httptest.NewRecorder()
			apiHandler.ServeHTTP(recorder, req)

			// Authorized users get PreconditionFailed (no embedded IDP configured)
			// Unauthorized users get rejected by the permissions middleware
			testing_tools.ReadResponse(t, recorder, http.StatusPreconditionFailed, user.expectResponse)
		})
	}
}

func Test_Invites_Regenerate(t *testing.T) {
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
		t.Run(user.name+" - Regenerate invite", func(t *testing.T) {
			apiHandler, _, _ := channel.BuildApiBlackBoxWithDBState(t, "../testdata/users_integration.sql", nil, false)

			req := testing_tools.BuildRequest(t, []byte{}, http.MethodPost, strings.Replace("/api/users/invites/{inviteId}/regenerate", "{inviteId}", "someInviteId", 1), user.userId)
			recorder := httptest.NewRecorder()
			apiHandler.ServeHTTP(recorder, req)

			// Authorized users get PreconditionFailed (no embedded IDP configured)
			// Unauthorized users get rejected by the permissions middleware
			testing_tools.ReadResponse(t, recorder, http.StatusPreconditionFailed, user.expectResponse)
		})
	}
}
