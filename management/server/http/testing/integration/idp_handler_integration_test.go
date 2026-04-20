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

func Test_IdentityProviders_GetAll(t *testing.T) {
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
		t.Run(user.name+" - Get all identity providers", func(t *testing.T) {
			apiHandler, _, done := channel.BuildApiBlackBoxWithDBState(t, "../testdata/identity_providers.sql", nil, true)

			req := testing_tools.BuildRequest(t, []byte{}, http.MethodGet, "/api/identity-providers", user.userId)
			recorder := httptest.NewRecorder()
			apiHandler.ServeHTTP(recorder, req)

			content, expectResponse := testing_tools.ReadResponse(t, recorder, http.StatusOK, user.expectResponse)
			if !expectResponse {
				return
			}

			got := []api.IdentityProvider{}
			if err := json.Unmarshal(content, &got); err != nil {
				t.Fatalf("Sent content is not in correct json format; %v", err)
			}

			// The embedded IdP manager is not initialized in the test environment,
			// so GetIdentityProviders returns an empty list.
			assert.Equal(t, 0, len(got))

			select {
			case <-done:
			case <-time.After(time.Second):
				t.Error("timeout waiting for peerShouldNotReceiveUpdate")
			}
		})
	}
}

func Test_IdentityProviders_GetById(t *testing.T) {
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
		idpId          string
		expectedStatus int
	}{
		{
			name:           "Get existing identity provider",
			idpId:          "testIdpId",
			expectedStatus: http.StatusInternalServerError,
		},
		{
			name:           "Get non-existing identity provider",
			idpId:          "nonExistingIdpId",
			expectedStatus: http.StatusInternalServerError,
		},
	}

	for _, tc := range tt {
		for _, user := range users {
			t.Run(user.name+" - "+tc.name, func(t *testing.T) {
				apiHandler, _, _ := channel.BuildApiBlackBoxWithDBState(t, "../testdata/identity_providers.sql", nil, false)

				req := testing_tools.BuildRequest(t, []byte{}, http.MethodGet, strings.Replace("/api/identity-providers/{idpId}", "{idpId}", tc.idpId, 1), user.userId)
				recorder := httptest.NewRecorder()
				apiHandler.ServeHTTP(recorder, req)

				testing_tools.ReadResponse(t, recorder, tc.expectedStatus, user.expectResponse)
			})
		}
	}
}

func Test_IdentityProviders_Create(t *testing.T) {
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
		requestBody    *api.PostApiIdentityProvidersJSONRequestBody
		expectedStatus int
	}{
		{
			name: "Create identity provider with valid data",
			requestBody: &api.PostApiIdentityProvidersJSONRequestBody{
				Type:         api.IdentityProviderTypeGoogle,
				Name:         "New IDP",
				ClientId:     "newClientId",
				ClientSecret: "newClientSecret",
			},
			// Validation passes but the embedded IdP manager is not initialized,
			// so the operation returns an internal server error.
			expectedStatus: http.StatusInternalServerError,
		},
		{
			name: "Create identity provider with invalid issuer",
			requestBody: &api.PostApiIdentityProvidersJSONRequestBody{
				Type:         api.IdentityProviderTypeOidc,
				Name:         "Invalid IDP",
				Issuer:       "not-a-url",
				ClientId:     "clientId",
				ClientSecret: "clientSecret",
			},
			expectedStatus: http.StatusUnprocessableEntity,
		},
	}

	for _, tc := range tt {
		for _, user := range users {
			t.Run(user.name+" - "+tc.name, func(t *testing.T) {
				apiHandler, _, _ := channel.BuildApiBlackBoxWithDBState(t, "../testdata/identity_providers.sql", nil, false)

				body, err := json.Marshal(tc.requestBody)
				if err != nil {
					t.Fatalf("Failed to marshal request body: %v", err)
				}

				req := testing_tools.BuildRequest(t, body, http.MethodPost, "/api/identity-providers", user.userId)
				recorder := httptest.NewRecorder()
				apiHandler.ServeHTTP(recorder, req)

				testing_tools.ReadResponse(t, recorder, tc.expectedStatus, user.expectResponse)
			})
		}
	}
}

func Test_IdentityProviders_Update(t *testing.T) {
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
		idpId          string
		requestBody    *api.PutApiIdentityProvidersIdpIdJSONRequestBody
		expectedStatus int
	}{
		{
			name:  "Update existing identity provider",
			idpId: "testIdpId",
			requestBody: &api.PutApiIdentityProvidersIdpIdJSONRequestBody{
				Type:         api.IdentityProviderTypeGoogle,
				Name:         "Updated IDP",
				ClientId:     "updatedClientId",
				ClientSecret: "updatedClientSecret",
			},
			// Validation passes but the embedded IdP manager is not initialized,
			// so the operation returns an internal server error.
			expectedStatus: http.StatusInternalServerError,
		},
		{
			name:  "Update non-existing identity provider",
			idpId: "nonExistingIdpId",
			requestBody: &api.PutApiIdentityProvidersIdpIdJSONRequestBody{
				Type:         api.IdentityProviderTypeGoogle,
				Name:         "Updated IDP",
				ClientId:     "updatedClientId",
				ClientSecret: "updatedClientSecret",
			},
			expectedStatus: http.StatusInternalServerError,
		},
	}

	for _, tc := range tt {
		for _, user := range users {
			t.Run(user.name+" - "+tc.name, func(t *testing.T) {
				apiHandler, _, _ := channel.BuildApiBlackBoxWithDBState(t, "../testdata/identity_providers.sql", nil, false)

				body, err := json.Marshal(tc.requestBody)
				if err != nil {
					t.Fatalf("Failed to marshal request body: %v", err)
				}

				req := testing_tools.BuildRequest(t, body, http.MethodPut, strings.Replace("/api/identity-providers/{idpId}", "{idpId}", tc.idpId, 1), user.userId)
				recorder := httptest.NewRecorder()
				apiHandler.ServeHTTP(recorder, req)

				testing_tools.ReadResponse(t, recorder, tc.expectedStatus, user.expectResponse)
			})
		}
	}
}

func Test_IdentityProviders_Delete(t *testing.T) {
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
		idpId          string
		expectedStatus int
	}{
		{
			name:           "Delete existing identity provider",
			idpId:          "testIdpId",
			expectedStatus: http.StatusInternalServerError,
		},
		{
			name:           "Delete non-existing identity provider",
			idpId:          "nonExistingIdpId",
			expectedStatus: http.StatusInternalServerError,
		},
	}

	for _, tc := range tt {
		for _, user := range users {
			t.Run(user.name+" - "+tc.name, func(t *testing.T) {
				apiHandler, _, _ := channel.BuildApiBlackBoxWithDBState(t, "../testdata/identity_providers.sql", nil, false)

				req := testing_tools.BuildRequest(t, []byte{}, http.MethodDelete, strings.Replace("/api/identity-providers/{idpId}", "{idpId}", tc.idpId, 1), user.userId)
				recorder := httptest.NewRecorder()
				apiHandler.ServeHTTP(recorder, req)

				testing_tools.ReadResponse(t, recorder, tc.expectedStatus, user.expectResponse)
			})
		}
	}
}
