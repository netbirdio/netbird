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
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/http/api"
)

func Test_Accounts_GetAll(t *testing.T) {
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
		t.Run(user.name+" - Get all accounts", func(t *testing.T) {
			apiHandler, _, done := channel.BuildApiBlackBoxWithDBState(t, "../testdata/accounts.sql", nil, true)

			req := testing_tools.BuildRequest(t, []byte{}, http.MethodGet, "/api/accounts", user.userId)
			recorder := httptest.NewRecorder()
			apiHandler.ServeHTTP(recorder, req)

			content, expectResponse := testing_tools.ReadResponse(t, recorder, http.StatusOK, user.expectResponse)
			if !expectResponse {
				return
			}

			got := []api.Account{}
			if err := json.Unmarshal(content, &got); err != nil {
				t.Fatalf("Sent content is not in correct json format; %v", err)
			}

			assert.Equal(t, 1, len(got))
			account := got[0]
			assert.Equal(t, "test.com", account.Domain)
			assert.Equal(t, "private", account.DomainCategory)
			assert.Equal(t, true, account.Settings.PeerLoginExpirationEnabled)
			assert.Equal(t, 86400, account.Settings.PeerLoginExpiration)
			assert.Equal(t, false, account.Settings.RegularUsersViewBlocked)

			select {
			case <-done:
			case <-time.After(time.Second):
				t.Error("timeout waiting for peerShouldNotReceiveUpdate")
			}
		})
	}
}

func Test_Accounts_Update(t *testing.T) {
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

	trueVal := true
	falseVal := false

	tt := []struct {
		name           string
		expectedStatus int
		requestBody    *api.AccountRequest
		verifyResponse func(t *testing.T, account *api.Account)
		verifyDB       func(t *testing.T, account *types.Account)
	}{
		{
			name: "Disable peer login expiration",
			requestBody: &api.AccountRequest{
				Settings: api.AccountSettings{
					PeerLoginExpirationEnabled: false,
					PeerLoginExpiration:        86400,
				},
			},
			expectedStatus: http.StatusOK,
			verifyResponse: func(t *testing.T, account *api.Account) {
				t.Helper()
				assert.Equal(t, false, account.Settings.PeerLoginExpirationEnabled)
			},
			verifyDB: func(t *testing.T, dbAccount *types.Account) {
				t.Helper()
				assert.Equal(t, false, dbAccount.Settings.PeerLoginExpirationEnabled)
			},
		},
		{
			name: "Update peer login expiration to 48h",
			requestBody: &api.AccountRequest{
				Settings: api.AccountSettings{
					PeerLoginExpirationEnabled: true,
					PeerLoginExpiration:        172800,
				},
			},
			expectedStatus: http.StatusOK,
			verifyResponse: func(t *testing.T, account *api.Account) {
				t.Helper()
				assert.Equal(t, 172800, account.Settings.PeerLoginExpiration)
			},
			verifyDB: func(t *testing.T, dbAccount *types.Account) {
				t.Helper()
				assert.Equal(t, 172800*time.Second, dbAccount.Settings.PeerLoginExpiration)
			},
		},
		{
			name: "Enable regular users view blocked",
			requestBody: &api.AccountRequest{
				Settings: api.AccountSettings{
					PeerLoginExpirationEnabled: true,
					PeerLoginExpiration:        86400,
					RegularUsersViewBlocked:    true,
				},
			},
			expectedStatus: http.StatusOK,
			verifyResponse: func(t *testing.T, account *api.Account) {
				t.Helper()
				assert.Equal(t, true, account.Settings.RegularUsersViewBlocked)
			},
			verifyDB: func(t *testing.T, dbAccount *types.Account) {
				t.Helper()
				assert.Equal(t, true, dbAccount.Settings.RegularUsersViewBlocked)
			},
		},
		{
			name: "Enable groups propagation",
			requestBody: &api.AccountRequest{
				Settings: api.AccountSettings{
					PeerLoginExpirationEnabled: true,
					PeerLoginExpiration:        86400,
					GroupsPropagationEnabled:   &trueVal,
				},
			},
			expectedStatus: http.StatusOK,
			verifyResponse: func(t *testing.T, account *api.Account) {
				t.Helper()
				assert.NotNil(t, account.Settings.GroupsPropagationEnabled)
				assert.Equal(t, true, *account.Settings.GroupsPropagationEnabled)
			},
			verifyDB: func(t *testing.T, dbAccount *types.Account) {
				t.Helper()
				assert.Equal(t, true, dbAccount.Settings.GroupsPropagationEnabled)
			},
		},
		{
			name: "Enable JWT groups",
			requestBody: &api.AccountRequest{
				Settings: api.AccountSettings{
					PeerLoginExpirationEnabled: true,
					PeerLoginExpiration:        86400,
					GroupsPropagationEnabled:   &falseVal,
					JwtGroupsEnabled:           &trueVal,
					JwtGroupsClaimName:         stringPointer("groups"),
				},
			},
			expectedStatus: http.StatusOK,
			verifyResponse: func(t *testing.T, account *api.Account) {
				t.Helper()
				assert.NotNil(t, account.Settings.JwtGroupsEnabled)
				assert.Equal(t, true, *account.Settings.JwtGroupsEnabled)
				assert.NotNil(t, account.Settings.JwtGroupsClaimName)
				assert.Equal(t, "groups", *account.Settings.JwtGroupsClaimName)
			},
			verifyDB: func(t *testing.T, dbAccount *types.Account) {
				t.Helper()
				assert.Equal(t, true, dbAccount.Settings.JWTGroupsEnabled)
				assert.Equal(t, "groups", dbAccount.Settings.JWTGroupsClaimName)
			},
		},
	}

	for _, tc := range tt {
		for _, user := range users {
			t.Run(user.name+" - "+tc.name, func(t *testing.T) {
				apiHandler, am, _ := channel.BuildApiBlackBoxWithDBState(t, "../testdata/accounts.sql", nil, false)

				body, err := json.Marshal(tc.requestBody)
				if err != nil {
					t.Fatalf("Failed to marshal request body: %v", err)
				}

				req := testing_tools.BuildRequest(t, body, http.MethodPut, strings.Replace("/api/accounts/{accountId}", "{accountId}", testing_tools.TestAccountId, 1), user.userId)
				recorder := httptest.NewRecorder()
				apiHandler.ServeHTTP(recorder, req)

				content, expectResponse := testing_tools.ReadResponse(t, recorder, tc.expectedStatus, user.expectResponse)
				if !expectResponse {
					return
				}

				got := &api.Account{}
				if err := json.Unmarshal(content, got); err != nil {
					t.Fatalf("Sent content is not in correct json format; %v", err)
				}

				assert.Equal(t, testing_tools.TestAccountId, got.Id)
				assert.Equal(t, "test.com", got.Domain)
				tc.verifyResponse(t, got)

				db := testing_tools.GetDB(t, am.GetStore())
				dbAccount := testing_tools.VerifyAccountSettings(t, db)
				tc.verifyDB(t, dbAccount)
			})
		}
	}
}

func stringPointer(s string) *string {
	return &s
}
