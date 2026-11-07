package idp

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
	"github.com/stretchr/testify/require"

	nbcontext "github.com/netbirdio/netbird/management/server/context"
	"github.com/netbirdio/netbird/management/server/mock_server"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/auth"
	"github.com/netbirdio/netbird/shared/management/http/api"
	"github.com/netbirdio/netbird/shared/management/status"
)

const (
	testAccountID = "test-account-id"
	testUserID    = "test-user-id"
	existingIDPID = "existing-idp-id"
	newIDPID      = "new-idp-id"
)

func initIDPTestData(existingIDP *types.IdentityProvider) *handler {
	return &handler{
		accountManager: &mock_server.MockAccountManager{
			GetIdentityProvidersFunc: func(_ context.Context, accountID, userID string) ([]*types.IdentityProvider, error) {
				if accountID != testAccountID {
					return nil, status.Errorf(status.NotFound, "account not found")
				}
				if existingIDP != nil {
					return []*types.IdentityProvider{existingIDP}, nil
				}
				return []*types.IdentityProvider{}, nil
			},
			GetIdentityProviderFunc: func(_ context.Context, accountID, idpID, userID string) (*types.IdentityProvider, error) {
				if accountID != testAccountID {
					return nil, status.Errorf(status.NotFound, "account not found")
				}
				if existingIDP != nil && idpID == existingIDP.ID {
					return existingIDP, nil
				}
				return nil, status.Errorf(status.NotFound, "identity provider not found")
			},
			CreateIdentityProviderFunc: func(_ context.Context, accountID, userID string, idp *types.IdentityProvider) (*types.IdentityProvider, error) {
				if accountID != testAccountID {
					return nil, status.Errorf(status.NotFound, "account not found")
				}
				if idp.Name == "" {
					return nil, status.Errorf(status.InvalidArgument, "name is required")
				}
				created := idp.Copy()
				created.ID = newIDPID
				created.AccountID = accountID
				return created, nil
			},
			UpdateIdentityProviderFunc: func(_ context.Context, accountID, idpID, userID string, idp *types.IdentityProvider) (*types.IdentityProvider, error) {
				if accountID != testAccountID {
					return nil, status.Errorf(status.NotFound, "account not found")
				}
				if existingIDP == nil || idpID != existingIDP.ID {
					return nil, status.Errorf(status.NotFound, "identity provider not found")
				}
				updated := idp.Copy()
				updated.ID = idpID
				updated.AccountID = accountID
				return updated, nil
			},
			DeleteIdentityProviderFunc: func(_ context.Context, accountID, idpID, userID string) error {
				if accountID != testAccountID {
					return status.Errorf(status.NotFound, "account not found")
				}
				if existingIDP == nil || idpID != existingIDP.ID {
					return status.Errorf(status.NotFound, "identity provider not found")
				}
				return nil
			},
		},
	}
}

func TestGetAllIdentityProviders(t *testing.T) {
	existingIDP := &types.IdentityProvider{
		ID:       existingIDPID,
		Name:     "Test IDP",
		Type:     types.IdentityProviderTypeOIDC,
		Issuer:   "https://issuer.example.com",
		ClientID: "client-id",
	}

	tt := []struct {
		name           string
		expectedStatus int
		expectedCount  int
	}{
		{
			name:           "Get All Identity Providers",
			expectedStatus: http.StatusOK,
			expectedCount:  1,
		},
	}

	h := initIDPTestData(existingIDP)

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/api/identity-providers", nil)
			req = nbcontext.SetUserAuthInRequest(req, auth.UserAuth{
				UserId:    testUserID,
				AccountId: testAccountID,
			})

			router := mux.NewRouter()
			router.HandleFunc("/api/identity-providers", h.getAllIdentityProviders).Methods("GET")
			router.ServeHTTP(recorder, req)

			res := recorder.Result()
			defer res.Body.Close()

			assert.Equal(t, tc.expectedStatus, recorder.Code)

			content, err := io.ReadAll(res.Body)
			require.NoError(t, err)

			var idps []api.IdentityProvider
			err = json.Unmarshal(content, &idps)
			require.NoError(t, err)
			assert.Len(t, idps, tc.expectedCount)
		})
	}
}

func TestGetIdentityProvider(t *testing.T) {
	existingIDP := &types.IdentityProvider{
		ID:       existingIDPID,
		Name:     "Test IDP",
		Type:     types.IdentityProviderTypeOIDC,
		Issuer:   "https://issuer.example.com",
		ClientID: "client-id",
	}

	tt := []struct {
		name           string
		idpID          string
		expectedStatus int
		expectedBody   bool
	}{
		{
			name:           "Get Existing Identity Provider",
			idpID:          existingIDPID,
			expectedStatus: http.StatusOK,
			expectedBody:   true,
		},
		{
			name:           "Get Non-Existing Identity Provider",
			idpID:          "non-existing-id",
			expectedStatus: http.StatusNotFound,
			expectedBody:   false,
		},
	}

	h := initIDPTestData(existingIDP)

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/identity-providers/%s", tc.idpID), nil)
			req = nbcontext.SetUserAuthInRequest(req, auth.UserAuth{
				UserId:    testUserID,
				AccountId: testAccountID,
			})

			router := mux.NewRouter()
			router.HandleFunc("/api/identity-providers/{idpId}", h.getIdentityProvider).Methods("GET")
			router.ServeHTTP(recorder, req)

			res := recorder.Result()
			defer res.Body.Close()

			assert.Equal(t, tc.expectedStatus, recorder.Code)

			if tc.expectedBody {
				content, err := io.ReadAll(res.Body)
				require.NoError(t, err)

				var idp api.IdentityProvider
				err = json.Unmarshal(content, &idp)
				require.NoError(t, err)
				assert.Equal(t, existingIDPID, *idp.Id)
				assert.Equal(t, existingIDP.Name, idp.Name)
			}
		})
	}
}

func TestCreateIdentityProvider(t *testing.T) {
	tt := []struct {
		name           string
		requestBody    string
		expectedStatus int
		expectedBody   bool
	}{
		{
			name: "Create Identity Provider",
			requestBody: `{
				"name": "New IDP",
				"type": "oidc",
				"issuer": "https://new-issuer.example.com",
				"client_id": "new-client-id",
				"client_secret": "new-client-secret"
			}`,
			expectedStatus: http.StatusOK,
			expectedBody:   true,
		},
		{
			name:           "Create Identity Provider with Invalid JSON",
			requestBody:    `{invalid json`,
			expectedStatus: http.StatusBadRequest,
			expectedBody:   false,
		},
	}

	h := initIDPTestData(nil)

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/api/identity-providers", bytes.NewBufferString(tc.requestBody))
			req.Header.Set("Content-Type", "application/json")
			req = nbcontext.SetUserAuthInRequest(req, auth.UserAuth{
				UserId:    testUserID,
				AccountId: testAccountID,
			})

			router := mux.NewRouter()
			router.HandleFunc("/api/identity-providers", h.createIdentityProvider).Methods("POST")
			router.ServeHTTP(recorder, req)

			res := recorder.Result()
			defer res.Body.Close()

			assert.Equal(t, tc.expectedStatus, recorder.Code)

			if tc.expectedBody {
				content, err := io.ReadAll(res.Body)
				require.NoError(t, err)

				var idp api.IdentityProvider
				err = json.Unmarshal(content, &idp)
				require.NoError(t, err)
				assert.Equal(t, newIDPID, *idp.Id)
				assert.Equal(t, "New IDP", idp.Name)
				assert.Equal(t, api.IdentityProviderTypeOidc, idp.Type)
			}
		})
	}
}

func TestUpdateIdentityProvider(t *testing.T) {
	existingIDP := &types.IdentityProvider{
		ID:           existingIDPID,
		Name:         "Test IDP",
		Type:         types.IdentityProviderTypeOIDC,
		Issuer:       "https://issuer.example.com",
		ClientID:     "client-id",
		ClientSecret: "client-secret",
	}

	tt := []struct {
		name           string
		idpID          string
		requestBody    string
		expectedStatus int
		expectedBody   bool
	}{
		{
			name:  "Update Existing Identity Provider",
			idpID: existingIDPID,
			requestBody: `{
				"name": "Updated IDP",
				"type": "oidc",
				"issuer": "https://updated-issuer.example.com",
				"client_id": "updated-client-id"
			}`,
			expectedStatus: http.StatusOK,
			expectedBody:   true,
		},
		{
			name:  "Update Non-Existing Identity Provider",
			idpID: "non-existing-id",
			requestBody: `{
				"name": "Updated IDP",
				"type": "oidc",
				"issuer": "https://updated-issuer.example.com",
				"client_id": "updated-client-id"
			}`,
			expectedStatus: http.StatusNotFound,
			expectedBody:   false,
		},
		{
			name:           "Update Identity Provider with Invalid JSON",
			idpID:          existingIDPID,
			requestBody:    `{invalid json`,
			expectedStatus: http.StatusBadRequest,
			expectedBody:   false,
		},
	}

	h := initIDPTestData(existingIDP)

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPut, fmt.Sprintf("/api/identity-providers/%s", tc.idpID), bytes.NewBufferString(tc.requestBody))
			req.Header.Set("Content-Type", "application/json")
			req = nbcontext.SetUserAuthInRequest(req, auth.UserAuth{
				UserId:    testUserID,
				AccountId: testAccountID,
			})

			router := mux.NewRouter()
			router.HandleFunc("/api/identity-providers/{idpId}", h.updateIdentityProvider).Methods("PUT")
			router.ServeHTTP(recorder, req)

			res := recorder.Result()
			defer res.Body.Close()

			assert.Equal(t, tc.expectedStatus, recorder.Code)

			if tc.expectedBody {
				content, err := io.ReadAll(res.Body)
				require.NoError(t, err)

				var idp api.IdentityProvider
				err = json.Unmarshal(content, &idp)
				require.NoError(t, err)
				assert.Equal(t, existingIDPID, *idp.Id)
				assert.Equal(t, "Updated IDP", idp.Name)
			}
		})
	}
}

func TestDeleteIdentityProvider(t *testing.T) {
	existingIDP := &types.IdentityProvider{
		ID:       existingIDPID,
		Name:     "Test IDP",
		Type:     types.IdentityProviderTypeOIDC,
		Issuer:   "https://issuer.example.com",
		ClientID: "client-id",
	}

	tt := []struct {
		name           string
		idpID          string
		expectedStatus int
	}{
		{
			name:           "Delete Existing Identity Provider",
			idpID:          existingIDPID,
			expectedStatus: http.StatusOK,
		},
		{
			name:           "Delete Non-Existing Identity Provider",
			idpID:          "non-existing-id",
			expectedStatus: http.StatusNotFound,
		},
	}

	h := initIDPTestData(existingIDP)

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodDelete, fmt.Sprintf("/api/identity-providers/%s", tc.idpID), nil)
			req = nbcontext.SetUserAuthInRequest(req, auth.UserAuth{
				UserId:    testUserID,
				AccountId: testAccountID,
			})

			router := mux.NewRouter()
			router.HandleFunc("/api/identity-providers/{idpId}", h.deleteIdentityProvider).Methods("DELETE")
			router.ServeHTTP(recorder, req)

			res := recorder.Result()
			defer res.Body.Close()

			assert.Equal(t, tc.expectedStatus, recorder.Code)
		})
	}
}

func TestToAPIResponse(t *testing.T) {
	idp := &types.IdentityProvider{
		ID:           "test-id",
		Name:         "Test IDP",
		Type:         types.IdentityProviderTypeGoogle,
		Issuer:       "https://accounts.google.com",
		ClientID:     "client-id",
		ClientSecret: "should-not-be-returned",
	}

	response := toAPIResponse(idp)

	assert.Equal(t, "test-id", *response.Id)
	assert.Equal(t, "Test IDP", response.Name)
	assert.Equal(t, api.IdentityProviderTypeGoogle, response.Type)
	assert.Equal(t, "https://accounts.google.com", response.Issuer)
	assert.Equal(t, "client-id", response.ClientId)
	// Note: ClientSecret is not included in response type by design
}

func TestFromAPIRequest(t *testing.T) {
	req := &api.IdentityProviderRequest{
		Name:         "New IDP",
		Type:         api.IdentityProviderTypeOkta,
		Issuer:       "https://dev-123456.okta.com",
		ClientId:     "okta-client-id",
		ClientSecret: "okta-client-secret",
	}

	idp := fromAPIRequest(req)

	assert.Equal(t, "New IDP", idp.Name)
	assert.Equal(t, types.IdentityProviderTypeOkta, idp.Type)
	assert.Equal(t, "https://dev-123456.okta.com", idp.Issuer)
	assert.Equal(t, "okta-client-id", idp.ClientID)
	assert.Equal(t, "okta-client-secret", idp.ClientSecret)
}

func TestOIDCOptionsAPIConversion(t *testing.T) {
	scopes := []string{"iserv:groups"}
	claim := "iserv:groups"
	getUserInfo := true
	req := &api.IdentityProviderRequest{
		Type:             api.IdentityProviderTypeOidc,
		AdditionalScopes: &scopes, GroupsClaim: &claim, GetUserInfo: &getUserInfo,
	}
	idp := fromAPIRequest(req)
	assert.Equal(t, scopes, idp.AdditionalScopes)
	assert.Equal(t, &claim, idp.GroupsClaim)
	assert.Equal(t, &getUserInfo, idp.GetUserInfo)
	resp := toAPIResponse(idp)
	assert.Equal(t, &scopes, resp.AdditionalScopes)
	assert.Equal(t, &claim, resp.GroupsClaim)
	assert.Equal(t, &getUserInfo, resp.GetUserInfo)

	empty := []string{}
	req.AdditionalScopes = &empty
	req.GroupsClaim = nil
	req.GetUserInfo = nil
	idp = fromAPIRequest(req)
	assert.NotNil(t, idp.AdditionalScopes, "an empty array must clear additional scopes on update")
	assert.Empty(t, idp.AdditionalScopes)
	assert.Nil(t, idp.GroupsClaim, "an omitted claim must retain the existing mapping")
	assert.Nil(t, idp.GetUserInfo, "an omitted UserInfo setting must retain the existing value")
}

func TestOIDCOptionsJSONUpdateSemantics(t *testing.T) {
	for _, tc := range []struct {
		name            string
		body            string
		wantScopesSet   bool
		wantClaimSet    bool
		wantUserInfoSet bool
	}{
		{"omitted", `{}`, false, false, false},
		{"null", `{"additional_scopes":null,"groups_claim":null,"get_user_info":null}`, false, false, false},
		{"clear", `{"additional_scopes":[],"groups_claim":"","get_user_info":false}`, true, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var req api.IdentityProviderRequest
			require.NoError(t, json.Unmarshal([]byte(tc.body), &req))
			idp := fromAPIRequest(&req)
			assert.Equal(t, tc.wantScopesSet, idp.AdditionalScopes != nil)
			assert.Equal(t, tc.wantClaimSet, idp.GroupsClaim != nil)
			assert.Equal(t, tc.wantUserInfoSet, idp.GetUserInfo != nil)
		})
	}
}
