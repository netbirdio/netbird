package credentials

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	credentialsmodel "github.com/netbirdio/netbird/management/internals/modules/credentials"
	nbcontext "github.com/netbirdio/netbird/management/server/context"
	"github.com/netbirdio/netbird/management/server/mock_server"
	"github.com/netbirdio/netbird/shared/auth"
	"github.com/netbirdio/netbird/shared/management/http/api"
	"github.com/netbirdio/netbird/shared/management/status"
)

const (
	testAccountID = "test_account"
	testUserID    = "test_user"
)

func newTestHandler(mock *mock_server.MockAccountManager) *handler {
	return &handler{accountManager: mock}
}

func authedRequest(t *testing.T, method, target string, body io.Reader) *http.Request {
	t.Helper()
	req := httptest.NewRequest(method, target, body)
	return nbcontext.SetUserAuthInRequest(req, auth.UserAuth{
		UserId:    testUserID,
		Domain:    "example.com",
		AccountId: testAccountID,
	})
}

func TestCreateCredential_HappyPath(t *testing.T) {
	var captured struct {
		accountID, userID, providerType, name, secret string
	}
	h := newTestHandler(&mock_server.MockAccountManager{
		CreateCredentialFunc: func(_ context.Context, accountID, userID, providerType, name string, secretFields map[string]string) (*credentialsmodel.Credential, error) {
			captured.accountID = accountID
			captured.userID = userID
			captured.providerType = providerType
			captured.name = name
			captured.secret = secretFields["auth_token"]
			return &credentialsmodel.Credential{
				ID:           "cred-1",
				AccountID:    accountID,
				ProviderType: providerType,
				Name:         name,
				CreatedAt:    time.Now().UTC(),
			}, nil
		},
	})

	tok := "cf_xxx"
	body, err := json.Marshal(api.CredentialRequest{
		ProviderType: "cloudflare",
		Name:         "primary",
		Secret:       &tok,
	})
	require.NoError(t, err)
	req := authedRequest(t, http.MethodPost, "/api/credentials", bytes.NewReader(body))

	rec := httptest.NewRecorder()
	router := mux.NewRouter()
	router.HandleFunc("/api/credentials", h.create).Methods(http.MethodPost)
	router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, testAccountID, captured.accountID)
	assert.Equal(t, "cloudflare", captured.providerType)
	assert.Equal(t, "cf_xxx", captured.secret)

	// Response must NOT contain the secret. Decoding into the API
	// type ensures only the schema fields exist; additional sanity
	// check by raw-string-match.
	respBody, _ := io.ReadAll(rec.Result().Body)
	assert.NotContains(t, string(respBody), "cf_xxx", "the secret must not appear on the response")
	assert.NotContains(t, string(respBody), "secret", "the response must not include any 'secret' field")

	var got api.Credential
	require.NoError(t, json.Unmarshal(respBody, &got))
	assert.Equal(t, "cred-1", got.Id)
	assert.Equal(t, "cloudflare", got.ProviderType)
	assert.Equal(t, "primary", got.Name)
}

func TestCreateCredential_BadJSON(t *testing.T) {
	h := newTestHandler(&mock_server.MockAccountManager{})
	req := authedRequest(t, http.MethodPost, "/api/credentials", strings.NewReader("not json"))
	rec := httptest.NewRecorder()
	router := mux.NewRouter()
	router.HandleFunc("/api/credentials", h.create).Methods(http.MethodPost)
	router.ServeHTTP(rec, req)
	// status.InvalidArgument maps to 422 in NetBird's HTTP error writer.
	assert.Equal(t, http.StatusUnprocessableEntity, rec.Code)
}

func TestGetCredential_NotFound(t *testing.T) {
	h := newTestHandler(&mock_server.MockAccountManager{
		GetCredentialMetadataFunc: func(_ context.Context, _, _, _ string) (*credentialsmodel.Credential, error) {
			return nil, status.Errorf(status.NotFound, "credential not found")
		},
	})
	req := authedRequest(t, http.MethodGet, "/api/credentials/missing", nil)
	rec := httptest.NewRecorder()
	router := mux.NewRouter()
	router.HandleFunc("/api/credentials/{credentialId}", h.get).Methods(http.MethodGet)
	router.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestGetCredential_HappyPath(t *testing.T) {
	created := time.Now().UTC()
	h := newTestHandler(&mock_server.MockAccountManager{
		GetCredentialMetadataFunc: func(_ context.Context, accountID, userID, ref string) (*credentialsmodel.Credential, error) {
			assert.Equal(t, testAccountID, accountID)
			assert.Equal(t, testUserID, userID)
			assert.Equal(t, "abc", ref)
			return &credentialsmodel.Credential{
				ID:           ref,
				AccountID:    accountID,
				ProviderType: "cloudflare",
				Name:         "main",
				CreatedAt:    created,
			}, nil
		},
	})
	req := authedRequest(t, http.MethodGet, "/api/credentials/abc", nil)
	rec := httptest.NewRecorder()
	router := mux.NewRouter()
	router.HandleFunc("/api/credentials/{credentialId}", h.get).Methods(http.MethodGet)
	router.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)

	respBody, _ := io.ReadAll(rec.Result().Body)
	assert.NotContains(t, string(respBody), "secret", "GET response must not include any secret field")
	var got api.Credential
	require.NoError(t, json.Unmarshal(respBody, &got))
	assert.Equal(t, "abc", got.Id)
}

func TestListCredentials_FilterPassedThrough(t *testing.T) {
	var capturedFilter string
	h := newTestHandler(&mock_server.MockAccountManager{
		ListCredentialsFunc: func(_ context.Context, _, _, providerTypeFilter string) ([]*credentialsmodel.Credential, error) {
			capturedFilter = providerTypeFilter
			return []*credentialsmodel.Credential{
				{ID: "a", AccountID: testAccountID, ProviderType: "cloudflare", Name: "first", CreatedAt: time.Now().UTC()},
			}, nil
		},
	})
	req := authedRequest(t, http.MethodGet, "/api/credentials?provider_type=cloudflare", nil)
	rec := httptest.NewRecorder()
	router := mux.NewRouter()
	router.HandleFunc("/api/credentials", h.list).Methods(http.MethodGet)
	router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "cloudflare", capturedFilter)
	respBody, _ := io.ReadAll(rec.Result().Body)
	assert.NotContains(t, string(respBody), "secret")
}

func TestUpdateCredential_HappyPath(t *testing.T) {
	var captured struct {
		ref, providerType, name, secret string
	}
	h := newTestHandler(&mock_server.MockAccountManager{
		UpdateCredentialFunc: func(_ context.Context, accountID, userID, ref, providerType, name string, secretFields map[string]string) (*credentialsmodel.Credential, error) {
			captured.ref = ref
			captured.providerType = providerType
			captured.name = name
			captured.secret = secretFields["auth_token"]
			return &credentialsmodel.Credential{
				ID:           ref,
				AccountID:    accountID,
				ProviderType: providerType,
				Name:         name,
				CreatedAt:    time.Now().UTC(),
			}, nil
		},
	})

	tok := "cf_rotated_token"
	body, err := json.Marshal(api.CredentialRequest{
		ProviderType: "cloudflare",
		Name:         "rotated",
		Secret:       &tok,
	})
	require.NoError(t, err)
	req := authedRequest(t, http.MethodPut, "/api/credentials/cred-1", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	router := mux.NewRouter()
	router.HandleFunc("/api/credentials/{credentialId}", h.update).Methods(http.MethodPut)
	router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "cred-1", captured.ref)
	assert.Equal(t, "cf_rotated_token", captured.secret)

	respBody, _ := io.ReadAll(rec.Result().Body)
	assert.NotContains(t, string(respBody), "cf_rotated_token", "PUT response must not echo the new secret")
	assert.NotContains(t, string(respBody), "secret", "PUT response must not include any 'secret' field")
}

func TestDeleteCredential_HappyPath(t *testing.T) {
	called := false
	h := newTestHandler(&mock_server.MockAccountManager{
		DeleteCredentialFunc: func(_ context.Context, _, _, _ string) error {
			called = true
			return nil
		},
	})
	req := authedRequest(t, http.MethodDelete, "/api/credentials/abc", nil)
	rec := httptest.NewRecorder()
	router := mux.NewRouter()
	router.HandleFunc("/api/credentials/{credentialId}", h.delete).Methods(http.MethodDelete)
	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.True(t, called)
}
