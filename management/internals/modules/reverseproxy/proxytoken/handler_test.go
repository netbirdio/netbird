package proxytoken

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	nbcontext "github.com/netbirdio/netbird/management/server/context"
	"github.com/netbirdio/netbird/management/server/permissions"
	"github.com/netbirdio/netbird/management/server/permissions/modules"
	"github.com/netbirdio/netbird/management/server/permissions/operations"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/auth"
	"github.com/netbirdio/netbird/shared/management/http/api"
)

func authContext(accountID, userID string) context.Context {
	return nbcontext.SetUserAuthInContext(context.Background(), auth.UserAuth{
		AccountId: accountID,
		UserId:    userID,
	})
}

func TestCreateToken_AccountScoped(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	accountID := "acc-123"
	var savedToken *types.ProxyAccessToken

	mockStore := store.NewMockStore(ctrl)
	mockStore.EXPECT().SaveProxyAccessToken(gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, token *types.ProxyAccessToken) error {
			savedToken = token
			return nil
		},
	)

	permsMgr := permissions.NewMockManager(ctrl)
	permsMgr.EXPECT().ValidateUserPermissions(gomock.Any(), accountID, "user-1", modules.Services, operations.Create).Return(true, nil)

	h := &handler{
		store:              mockStore,
		permissionsManager: permsMgr,
	}

	body := `{"name": "my-token"}`
	req := httptest.NewRequest("POST", "/reverse-proxies/proxy-tokens", bytes.NewBufferString(body))
	req = req.WithContext(authContext(accountID, "user-1"))
	w := httptest.NewRecorder()

	h.createToken(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	var resp api.ProxyTokenCreated
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))

	assert.NotEmpty(t, resp.PlainToken)
	assert.Equal(t, "my-token", resp.Name)
	assert.False(t, resp.Revoked)

	require.NotNil(t, savedToken)
	require.NotNil(t, savedToken.AccountID)
	assert.Equal(t, accountID, *savedToken.AccountID)
	assert.Equal(t, "user-1", savedToken.CreatedBy)
}

func TestCreateToken_WithExpiration(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	var savedToken *types.ProxyAccessToken

	mockStore := store.NewMockStore(ctrl)
	mockStore.EXPECT().SaveProxyAccessToken(gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, token *types.ProxyAccessToken) error {
			savedToken = token
			return nil
		},
	)

	permsMgr := permissions.NewMockManager(ctrl)
	permsMgr.EXPECT().ValidateUserPermissions(gomock.Any(), "acc-123", "user-1", modules.Services, operations.Create).Return(true, nil)

	h := &handler{
		store:              mockStore,
		permissionsManager: permsMgr,
	}

	body := `{"name": "expiring-token", "expires_in": 3600}`
	req := httptest.NewRequest("POST", "/reverse-proxies/proxy-tokens", bytes.NewBufferString(body))
	req = req.WithContext(authContext("acc-123", "user-1"))
	w := httptest.NewRecorder()

	h.createToken(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	require.NotNil(t, savedToken)
	require.NotNil(t, savedToken.ExpiresAt)
	assert.True(t, savedToken.ExpiresAt.After(time.Now()))
}

func TestCreateToken_EmptyName(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	permsMgr := permissions.NewMockManager(ctrl)
	permsMgr.EXPECT().ValidateUserPermissions(gomock.Any(), "acc-123", "user-1", modules.Services, operations.Create).Return(true, nil)

	h := &handler{
		permissionsManager: permsMgr,
	}

	body := `{"name": ""}`
	req := httptest.NewRequest("POST", "/reverse-proxies/proxy-tokens", bytes.NewBufferString(body))
	req = req.WithContext(authContext("acc-123", "user-1"))
	w := httptest.NewRecorder()

	h.createToken(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCreateToken_PermissionDenied(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	permsMgr := permissions.NewMockManager(ctrl)
	permsMgr.EXPECT().ValidateUserPermissions(gomock.Any(), "acc-123", "user-1", modules.Services, operations.Create).Return(false, nil)

	h := &handler{
		permissionsManager: permsMgr,
	}

	body := `{"name": "test"}`
	req := httptest.NewRequest("POST", "/reverse-proxies/proxy-tokens", bytes.NewBufferString(body))
	req = req.WithContext(authContext("acc-123", "user-1"))
	w := httptest.NewRecorder()

	h.createToken(w, req)
	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestListTokens(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	accountID := "acc-123"
	now := time.Now()

	mockStore := store.NewMockStore(ctrl)
	mockStore.EXPECT().GetProxyAccessTokensByAccountID(gomock.Any(), store.LockingStrengthNone, accountID).Return([]*types.ProxyAccessToken{
		{ID: "tok-1", Name: "token-1", AccountID: &accountID, CreatedAt: now, Revoked: false},
		{ID: "tok-2", Name: "token-2", AccountID: &accountID, CreatedAt: now, Revoked: true},
	}, nil)

	permsMgr := permissions.NewMockManager(ctrl)
	permsMgr.EXPECT().ValidateUserPermissions(gomock.Any(), accountID, "user-1", modules.Services, operations.Read).Return(true, nil)

	h := &handler{
		store:              mockStore,
		permissionsManager: permsMgr,
	}

	req := httptest.NewRequest("GET", "/reverse-proxies/proxy-tokens", nil)
	req = req.WithContext(authContext(accountID, "user-1"))
	w := httptest.NewRecorder()

	h.listTokens(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	var resp []api.ProxyToken
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	require.Len(t, resp, 2)
	assert.Equal(t, "tok-1", resp[0].Id)
	assert.False(t, resp[0].Revoked)
	assert.Equal(t, "tok-2", resp[1].Id)
	assert.True(t, resp[1].Revoked)
}

func TestRevokeToken_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	accountID := "acc-123"

	mockStore := store.NewMockStore(ctrl)
	mockStore.EXPECT().GetProxyAccessTokenByID(gomock.Any(), store.LockingStrengthNone, "tok-1").Return(&types.ProxyAccessToken{
		ID:        "tok-1",
		Name:      "test-token",
		AccountID: &accountID,
	}, nil)
	mockStore.EXPECT().RevokeProxyAccessToken(gomock.Any(), "tok-1").Return(nil)

	permsMgr := permissions.NewMockManager(ctrl)
	permsMgr.EXPECT().ValidateUserPermissions(gomock.Any(), accountID, "user-1", modules.Services, operations.Delete).Return(true, nil)

	h := &handler{
		store:              mockStore,
		permissionsManager: permsMgr,
	}

	req := httptest.NewRequest("DELETE", "/reverse-proxies/proxy-tokens/tok-1", nil)
	req = req.WithContext(authContext(accountID, "user-1"))
	req = mux.SetURLVars(req, map[string]string{"tokenId": "tok-1"})
	w := httptest.NewRecorder()

	h.revokeToken(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestRevokeToken_WrongAccount(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	otherAccount := "acc-other"

	mockStore := store.NewMockStore(ctrl)
	mockStore.EXPECT().GetProxyAccessTokenByID(gomock.Any(), store.LockingStrengthNone, "tok-1").Return(&types.ProxyAccessToken{
		ID:        "tok-1",
		AccountID: &otherAccount,
	}, nil)

	permsMgr := permissions.NewMockManager(ctrl)
	permsMgr.EXPECT().ValidateUserPermissions(gomock.Any(), "acc-123", "user-1", modules.Services, operations.Delete).Return(true, nil)

	h := &handler{
		store:              mockStore,
		permissionsManager: permsMgr,
	}

	req := httptest.NewRequest("DELETE", "/reverse-proxies/proxy-tokens/tok-1", nil)
	req = req.WithContext(authContext("acc-123", "user-1"))
	req = mux.SetURLVars(req, map[string]string{"tokenId": "tok-1"})
	w := httptest.NewRecorder()

	h.revokeToken(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestRevokeToken_ManagementWideToken(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockStore := store.NewMockStore(ctrl)
	mockStore.EXPECT().GetProxyAccessTokenByID(gomock.Any(), store.LockingStrengthNone, "tok-1").Return(&types.ProxyAccessToken{
		ID:        "tok-1",
		AccountID: nil,
	}, nil)

	permsMgr := permissions.NewMockManager(ctrl)
	permsMgr.EXPECT().ValidateUserPermissions(gomock.Any(), "acc-123", "user-1", modules.Services, operations.Delete).Return(true, nil)

	h := &handler{
		store:              mockStore,
		permissionsManager: permsMgr,
	}

	req := httptest.NewRequest("DELETE", "/reverse-proxies/proxy-tokens/tok-1", nil)
	req = req.WithContext(authContext("acc-123", "user-1"))
	req = mux.SetURLVars(req, map[string]string{"tokenId": "tok-1"})
	w := httptest.NewRecorder()

	h.revokeToken(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}
