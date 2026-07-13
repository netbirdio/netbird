package instance

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/mail"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/server/account"
	"github.com/netbirdio/netbird/management/server/idp"
	nbinstance "github.com/netbirdio/netbird/management/server/instance"
	"github.com/netbirdio/netbird/management/server/mock_server"
	nbstore "github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/auth"
	"github.com/netbirdio/netbird/shared/management/http/api"
	"github.com/netbirdio/netbird/shared/management/status"
)

// mockInstanceManager implements instance.Manager for testing
type mockInstanceManager struct {
	isSetupRequired   bool
	isSetupRequiredFn func(ctx context.Context) (bool, error)
	createOwnerUserFn func(ctx context.Context, email, password, name string) (*idp.UserData, error)
	rollbackSetupFn   func(ctx context.Context, userID string) error
	getVersionInfoFn  func(ctx context.Context) (*nbinstance.VersionInfo, error)
}

func (m *mockInstanceManager) IsSetupRequired(ctx context.Context) (bool, error) {
	if m.isSetupRequiredFn != nil {
		return m.isSetupRequiredFn(ctx)
	}
	return m.isSetupRequired, nil
}

func (m *mockInstanceManager) CreateOwnerUser(ctx context.Context, email, password, name string) (*idp.UserData, error) {
	if m.createOwnerUserFn != nil {
		return m.createOwnerUserFn(ctx, email, password, name)
	}

	// Default mock includes validation like the real manager
	if !m.isSetupRequired {
		return nil, status.Errorf(status.PreconditionFailed, "setup already completed")
	}
	if email == "" {
		return nil, status.Errorf(status.InvalidArgument, "email is required")
	}
	if _, err := mail.ParseAddress(email); err != nil {
		return nil, status.Errorf(status.InvalidArgument, "invalid email format")
	}
	if name == "" {
		return nil, status.Errorf(status.InvalidArgument, "name is required")
	}
	if password == "" {
		return nil, status.Errorf(status.InvalidArgument, "password is required")
	}
	if len(password) < 8 {
		return nil, status.Errorf(status.InvalidArgument, "password must be at least 8 characters")
	}

	return &idp.UserData{
		ID:    "test-user-id",
		Email: email,
		Name:  name,
	}, nil
}

func (m *mockInstanceManager) RollbackSetup(ctx context.Context, userID string) error {
	if m.rollbackSetupFn != nil {
		return m.rollbackSetupFn(ctx, userID)
	}
	return nil
}

func (m *mockInstanceManager) GetVersionInfo(ctx context.Context) (*nbinstance.VersionInfo, error) {
	if m.getVersionInfoFn != nil {
		return m.getVersionInfoFn(ctx)
	}
	return &nbinstance.VersionInfo{
		CurrentVersion:            "0.34.0",
		DashboardVersion:          "2.0.0",
		ManagementVersion:         "0.35.0",
		ManagementUpdateAvailable: true,
	}, nil
}

var _ nbinstance.Manager = (*mockInstanceManager)(nil)

func setupTestRouter(manager nbinstance.Manager) *mux.Router {
	return setupTestRouterWithPAT(manager, nil)
}

func setupTestRouterWithPAT(manager nbinstance.Manager, accountManager account.Manager) *mux.Router {
	router := mux.NewRouter()
	AddEndpoints(manager, accountManager, router)
	return router
}

func TestGetInstanceStatus_SetupRequired(t *testing.T) {
	manager := &mockInstanceManager{isSetupRequired: true}
	router := setupTestRouter(manager)

	req := httptest.NewRequest(http.MethodGet, "/instance", nil)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var response api.InstanceStatus
	err := json.NewDecoder(rec.Body).Decode(&response)
	require.NoError(t, err)
	assert.True(t, response.SetupRequired)
}

func TestGetInstanceStatus_SetupNotRequired(t *testing.T) {
	manager := &mockInstanceManager{isSetupRequired: false}
	router := setupTestRouter(manager)

	req := httptest.NewRequest(http.MethodGet, "/instance", nil)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var response api.InstanceStatus
	err := json.NewDecoder(rec.Body).Decode(&response)
	require.NoError(t, err)
	assert.False(t, response.SetupRequired)
}

func TestGetInstanceStatus_Error(t *testing.T) {
	manager := &mockInstanceManager{
		isSetupRequiredFn: func(ctx context.Context) (bool, error) {
			return false, errors.New("database error")
		},
	}
	router := setupTestRouter(manager)

	req := httptest.NewRequest(http.MethodGet, "/instance", nil)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

func TestSetup_Success(t *testing.T) {
	manager := &mockInstanceManager{
		isSetupRequired: true,
		createOwnerUserFn: func(ctx context.Context, email, password, name string) (*idp.UserData, error) {
			assert.Equal(t, "admin@example.com", email)
			assert.Equal(t, "securepassword123", password)
			assert.Equal(t, "Admin User", name)
			return &idp.UserData{
				ID:    "created-user-id",
				Email: email,
				Name:  name,
			}, nil
		},
	}
	router := setupTestRouter(manager)

	body := `{"email": "admin@example.com", "password": "securepassword123", "name": "Admin User"}`
	req := httptest.NewRequest(http.MethodPost, "/setup", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"))

	var response api.SetupResponse
	err := json.NewDecoder(rec.Body).Decode(&response)
	require.NoError(t, err)
	assert.Equal(t, "created-user-id", response.UserId)
	assert.Equal(t, "admin@example.com", response.Email)
}

func TestSetup_AlreadyCompleted(t *testing.T) {
	manager := &mockInstanceManager{isSetupRequired: false}
	router := setupTestRouter(manager)

	body := `{"email": "admin@example.com", "password": "securepassword123"}`
	req := httptest.NewRequest(http.MethodPost, "/setup", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusPreconditionFailed, rec.Code)
}

func TestSetup_MissingEmail(t *testing.T) {
	manager := &mockInstanceManager{isSetupRequired: true}
	router := setupTestRouter(manager)

	body := `{"password": "securepassword123"}`
	req := httptest.NewRequest(http.MethodPost, "/setup", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnprocessableEntity, rec.Code)
}

func TestSetup_InvalidEmail(t *testing.T) {
	manager := &mockInstanceManager{isSetupRequired: true}
	router := setupTestRouter(manager)

	body := `{"email": "not-an-email", "password": "securepassword123", "name": "User"}`
	req := httptest.NewRequest(http.MethodPost, "/setup", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	// Note: Invalid email format uses mail.ParseAddress which is treated differently
	// and returns 400 Bad Request instead of 422 Unprocessable Entity
	assert.Equal(t, http.StatusUnprocessableEntity, rec.Code)
}

func TestSetup_MissingPassword(t *testing.T) {
	manager := &mockInstanceManager{isSetupRequired: true}
	router := setupTestRouter(manager)

	body := `{"email": "admin@example.com", "name": "User"}`
	req := httptest.NewRequest(http.MethodPost, "/setup", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnprocessableEntity, rec.Code)
}

func TestSetup_PasswordTooShort(t *testing.T) {
	manager := &mockInstanceManager{isSetupRequired: true}
	router := setupTestRouter(manager)

	body := `{"email": "admin@example.com", "password": "short", "name": "User"}`
	req := httptest.NewRequest(http.MethodPost, "/setup", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnprocessableEntity, rec.Code)
}

func TestSetup_InvalidJSON(t *testing.T) {
	manager := &mockInstanceManager{isSetupRequired: true}
	router := setupTestRouter(manager)

	body := `{invalid json}`
	req := httptest.NewRequest(http.MethodPost, "/setup", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestSetup_CreateUserError(t *testing.T) {
	manager := &mockInstanceManager{
		isSetupRequired: true,
		createOwnerUserFn: func(ctx context.Context, email, password, name string) (*idp.UserData, error) {
			return nil, errors.New("user creation failed")
		},
	}
	router := setupTestRouter(manager)

	body := `{"email": "admin@example.com", "password": "securepassword123", "name": "User"}`
	req := httptest.NewRequest(http.MethodPost, "/setup", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

func TestSetup_ManagerError(t *testing.T) {
	manager := &mockInstanceManager{
		isSetupRequired: true,
		createOwnerUserFn: func(ctx context.Context, email, password, name string) (*idp.UserData, error) {
			return nil, status.Errorf(status.Internal, "database error")
		},
	}
	router := setupTestRouter(manager)

	body := `{"email": "admin@example.com", "password": "securepassword123", "name": "User"}`
	req := httptest.NewRequest(http.MethodPost, "/setup", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

func TestSetup_PAT_FeatureDisabled_IgnoresCreatePAT(t *testing.T) {
	t.Setenv(nbinstance.SetupPATEnabledEnvKey, "false")

	manager := &mockInstanceManager{isSetupRequired: true}
	// NB_SETUP_PAT_ENABLED=false: request fields must be silently ignored
	router := setupTestRouterWithPAT(manager, &mock_server.MockAccountManager{})

	body := `{"email": "admin@example.com", "password": "securepassword123", "name": "Admin", "create_pat": true}`
	req := httptest.NewRequest(http.MethodPost, "/setup", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	var response api.SetupResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&response))
	assert.Nil(t, response.PersonalAccessToken)
}

func TestSetup_PAT_FlagOmitted_NoPAT(t *testing.T) {
	t.Setenv(nbinstance.SetupPATEnabledEnvKey, "true")

	manager := &mockInstanceManager{isSetupRequired: true}
	router := setupTestRouterWithPAT(manager, &mock_server.MockAccountManager{})

	body := `{"email": "admin@example.com", "password": "securepassword123", "name": "Admin"}`
	req := httptest.NewRequest(http.MethodPost, "/setup", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	var response api.SetupResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&response))
	assert.Nil(t, response.PersonalAccessToken)
}

func TestSetup_PAT_MissingExpireIn_DefaultsToOneDay(t *testing.T) {
	t.Setenv(nbinstance.SetupPATEnabledEnvKey, "true")

	createCalled := false
	manager := &mockInstanceManager{
		isSetupRequired: true,
		createOwnerUserFn: func(ctx context.Context, email, password, name string) (*idp.UserData, error) {
			createCalled = true
			return &idp.UserData{ID: "u1", Email: email, Name: name}, nil
		},
	}
	accountMgr := &mock_server.MockAccountManager{
		GetAccountIDByUserIdFunc: func(_ context.Context, userAuth auth.UserAuth) (string, error) {
			assert.Equal(t, "u1", userAuth.UserId)
			return "acc-1", nil
		},
		CreatePATFunc: func(_ context.Context, accountID, initiator, target, name string, expiresIn int) (*types.PersonalAccessTokenGenerated, error) {
			assert.Equal(t, "acc-1", accountID)
			assert.Equal(t, "u1", initiator)
			assert.Equal(t, "u1", target)
			assert.Equal(t, "setup-token", name)
			assert.Equal(t, 1, expiresIn)
			return &types.PersonalAccessTokenGenerated{PlainToken: "nbp_plain"}, nil
		},
	}
	router := setupTestRouterWithPAT(manager, accountMgr)

	body := `{"email": "admin@example.com", "password": "securepassword123", "name": "Admin", "create_pat": true}`
	req := httptest.NewRequest(http.MethodPost, "/setup", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
	assert.True(t, createCalled)
	var response api.SetupResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&response))
	require.NotNil(t, response.PersonalAccessToken)
	assert.Equal(t, "nbp_plain", *response.PersonalAccessToken)
}

func TestSetup_PAT_ExpireOutOfRange(t *testing.T) {
	t.Setenv(nbinstance.SetupPATEnabledEnvKey, "true")

	manager := &mockInstanceManager{isSetupRequired: true}
	router := setupTestRouterWithPAT(manager, &mock_server.MockAccountManager{})

	body := `{"email": "admin@example.com", "password": "securepassword123", "name": "Admin", "create_pat": true, "pat_expire_in": 0}`
	req := httptest.NewRequest(http.MethodPost, "/setup", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnprocessableEntity, rec.Code)
}

func TestSetup_PAT_Success(t *testing.T) {
	t.Setenv(nbinstance.SetupPATEnabledEnvKey, "true")

	manager := &mockInstanceManager{
		isSetupRequired: true,
		createOwnerUserFn: func(ctx context.Context, email, password, name string) (*idp.UserData, error) {
			return &idp.UserData{ID: "owner-id", Email: email, Name: name}, nil
		},
	}

	gotAccountArgs := struct {
		userID string
		email  string
	}{}
	accountMgr := &mock_server.MockAccountManager{
		GetAccountIDByUserIdFunc: func(_ context.Context, userAuth auth.UserAuth) (string, error) {
			gotAccountArgs.userID = userAuth.UserId
			gotAccountArgs.email = userAuth.Email
			return "acc-1", nil
		},
		CreatePATFunc: func(_ context.Context, accountID, initiator, target, name string, expiresIn int) (*types.PersonalAccessTokenGenerated, error) {
			assert.Equal(t, "acc-1", accountID)
			assert.Equal(t, "owner-id", initiator)
			assert.Equal(t, "owner-id", target)
			assert.Equal(t, "setup-token", name)
			assert.Equal(t, 30, expiresIn)
			return &types.PersonalAccessTokenGenerated{PlainToken: "nbp_plain"}, nil
		},
	}

	router := setupTestRouterWithPAT(manager, accountMgr)

	body := `{"email": "admin@example.com", "password": "securepassword123", "name": "Admin", "create_pat": true, "pat_expire_in": 30}`
	req := httptest.NewRequest(http.MethodPost, "/setup", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
	var response api.SetupResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&response))
	assert.Equal(t, "owner-id", response.UserId)
	require.NotNil(t, response.PersonalAccessToken)
	assert.Equal(t, "nbp_plain", *response.PersonalAccessToken)
	assert.Equal(t, "owner-id", gotAccountArgs.userID)
	assert.Equal(t, "admin@example.com", gotAccountArgs.email)
}

func TestSetup_PAT_AccountCreationFails_Rollback(t *testing.T) {
	t.Setenv(nbinstance.SetupPATEnabledEnvKey, "true")

	ctrl := gomock.NewController(t)
	accountStore := nbstore.NewMockStore(ctrl)
	accountStore.EXPECT().GetAccountIDByUserID(gomock.Any(), nbstore.LockingStrengthNone, "owner-id").Return("", status.NewAccountNotFoundError("owner-id"))

	rolledBackFor := ""
	manager := &mockInstanceManager{
		isSetupRequired: true,
		createOwnerUserFn: func(ctx context.Context, email, password, name string) (*idp.UserData, error) {
			return &idp.UserData{ID: "owner-id", Email: email, Name: name}, nil
		},
		rollbackSetupFn: func(_ context.Context, userID string) error {
			rolledBackFor = userID
			return nil
		},
	}
	accountMgr := &mock_server.MockAccountManager{
		GetAccountIDByUserIdFunc: func(_ context.Context, _ auth.UserAuth) (string, error) {
			return "", errors.New("db down")
		},
		GetStoreFunc: func() nbstore.Store {
			return accountStore
		},
	}

	router := setupTestRouterWithPAT(manager, accountMgr)

	body := `{"email": "admin@example.com", "password": "securepassword123", "name": "Admin", "create_pat": true, "pat_expire_in": 30}`
	req := httptest.NewRequest(http.MethodPost, "/setup", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.Equal(t, "owner-id", rolledBackFor, "RollbackSetup must be called with the created user id")
}

func TestSetup_PAT_CreatePATFails_Rollback(t *testing.T) {
	t.Setenv(nbinstance.SetupPATEnabledEnvKey, "true")

	ctrl := gomock.NewController(t)
	accountStore := nbstore.NewMockStore(ctrl)
	account := &types.Account{Id: "acc-1"}
	accountStore.EXPECT().GetAccount(gomock.Any(), "acc-1").Return(account, nil)
	accountStore.EXPECT().DeleteAccount(gomock.Any(), account).Return(nil)

	rolledBackFor := ""
	manager := &mockInstanceManager{
		isSetupRequired: true,
		createOwnerUserFn: func(ctx context.Context, email, password, name string) (*idp.UserData, error) {
			return &idp.UserData{ID: "owner-id", Email: email, Name: name}, nil
		},
		rollbackSetupFn: func(_ context.Context, userID string) error {
			rolledBackFor = userID
			return nil
		},
	}
	accountMgr := &mock_server.MockAccountManager{
		GetAccountIDByUserIdFunc: func(_ context.Context, _ auth.UserAuth) (string, error) {
			return "acc-1", nil
		},
		CreatePATFunc: func(_ context.Context, _, _, _, _ string, _ int) (*types.PersonalAccessTokenGenerated, error) {
			return nil, status.Errorf(status.Internal, "token store unavailable")
		},
		GetStoreFunc: func() nbstore.Store {
			return accountStore
		},
	}

	router := setupTestRouterWithPAT(manager, accountMgr)

	body := `{"email": "admin@example.com", "password": "securepassword123", "name": "Admin", "create_pat": true, "pat_expire_in": 30}`
	req := httptest.NewRequest(http.MethodPost, "/setup", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.Equal(t, "owner-id", rolledBackFor, "RollbackSetup must be called when CreatePAT fails")
}

func TestGetVersionInfo_Success(t *testing.T) {
	manager := &mockInstanceManager{}
	router := mux.NewRouter()
	AddVersionEndpoint(manager, router)

	req := httptest.NewRequest(http.MethodGet, "/instance/version", nil)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var response api.InstanceVersionInfo
	err := json.NewDecoder(rec.Body).Decode(&response)
	require.NoError(t, err)

	assert.Equal(t, "0.34.0", response.ManagementCurrentVersion)
	assert.NotNil(t, response.DashboardAvailableVersion)
	assert.Equal(t, "2.0.0", *response.DashboardAvailableVersion)
	assert.NotNil(t, response.ManagementAvailableVersion)
	assert.Equal(t, "0.35.0", *response.ManagementAvailableVersion)
	assert.True(t, response.ManagementUpdateAvailable)
}

func TestGetVersionInfo_Error(t *testing.T) {
	manager := &mockInstanceManager{
		getVersionInfoFn: func(ctx context.Context) (*nbinstance.VersionInfo, error) {
			return nil, errors.New("failed to fetch versions")
		},
	}
	router := mux.NewRouter()
	AddVersionEndpoint(manager, router)

	req := httptest.NewRequest(http.MethodGet, "/instance/version", nil)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}
