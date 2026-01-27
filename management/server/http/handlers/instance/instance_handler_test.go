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

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/server/idp"
	nbinstance "github.com/netbirdio/netbird/management/server/instance"
	"github.com/netbirdio/netbird/shared/management/http/api"
	"github.com/netbirdio/netbird/shared/management/status"
)

// mockInstanceManager implements instance.Manager for testing
type mockInstanceManager struct {
	isSetupRequired   bool
	isSetupRequiredFn func(ctx context.Context) (bool, error)
	createOwnerUserFn func(ctx context.Context, email, password, name string) (*idp.UserData, error)
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
	router := mux.NewRouter()
	AddEndpoints(manager, router)
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
