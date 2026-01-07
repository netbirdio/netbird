package instance

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/server/idp"
)

// mockStore implements a minimal store.Store for testing
type mockStore struct {
	accountsCount int64
	err           error
}

func (m *mockStore) GetAccountsCounter(ctx context.Context) (int64, error) {
	if m.err != nil {
		return 0, m.err
	}
	return m.accountsCount, nil
}

// mockEmbeddedIdPManager wraps the real EmbeddedIdPManager for testing
type mockEmbeddedIdPManager struct {
	createUserFunc func(ctx context.Context, email, password, name string) (*idp.UserData, error)
}

func (m *mockEmbeddedIdPManager) CreateUserWithPassword(ctx context.Context, email, password, name string) (*idp.UserData, error) {
	if m.createUserFunc != nil {
		return m.createUserFunc(ctx, email, password, name)
	}
	return &idp.UserData{
		ID:    "test-user-id",
		Email: email,
		Name:  name,
	}, nil
}

// testManager is a test implementation that accepts our mock types
type testManager struct {
	store              *mockStore
	embeddedIdpManager *mockEmbeddedIdPManager
}

func (m *testManager) IsSetupRequired(ctx context.Context) (bool, error) {
	if m.embeddedIdpManager == nil {
		return false, nil
	}

	count, err := m.store.GetAccountsCounter(ctx)
	if err != nil {
		return false, err
	}

	return count == 0, nil
}

func (m *testManager) CreateOwnerUser(ctx context.Context, email, password, name string) (*idp.UserData, error) {
	if m.embeddedIdpManager == nil {
		return nil, errors.New("embedded IDP is not enabled")
	}

	return m.embeddedIdpManager.CreateUserWithPassword(ctx, email, password, name)
}

func TestIsSetupRequired_EmbeddedIdPDisabled(t *testing.T) {
	manager := &testManager{
		store:              &mockStore{accountsCount: 0},
		embeddedIdpManager: nil, // No embedded IDP
	}

	required, err := manager.IsSetupRequired(context.Background())
	require.NoError(t, err)
	assert.False(t, required, "setup should not be required when embedded IDP is disabled")
}

func TestIsSetupRequired_NoAccounts(t *testing.T) {
	manager := &testManager{
		store:              &mockStore{accountsCount: 0},
		embeddedIdpManager: &mockEmbeddedIdPManager{},
	}

	required, err := manager.IsSetupRequired(context.Background())
	require.NoError(t, err)
	assert.True(t, required, "setup should be required when no accounts exist")
}

func TestIsSetupRequired_AccountsExist(t *testing.T) {
	manager := &testManager{
		store:              &mockStore{accountsCount: 1},
		embeddedIdpManager: &mockEmbeddedIdPManager{},
	}

	required, err := manager.IsSetupRequired(context.Background())
	require.NoError(t, err)
	assert.False(t, required, "setup should not be required when accounts exist")
}

func TestIsSetupRequired_MultipleAccounts(t *testing.T) {
	manager := &testManager{
		store:              &mockStore{accountsCount: 5},
		embeddedIdpManager: &mockEmbeddedIdPManager{},
	}

	required, err := manager.IsSetupRequired(context.Background())
	require.NoError(t, err)
	assert.False(t, required, "setup should not be required when multiple accounts exist")
}

func TestIsSetupRequired_StoreError(t *testing.T) {
	manager := &testManager{
		store:              &mockStore{err: errors.New("database error")},
		embeddedIdpManager: &mockEmbeddedIdPManager{},
	}

	_, err := manager.IsSetupRequired(context.Background())
	assert.Error(t, err, "should return error when store fails")
}

func TestCreateOwnerUser_Success(t *testing.T) {
	expectedEmail := "admin@example.com"
	expectedName := "Admin User"
	expectedPassword := "securepassword123"

	manager := &testManager{
		store: &mockStore{accountsCount: 0},
		embeddedIdpManager: &mockEmbeddedIdPManager{
			createUserFunc: func(ctx context.Context, email, password, name string) (*idp.UserData, error) {
				assert.Equal(t, expectedEmail, email)
				assert.Equal(t, expectedPassword, password)
				assert.Equal(t, expectedName, name)
				return &idp.UserData{
					ID:    "created-user-id",
					Email: email,
					Name:  name,
				}, nil
			},
		},
	}

	userData, err := manager.CreateOwnerUser(context.Background(), expectedEmail, expectedPassword, expectedName)
	require.NoError(t, err)
	assert.Equal(t, "created-user-id", userData.ID)
	assert.Equal(t, expectedEmail, userData.Email)
	assert.Equal(t, expectedName, userData.Name)
}

func TestCreateOwnerUser_EmbeddedIdPDisabled(t *testing.T) {
	manager := &testManager{
		store:              &mockStore{accountsCount: 0},
		embeddedIdpManager: nil,
	}

	_, err := manager.CreateOwnerUser(context.Background(), "admin@example.com", "password123", "Admin")
	assert.Error(t, err, "should return error when embedded IDP is disabled")
	assert.Contains(t, err.Error(), "embedded IDP is not enabled")
}

func TestCreateOwnerUser_IdPError(t *testing.T) {
	manager := &testManager{
		store: &mockStore{accountsCount: 0},
		embeddedIdpManager: &mockEmbeddedIdPManager{
			createUserFunc: func(ctx context.Context, email, password, name string) (*idp.UserData, error) {
				return nil, errors.New("user already exists")
			},
		},
	}

	_, err := manager.CreateOwnerUser(context.Background(), "admin@example.com", "password123", "Admin")
	assert.Error(t, err, "should return error when IDP fails")
}

func TestDefaultManager_ValidateSetupRequest(t *testing.T) {
	manager := &DefaultManager{
		setupRequired: true,
	}

	tests := []struct {
		name        string
		email       string
		password    string
		userName    string
		expectError bool
		errorMsg    string
	}{
		{
			name:        "valid request",
			email:       "admin@example.com",
			password:    "password123",
			userName:    "Admin User",
			expectError: false,
		},
		{
			name:        "empty email",
			email:       "",
			password:    "password123",
			userName:    "Admin User",
			expectError: true,
			errorMsg:    "email is required",
		},
		{
			name:        "invalid email format",
			email:       "not-an-email",
			password:    "password123",
			userName:    "Admin User",
			expectError: true,
			errorMsg:    "invalid email format",
		},
		{
			name:        "empty name",
			email:       "admin@example.com",
			password:    "password123",
			userName:    "",
			expectError: true,
			errorMsg:    "name is required",
		},
		{
			name:        "empty password",
			email:       "admin@example.com",
			password:    "",
			userName:    "Admin User",
			expectError: true,
			errorMsg:    "password is required",
		},
		{
			name:        "password too short",
			email:       "admin@example.com",
			password:    "short",
			userName:    "Admin User",
			expectError: true,
			errorMsg:    "password must be at least 8 characters",
		},
		{
			name:        "password exactly 8 characters",
			email:       "admin@example.com",
			password:    "12345678",
			userName:    "Admin User",
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := manager.validateSetupInfo(tt.email, tt.password, tt.userName)
			if tt.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestDefaultManager_CreateOwnerUser_SetupAlreadyCompleted(t *testing.T) {
	manager := &DefaultManager{
		setupRequired:      false,
		embeddedIdpManager: &idp.EmbeddedIdPManager{},
	}

	_, err := manager.CreateOwnerUser(context.Background(), "admin@example.com", "password123", "Admin")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "setup already completed")
}
