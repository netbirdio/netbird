package instance

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dexidp/dex/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/server/idp"
	"github.com/netbirdio/netbird/shared/management/status"
)

type mockIdP struct {
	mu                sync.Mutex
	createUserFunc    func(ctx context.Context, email, password, name string) (*idp.UserData, error)
	deleteUserFunc    func(ctx context.Context, userID string) error
	users             map[string][]*idp.UserData
	getAllAccountsErr error
}

func (m *mockIdP) CreateUserWithPassword(ctx context.Context, email, password, name string) (*idp.UserData, error) {
	if m.createUserFunc != nil {
		return m.createUserFunc(ctx, email, password, name)
	}
	return &idp.UserData{ID: "test-user-id", Email: email, Name: name}, nil
}

func (m *mockIdP) DeleteUser(ctx context.Context, userID string) error {
	if m.deleteUserFunc != nil {
		return m.deleteUserFunc(ctx, userID)
	}
	return nil
}

func (m *mockIdP) GetAllAccounts(_ context.Context) (map[string][]*idp.UserData, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.getAllAccountsErr != nil {
		return nil, m.getAllAccountsErr
	}
	return m.users, nil
}

type mockStore struct {
	accountsCount int64
	err           error
}

func (m *mockStore) GetAccountsCounter(_ context.Context) (int64, error) {
	if m.err != nil {
		return 0, m.err
	}
	return m.accountsCount, nil
}

func newTestManager(idpMock *mockIdP, storeMock *mockStore) *DefaultManager {
	return &DefaultManager{
		store:              storeMock,
		embeddedIdpManager: idpMock,
		setupRequired:      true,
		httpClient:         &http.Client{Timeout: httpTimeout},
	}
}

func TestCreateOwnerUser_Success(t *testing.T) {
	idpMock := &mockIdP{}
	mgr := newTestManager(idpMock, &mockStore{})

	userData, err := mgr.CreateOwnerUser(context.Background(), "admin@example.com", "password123", "Admin")
	require.NoError(t, err)
	assert.Equal(t, "admin@example.com", userData.Email)

	_, err = mgr.CreateOwnerUser(context.Background(), "admin2@example.com", "password123", "Admin2")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "setup already completed")
}

func TestCreateOwnerUser_SetupAlreadyCompleted(t *testing.T) {
	mgr := newTestManager(&mockIdP{}, &mockStore{})
	mgr.setupRequired = false

	_, err := mgr.CreateOwnerUser(context.Background(), "admin@example.com", "password123", "Admin")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "setup already completed")
}

func TestCreateOwnerUser_EmbeddedIdPDisabled(t *testing.T) {
	mgr := &DefaultManager{setupRequired: true}

	_, err := mgr.CreateOwnerUser(context.Background(), "admin@example.com", "password123", "Admin")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "embedded IDP is not enabled")
}

func TestCreateOwnerUser_IdPError(t *testing.T) {
	idpMock := &mockIdP{
		createUserFunc: func(_ context.Context, _, _, _ string) (*idp.UserData, error) {
			return nil, errors.New("provider error")
		},
	}
	mgr := newTestManager(idpMock, &mockStore{})

	_, err := mgr.CreateOwnerUser(context.Background(), "admin@example.com", "password123", "Admin")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "provider error")

	required, _ := mgr.IsSetupRequired(context.Background())
	assert.True(t, required, "setup should still be required after IdP error")
}

func TestCreateOwnerUser_TransientDBError_DoesNotBlockSetup(t *testing.T) {
	mgr := newTestManager(&mockIdP{}, &mockStore{err: errors.New("connection refused")})

	_, err := mgr.CreateOwnerUser(context.Background(), "admin@example.com", "password123", "Admin")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "connection refused")

	required, _ := mgr.IsSetupRequired(context.Background())
	assert.True(t, required, "setup should still be required after transient DB error")

	mgr.store = &mockStore{}
	userData, err := mgr.CreateOwnerUser(context.Background(), "admin@example.com", "password123", "Admin")
	require.NoError(t, err)
	assert.Equal(t, "admin@example.com", userData.Email)
}

func TestCreateOwnerUser_TransientIdPError_DoesNotBlockSetup(t *testing.T) {
	idpMock := &mockIdP{getAllAccountsErr: errors.New("connection reset")}
	mgr := newTestManager(idpMock, &mockStore{})

	_, err := mgr.CreateOwnerUser(context.Background(), "admin@example.com", "password123", "Admin")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "connection reset")

	required, _ := mgr.IsSetupRequired(context.Background())
	assert.True(t, required, "setup should still be required after transient IdP error")

	idpMock.getAllAccountsErr = nil
	userData, err := mgr.CreateOwnerUser(context.Background(), "admin@example.com", "password123", "Admin")
	require.NoError(t, err)
	assert.Equal(t, "admin@example.com", userData.Email)
}

func TestCreateOwnerUser_DBCheckBlocksConcurrent(t *testing.T) {
	idpMock := &mockIdP{
		users: map[string][]*idp.UserData{
			"acc1": {{ID: "existing-user"}},
		},
	}
	mgr := newTestManager(idpMock, &mockStore{})

	_, err := mgr.CreateOwnerUser(context.Background(), "admin@example.com", "password123", "Admin")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "setup already completed")
}

func TestCreateOwnerUser_DBCheckBlocksWhenAccountsExist(t *testing.T) {
	mgr := newTestManager(&mockIdP{}, &mockStore{accountsCount: 1})

	_, err := mgr.CreateOwnerUser(context.Background(), "admin@example.com", "password123", "Admin")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "setup already completed")
}

func TestCreateOwnerUser_ConcurrentRequests(t *testing.T) {
	var idpCallCount atomic.Int32
	var successCount atomic.Int32
	var failCount atomic.Int32

	idpMock := &mockIdP{
		createUserFunc: func(_ context.Context, email, _, _ string) (*idp.UserData, error) {
			idpCallCount.Add(1)
			time.Sleep(50 * time.Millisecond)
			return &idp.UserData{ID: "user-1", Email: email, Name: "Owner"}, nil
		},
	}
	mgr := newTestManager(idpMock, &mockStore{})

	var wg sync.WaitGroup
	for i := range 10 {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			_, err := mgr.CreateOwnerUser(
				context.Background(),
				fmt.Sprintf("owner%d@example.com", idx),
				"password1234",
				fmt.Sprintf("Owner%d", idx),
			)
			if err != nil {
				failCount.Add(1)
			} else {
				successCount.Add(1)
			}
		}(i)
	}
	wg.Wait()

	assert.Equal(t, int32(1), successCount.Load(), "exactly one concurrent setup request should succeed")
	assert.Equal(t, int32(9), failCount.Load(), "remaining concurrent requests should fail")
	assert.Equal(t, int32(1), idpCallCount.Load(), "IdP CreateUser should be called exactly once")
}

func TestIsSetupRequired_EmbeddedIdPDisabled(t *testing.T) {
	mgr := &DefaultManager{}

	required, err := mgr.IsSetupRequired(context.Background())
	require.NoError(t, err)
	assert.False(t, required)
}

func TestIsSetupRequired_ReturnsFlag(t *testing.T) {
	mgr := newTestManager(&mockIdP{}, &mockStore{})

	required, err := mgr.IsSetupRequired(context.Background())
	require.NoError(t, err)
	assert.True(t, required)

	mgr.setupMu.Lock()
	mgr.setupRequired = false
	mgr.setupMu.Unlock()

	required, err = mgr.IsSetupRequired(context.Background())
	require.NoError(t, err)
	assert.False(t, required)
}

func TestRollbackSetup_UserAlreadyDeletedIsSuccess(t *testing.T) {
	tests := []struct {
		name string
		err  error
	}{
		{
			name: "management status not found",
			err:  status.NewUserNotFoundError("owner-id"),
		},
		{
			name: "dex storage not found",
			err:  fmt.Errorf("failed to get user for deletion: %w", storage.ErrNotFound),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			idpMock := &mockIdP{
				deleteUserFunc: func(_ context.Context, userID string) error {
					assert.Equal(t, "owner-id", userID)
					return tt.err
				},
			}
			mgr := newTestManager(idpMock, &mockStore{})
			mgr.setupRequired = false

			err := mgr.RollbackSetup(context.Background(), "owner-id")
			require.NoError(t, err)

			required, err := mgr.IsSetupRequired(context.Background())
			require.NoError(t, err)
			assert.True(t, required, "setup should be required when no accounts or local users remain")
		})
	}
}

func TestRollbackSetup_RecomputesSetupStateWhenAccountStillExists(t *testing.T) {
	idpMock := &mockIdP{
		deleteUserFunc: func(_ context.Context, _ string) error {
			return status.NewUserNotFoundError("owner-id")
		},
	}
	mgr := newTestManager(idpMock, &mockStore{accountsCount: 1})
	mgr.setupRequired = true

	err := mgr.RollbackSetup(context.Background(), "owner-id")
	require.NoError(t, err)

	required, err := mgr.IsSetupRequired(context.Background())
	require.NoError(t, err)
	assert.False(t, required, "setup should not be required while an account still exists")
}

func TestRollbackSetup_ReturnsDeleteErrorButReloadsSetupState(t *testing.T) {
	idpMock := &mockIdP{
		deleteUserFunc: func(_ context.Context, _ string) error {
			return errors.New("idp unavailable")
		},
	}
	mgr := newTestManager(idpMock, &mockStore{})
	mgr.setupRequired = false

	err := mgr.RollbackSetup(context.Background(), "owner-id")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "idp unavailable")

	required, err := mgr.IsSetupRequired(context.Background())
	require.NoError(t, err)
	assert.True(t, required, "setup state should be reloaded even when user deletion fails")
}

func TestDefaultManager_ValidateSetupRequest(t *testing.T) {
	manager := &DefaultManager{setupRequired: true}

	tests := []struct {
		name        string
		email       string
		password    string
		userName    string
		expectError bool
		errorMsg    string
	}{
		{
			name:     "valid request",
			email:    "admin@example.com",
			password: "password123",
			userName: "Admin User",
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
			name:     "password exactly 8 characters",
			email:    "admin@example.com",
			password: "12345678",
			userName: "Admin User",
		},
		{
			name:     "password exactly 72 characters",
			email:    "admin@example.com",
			password: "aaaaaaaabbbbbbbbccccccccddddddddeeeeeeeeffffffffgggggggghhhhhhhhiiiiiiii",
			userName: "Admin User",
		},
		{
			name:        "password too long",
			email:       "admin@example.com",
			password:    "aaaaaaaabbbbbbbbccccccccddddddddeeeeeeeeffffffffgggggggghhhhhhhhiiiiiiiij",
			userName:    "Admin User",
			expectError: true,
			errorMsg:    "password must be at most 72 characters",
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
