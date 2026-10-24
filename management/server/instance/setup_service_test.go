package instance

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/netbirdio/netbird/management/server/idp"
	"github.com/netbirdio/netbird/management/server/mock_server"
	nbstore "github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/auth"
	"github.com/netbirdio/netbird/shared/management/status"
)

type setupInstanceManagerMock struct {
	createOwnerUserFn func(ctx context.Context, email, password, name string) (*idp.UserData, error)
	rollbackSetupFn   func(ctx context.Context, userID string) error
}

func (m *setupInstanceManagerMock) IsSetupRequired(context.Context) (bool, error) {
	return true, nil
}

func (m *setupInstanceManagerMock) CreateOwnerUser(ctx context.Context, email, password, name string) (*idp.UserData, error) {
	if m.createOwnerUserFn != nil {
		return m.createOwnerUserFn(ctx, email, password, name)
	}
	return &idp.UserData{ID: "owner-id", Email: email, Name: name}, nil
}

func (m *setupInstanceManagerMock) RollbackSetup(ctx context.Context, userID string) error {
	if m.rollbackSetupFn != nil {
		return m.rollbackSetupFn(ctx, userID)
	}
	return nil
}

func (m *setupInstanceManagerMock) GetVersionInfo(context.Context) (*VersionInfo, error) {
	return &VersionInfo{}, nil
}

var _ Manager = (*setupInstanceManagerMock)(nil)

func intPtr(v int) *int {
	return &v
}

func TestSetupOwner_PATFeatureDisabled_IgnoresCreatePAT(t *testing.T) {
	t.Setenv(SetupPATEnabledEnvKey, "false")

	createCalls := 0
	setupManager := NewSetupService(
		&setupInstanceManagerMock{
			createOwnerUserFn: func(_ context.Context, email, _, name string) (*idp.UserData, error) {
				createCalls++
				return &idp.UserData{ID: "owner-id", Email: email, Name: name}, nil
			},
		},
		&mock_server.MockAccountManager{},
	)

	result, err := setupManager.SetupOwner(context.Background(), "admin@example.com", "securepassword123", "Admin", SetupOptions{
		CreatePAT: true,
	})

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "owner-id", result.User.ID)
	assert.Empty(t, result.PATPlainToken)
	assert.Equal(t, 1, createCalls)
}

func TestSetupOwner_PATFeatureEnabled_MissingExpireDefaultsToOneDay(t *testing.T) {
	t.Setenv(SetupPATEnabledEnvKey, "true")

	createCalled := false
	setupManager := NewSetupService(
		&setupInstanceManagerMock{
			createOwnerUserFn: func(_ context.Context, email, _, name string) (*idp.UserData, error) {
				createCalled = true
				return &idp.UserData{ID: "owner-id", Email: email, Name: name}, nil
			},
		},
		&mock_server.MockAccountManager{
			GetAccountIDFromUserAuthFunc: func(_ context.Context, userAuth auth.UserAuth) (string, string, error) {
				assert.Equal(t, "owner-id", userAuth.UserId)
				return "acc-1", "owner-id", nil
			},
			CreatePATFunc: func(_ context.Context, accountID, initiatorUserID, targetUserID, tokenName string, expiresIn int) (*types.PersonalAccessTokenGenerated, error) {
				assert.Equal(t, "acc-1", accountID)
				assert.Equal(t, "owner-id", initiatorUserID)
				assert.Equal(t, "owner-id", targetUserID)
				assert.Equal(t, setupPATTokenName, tokenName)
				assert.Equal(t, setupPATDefaultExpireDays, expiresIn)
				return &types.PersonalAccessTokenGenerated{PlainToken: "nbp_plain"}, nil
			},
		},
	)

	result, err := setupManager.SetupOwner(context.Background(), "admin@example.com", "securepassword123", "Admin", SetupOptions{
		CreatePAT: true,
	})

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, createCalled)
	assert.Equal(t, "nbp_plain", result.PATPlainToken)
}

func TestSetupOwner_PATFeatureEnabled_MissingAccountManagerFailsBeforeCreateUser(t *testing.T) {
	t.Setenv(SetupPATEnabledEnvKey, "true")

	createCalled := false
	rollbackCalled := false
	setupManager := NewSetupService(
		&setupInstanceManagerMock{
			createOwnerUserFn: func(_ context.Context, email, _, name string) (*idp.UserData, error) {
				createCalled = true
				return &idp.UserData{ID: "owner-id", Email: email, Name: name}, nil
			},
			rollbackSetupFn: func(_ context.Context, _ string) error {
				rollbackCalled = true
				return nil
			},
		},
		nil,
	)

	result, err := setupManager.SetupOwner(context.Background(), "admin@example.com", "securepassword123", "Admin", SetupOptions{
		CreatePAT: true,
	})

	require.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "account manager is required")
	assert.False(t, createCalled)
	assert.False(t, rollbackCalled)
}

func TestSetupOwner_AccountProvisioningFails_RollsBackSideEffectAccountAndUser(t *testing.T) {
	t.Setenv(SetupPATEnabledEnvKey, "true")

	ctrl := gomock.NewController(t)
	accountStore := nbstore.NewMockStore(ctrl)
	account := &types.Account{Id: "acc-1", CreatedBy: "owner-id"}
	accountStore.EXPECT().GetAccountIDByUserID(gomock.Any(), nbstore.LockingStrengthNone, "owner-id").Return("acc-1", nil)
	accountStore.EXPECT().GetAccount(gomock.Any(), "acc-1").Return(account, nil)
	accountStore.EXPECT().DeleteAccount(gomock.Any(), account).Return(nil)

	rolledBackFor := ""
	rollbackCalls := 0
	setupManager := NewSetupService(
		&setupInstanceManagerMock{
			rollbackSetupFn: func(_ context.Context, userID string) error {
				rollbackCalls++
				rolledBackFor = userID
				return nil
			},
		},
		&mock_server.MockAccountManager{
			GetAccountIDFromUserAuthFunc: func(_ context.Context, userAuth auth.UserAuth) (string, string, error) {
				assert.Equal(t, "owner-id", userAuth.UserId)
				return "", "", errors.New("metadata update failed")
			},
			GetStoreFunc: func() nbstore.Store {
				return accountStore
			},
		},
	)

	result, err := setupManager.SetupOwner(context.Background(), "admin@example.com", "securepassword123", "Admin", SetupOptions{
		CreatePAT:       true,
		PATExpireInDays: intPtr(30),
	})

	require.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "create account for setup user")
	assert.Equal(t, "owner-id", rolledBackFor)
	assert.Equal(t, 1, rollbackCalls)
}

func TestSetupOwner_CreatePATFails_RollsBackSetupAccountAndUser(t *testing.T) {
	t.Setenv(SetupPATEnabledEnvKey, "true")

	ctrl := gomock.NewController(t)
	accountStore := nbstore.NewMockStore(ctrl)
	account := &types.Account{Id: "acc-1", CreatedBy: "owner-id"}
	accountStore.EXPECT().GetAccount(gomock.Any(), "acc-1").Return(account, nil)
	accountStore.EXPECT().DeleteAccount(gomock.Any(), account).Return(nil)

	rollbackCalls := 0
	setupManager := NewSetupService(
		&setupInstanceManagerMock{
			rollbackSetupFn: func(_ context.Context, userID string) error {
				rollbackCalls++
				assert.Equal(t, "owner-id", userID)
				return nil
			},
		},
		&mock_server.MockAccountManager{
			GetAccountIDFromUserAuthFunc: func(_ context.Context, userAuth auth.UserAuth) (string, string, error) {
				assert.Equal(t, "owner-id", userAuth.UserId)
				return "acc-1", "owner-id", nil
			},
			CreatePATFunc: func(_ context.Context, accountID, initiatorUserID, targetUserID, tokenName string, expiresIn int) (*types.PersonalAccessTokenGenerated, error) {
				assert.Equal(t, "acc-1", accountID)
				assert.Equal(t, "owner-id", initiatorUserID)
				assert.Equal(t, "owner-id", targetUserID)
				assert.Equal(t, setupPATTokenName, tokenName)
				assert.Equal(t, 30, expiresIn)
				return nil, status.Errorf(status.Internal, "token store unavailable")
			},
			GetStoreFunc: func() nbstore.Store {
				return accountStore
			},
		},
	)

	result, err := setupManager.SetupOwner(context.Background(), "admin@example.com", "securepassword123", "Admin", SetupOptions{
		CreatePAT:       true,
		PATExpireInDays: intPtr(30),
	})

	require.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "create setup PAT")
	assert.Equal(t, 1, rollbackCalls)
}

// A concurrent first login can make the setup account shared: either a JIT user
// created the primary account first and the owner joined it, or a JIT user joined
// the setup account. A PAT failure must not delete an account other users rely on.
// DeleteAccount is not expected, so the mock store fails the test if it is called.
func TestSetupOwner_CreatePATFails_KeepsSharedAccount(t *testing.T) {
	tests := map[string]*types.Account{
		"created by another user": {Id: "acc-1", CreatedBy: "jit-user"},
		"another user joined": {Id: "acc-1", CreatedBy: "owner-id", Users: map[string]*types.User{
			"owner-id": {Id: "owner-id"},
			"jit-user": {Id: "jit-user"},
		}},
	}

	for name, account := range tests {
		t.Run(name, func(t *testing.T) {
			t.Setenv(SetupPATEnabledEnvKey, "true")

			ctrl := gomock.NewController(t)
			accountStore := nbstore.NewMockStore(ctrl)
			accountStore.EXPECT().GetAccount(gomock.Any(), "acc-1").Return(account, nil)

			rollbackCalls := 0
			setupManager := NewSetupService(
				&setupInstanceManagerMock{
					rollbackSetupFn: func(_ context.Context, _ string) error {
						rollbackCalls++
						return nil
					},
				},
				&mock_server.MockAccountManager{
					GetAccountIDFromUserAuthFunc: func(_ context.Context, _ auth.UserAuth) (string, string, error) {
						return "acc-1", "owner-id", nil
					},
					CreatePATFunc: func(_ context.Context, _, _, _, _ string, _ int) (*types.PersonalAccessTokenGenerated, error) {
						return nil, status.Errorf(status.PermissionDenied, "user is blocked")
					},
					GetStoreFunc: func() nbstore.Store {
						return accountStore
					},
				},
			)

			_, err := setupManager.SetupOwner(context.Background(), "admin@example.com", "securepassword123", "Admin", SetupOptions{
				CreatePAT:       true,
				PATExpireInDays: intPtr(30),
			})

			require.Error(t, err)
			assert.Equal(t, 1, rollbackCalls, "setup user should still be rolled back")
		})
	}
}

func TestSetupOwner_CreatePATFails_AccountAlreadyGoneStillRollsBackUser(t *testing.T) {
	t.Setenv(SetupPATEnabledEnvKey, "true")

	ctrl := gomock.NewController(t)
	accountStore := nbstore.NewMockStore(ctrl)
	accountStore.EXPECT().GetAccount(gomock.Any(), "acc-1").Return(nil, status.NewAccountNotFoundError("acc-1"))

	rolledBackFor := ""
	rollbackCalls := 0
	setupManager := NewSetupService(
		&setupInstanceManagerMock{
			rollbackSetupFn: func(_ context.Context, userID string) error {
				rollbackCalls++
				rolledBackFor = userID
				return nil
			},
		},
		&mock_server.MockAccountManager{
			GetAccountIDFromUserAuthFunc: func(_ context.Context, _ auth.UserAuth) (string, string, error) {
				return "acc-1", "owner-id", nil
			},
			CreatePATFunc: func(_ context.Context, _, _, _, _ string, _ int) (*types.PersonalAccessTokenGenerated, error) {
				return nil, errors.New("token failure")
			},
			GetStoreFunc: func() nbstore.Store {
				return accountStore
			},
		},
	)

	result, err := setupManager.SetupOwner(context.Background(), "admin@example.com", "securepassword123", "Admin", SetupOptions{
		CreatePAT:       true,
		PATExpireInDays: intPtr(30),
	})

	require.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "create setup PAT")
	assert.Equal(t, "owner-id", rolledBackFor)
	assert.Equal(t, 1, rollbackCalls)
}

func TestSetupOwner_CreatePATFails_AccountRollbackFailureStopsBeforeUserRollback(t *testing.T) {
	t.Setenv(SetupPATEnabledEnvKey, "true")

	ctrl := gomock.NewController(t)
	accountStore := nbstore.NewMockStore(ctrl)
	account := &types.Account{Id: "acc-1", CreatedBy: "owner-id"}
	accountStore.EXPECT().GetAccount(gomock.Any(), "acc-1").Return(account, nil)
	accountStore.EXPECT().DeleteAccount(gomock.Any(), account).Return(errors.New("delete failed"))

	rollbackCalls := 0
	setupManager := NewSetupService(
		&setupInstanceManagerMock{
			rollbackSetupFn: func(_ context.Context, userID string) error {
				rollbackCalls++
				return nil
			},
		},
		&mock_server.MockAccountManager{
			GetAccountIDFromUserAuthFunc: func(_ context.Context, _ auth.UserAuth) (string, string, error) {
				return "acc-1", "owner-id", nil
			},
			CreatePATFunc: func(_ context.Context, _, _, _, _ string, _ int) (*types.PersonalAccessTokenGenerated, error) {
				return nil, errors.New("token failure")
			},
			GetStoreFunc: func() nbstore.Store {
				return accountStore
			},
		},
	)

	result, err := setupManager.SetupOwner(context.Background(), "admin@example.com", "securepassword123", "Admin", SetupOptions{
		CreatePAT:       true,
		PATExpireInDays: intPtr(30),
	})

	require.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "create setup PAT")
	assert.Contains(t, err.Error(), "failed to roll back setup resources")
	assert.Equal(t, 0, rollbackCalls)
}
