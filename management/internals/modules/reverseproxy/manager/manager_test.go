package manager

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/shared/management/status"
)

func TestInitializeServiceForCreate(t *testing.T) {
	ctx := context.Background()
	accountID := "test-account"

	t.Run("successful initialization without cluster deriver", func(t *testing.T) {
		mgr := &managerImpl{
			clusterDeriver: nil,
		}

		service := &reverseproxy.Service{
			Domain: "example.com",
			Auth:   reverseproxy.AuthConfig{},
		}

		err := mgr.initializeServiceForCreate(ctx, accountID, service)

		assert.NoError(t, err)
		assert.Equal(t, accountID, service.AccountID)
		assert.Empty(t, service.ProxyCluster, "proxy cluster should be empty when no deriver")
		assert.NotEmpty(t, service.ID, "service ID should be initialized")
		assert.NotEmpty(t, service.SessionPrivateKey, "session private key should be generated")
		assert.NotEmpty(t, service.SessionPublicKey, "session public key should be generated")
	})

	t.Run("verifies session keys are different", func(t *testing.T) {
		mgr := &managerImpl{
			clusterDeriver: nil,
		}

		service1 := &reverseproxy.Service{Domain: "test1.com", Auth: reverseproxy.AuthConfig{}}
		service2 := &reverseproxy.Service{Domain: "test2.com", Auth: reverseproxy.AuthConfig{}}

		err1 := mgr.initializeServiceForCreate(ctx, accountID, service1)
		err2 := mgr.initializeServiceForCreate(ctx, accountID, service2)

		assert.NoError(t, err1)
		assert.NoError(t, err2)
		assert.NotEqual(t, service1.SessionPrivateKey, service2.SessionPrivateKey, "private keys should be unique")
		assert.NotEqual(t, service1.SessionPublicKey, service2.SessionPublicKey, "public keys should be unique")
	})
}

func TestCheckDomainAvailable(t *testing.T) {
	ctx := context.Background()
	accountID := "test-account"

	tests := []struct {
		name             string
		domain           string
		excludeServiceID string
		setupMock        func(*store.MockStore)
		expectedError    bool
		errorType        status.Type
	}{
		{
			name:             "domain available - not found",
			domain:           "available.com",
			excludeServiceID: "",
			setupMock: func(ms *store.MockStore) {
				ms.EXPECT().
					GetServiceByDomain(ctx, accountID, "available.com").
					Return(nil, status.Errorf(status.NotFound, "not found"))
			},
			expectedError: false,
		},
		{
			name:             "domain already exists",
			domain:           "exists.com",
			excludeServiceID: "",
			setupMock: func(ms *store.MockStore) {
				ms.EXPECT().
					GetServiceByDomain(ctx, accountID, "exists.com").
					Return(&reverseproxy.Service{ID: "existing-id", Domain: "exists.com"}, nil)
			},
			expectedError: true,
			errorType:     status.AlreadyExists,
		},
		{
			name:             "domain exists but excluded (same ID)",
			domain:           "exists.com",
			excludeServiceID: "service-123",
			setupMock: func(ms *store.MockStore) {
				ms.EXPECT().
					GetServiceByDomain(ctx, accountID, "exists.com").
					Return(&reverseproxy.Service{ID: "service-123", Domain: "exists.com"}, nil)
			},
			expectedError: false,
		},
		{
			name:             "domain exists with different ID",
			domain:           "exists.com",
			excludeServiceID: "service-456",
			setupMock: func(ms *store.MockStore) {
				ms.EXPECT().
					GetServiceByDomain(ctx, accountID, "exists.com").
					Return(&reverseproxy.Service{ID: "service-123", Domain: "exists.com"}, nil)
			},
			expectedError: true,
			errorType:     status.AlreadyExists,
		},
		{
			name:             "store error (non-NotFound)",
			domain:           "error.com",
			excludeServiceID: "",
			setupMock: func(ms *store.MockStore) {
				ms.EXPECT().
					GetServiceByDomain(ctx, accountID, "error.com").
					Return(nil, errors.New("database error"))
			},
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockStore := store.NewMockStore(ctrl)
			tt.setupMock(mockStore)

			mgr := &managerImpl{}
			err := mgr.checkDomainAvailable(ctx, mockStore, accountID, tt.domain, tt.excludeServiceID)

			if tt.expectedError {
				require.Error(t, err)
				if tt.errorType != 0 {
					sErr, ok := status.FromError(err)
					require.True(t, ok, "error should be a status error")
					assert.Equal(t, tt.errorType, sErr.Type())
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestCheckDomainAvailable_EdgeCases(t *testing.T) {
	ctx := context.Background()
	accountID := "test-account"

	t.Run("empty domain", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockStore := store.NewMockStore(ctrl)
		mockStore.EXPECT().
			GetServiceByDomain(ctx, accountID, "").
			Return(nil, status.Errorf(status.NotFound, "not found"))

		mgr := &managerImpl{}
		err := mgr.checkDomainAvailable(ctx, mockStore, accountID, "", "")

		assert.NoError(t, err)
	})

	t.Run("empty exclude ID with existing service", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockStore := store.NewMockStore(ctrl)
		mockStore.EXPECT().
			GetServiceByDomain(ctx, accountID, "test.com").
			Return(&reverseproxy.Service{ID: "some-id", Domain: "test.com"}, nil)

		mgr := &managerImpl{}
		err := mgr.checkDomainAvailable(ctx, mockStore, accountID, "test.com", "")

		assert.Error(t, err)
		sErr, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, status.AlreadyExists, sErr.Type())
	})

	t.Run("nil existing service with nil error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockStore := store.NewMockStore(ctrl)
		mockStore.EXPECT().
			GetServiceByDomain(ctx, accountID, "nil.com").
			Return(nil, nil)

		mgr := &managerImpl{}
		err := mgr.checkDomainAvailable(ctx, mockStore, accountID, "nil.com", "")

		assert.NoError(t, err)
	})
}

func TestPersistNewService(t *testing.T) {
	ctx := context.Background()
	accountID := "test-account"

	t.Run("successful service creation with no targets", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockStore := store.NewMockStore(ctrl)
		service := &reverseproxy.Service{
			ID:      "service-123",
			Domain:  "new.com",
			Targets: []*reverseproxy.Target{},
		}

		// Mock ExecuteInTransaction to execute the function immediately
		mockStore.EXPECT().
			ExecuteInTransaction(ctx, gomock.Any()).
			DoAndReturn(func(ctx context.Context, fn func(store.Store) error) error {
				// Create another mock for the transaction
				txMock := store.NewMockStore(ctrl)
				txMock.EXPECT().
					GetServiceByDomain(ctx, accountID, "new.com").
					Return(nil, status.Errorf(status.NotFound, "not found"))
				txMock.EXPECT().
					CreateService(ctx, service).
					Return(nil)

				return fn(txMock)
			})

		mgr := &managerImpl{store: mockStore}
		err := mgr.persistNewService(ctx, accountID, service)

		assert.NoError(t, err)
	})

	t.Run("domain already exists", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockStore := store.NewMockStore(ctrl)
		service := &reverseproxy.Service{
			ID:      "service-123",
			Domain:  "existing.com",
			Targets: []*reverseproxy.Target{},
		}

		mockStore.EXPECT().
			ExecuteInTransaction(ctx, gomock.Any()).
			DoAndReturn(func(ctx context.Context, fn func(store.Store) error) error {
				txMock := store.NewMockStore(ctrl)
				txMock.EXPECT().
					GetServiceByDomain(ctx, accountID, "existing.com").
					Return(&reverseproxy.Service{ID: "other-id", Domain: "existing.com"}, nil)

				return fn(txMock)
			})

		mgr := &managerImpl{store: mockStore}
		err := mgr.persistNewService(ctx, accountID, service)

		require.Error(t, err)
		sErr, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, status.AlreadyExists, sErr.Type())
	})
}
func TestPreserveExistingAuthSecrets(t *testing.T) {
	mgr := &managerImpl{}

	t.Run("preserve password when empty", func(t *testing.T) {
		existing := &reverseproxy.Service{
			Auth: reverseproxy.AuthConfig{
				PasswordAuth: &reverseproxy.PasswordAuthConfig{
					Enabled:  true,
					Password: "hashed-password",
				},
			},
		}

		updated := &reverseproxy.Service{
			Auth: reverseproxy.AuthConfig{
				PasswordAuth: &reverseproxy.PasswordAuthConfig{
					Enabled:  true,
					Password: "",
				},
			},
		}

		mgr.preserveExistingAuthSecrets(updated, existing)

		assert.Equal(t, existing.Auth.PasswordAuth, updated.Auth.PasswordAuth)
	})

	t.Run("preserve pin when empty", func(t *testing.T) {
		existing := &reverseproxy.Service{
			Auth: reverseproxy.AuthConfig{
				PinAuth: &reverseproxy.PINAuthConfig{
					Enabled: true,
					Pin:     "hashed-pin",
				},
			},
		}

		updated := &reverseproxy.Service{
			Auth: reverseproxy.AuthConfig{
				PinAuth: &reverseproxy.PINAuthConfig{
					Enabled: true,
					Pin:     "",
				},
			},
		}

		mgr.preserveExistingAuthSecrets(updated, existing)

		assert.Equal(t, existing.Auth.PinAuth, updated.Auth.PinAuth)
	})

	t.Run("do not preserve when password is provided", func(t *testing.T) {
		existing := &reverseproxy.Service{
			Auth: reverseproxy.AuthConfig{
				PasswordAuth: &reverseproxy.PasswordAuthConfig{
					Enabled:  true,
					Password: "old-password",
				},
			},
		}

		updated := &reverseproxy.Service{
			Auth: reverseproxy.AuthConfig{
				PasswordAuth: &reverseproxy.PasswordAuthConfig{
					Enabled:  true,
					Password: "new-password",
				},
			},
		}

		mgr.preserveExistingAuthSecrets(updated, existing)

		assert.Equal(t, "new-password", updated.Auth.PasswordAuth.Password)
		assert.NotEqual(t, existing.Auth.PasswordAuth, updated.Auth.PasswordAuth)
	})
}

func TestPreserveServiceMetadata(t *testing.T) {
	mgr := &managerImpl{}

	existing := &reverseproxy.Service{
		Meta: reverseproxy.ServiceMeta{
			CertificateIssuedAt: time.Now(),
			Status:              "active",
		},
		SessionPrivateKey: "private-key",
		SessionPublicKey:  "public-key",
	}

	updated := &reverseproxy.Service{
		Domain: "updated.com",
	}

	mgr.preserveServiceMetadata(updated, existing)

	assert.Equal(t, existing.Meta, updated.Meta)
	assert.Equal(t, existing.SessionPrivateKey, updated.SessionPrivateKey)
	assert.Equal(t, existing.SessionPublicKey, updated.SessionPublicKey)
}
