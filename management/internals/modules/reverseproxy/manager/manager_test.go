package manager

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy"
	nbgrpc "github.com/netbirdio/netbird/management/internals/shared/grpc"
	"github.com/netbirdio/netbird/management/server/activity"
	"github.com/netbirdio/netbird/management/server/mock_server"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
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

func TestDeletePeerService_SourcePeerValidation(t *testing.T) {
	ctx := context.Background()
	accountID := "test-account"
	ownerPeerID := "peer-owner"
	otherPeerID := "peer-other"
	serviceID := "service-123"

	testPeer := &nbpeer.Peer{
		ID:   ownerPeerID,
		Name: "test-peer",
		IP:   net.ParseIP("100.64.0.1"),
	}

	newEphemeralService := func() *reverseproxy.Service {
		return &reverseproxy.Service{
			ID:         serviceID,
			AccountID:  accountID,
			Name:       "test-service",
			Domain:     "test.example.com",
			Source:     reverseproxy.SourceEphemeral,
			SourcePeer: ownerPeerID,
		}
	}

	newPermanentService := func() *reverseproxy.Service {
		return &reverseproxy.Service{
			ID:        serviceID,
			AccountID: accountID,
			Name:      "api-service",
			Domain:    "api.example.com",
			Source:    reverseproxy.SourcePermanent,
		}
	}

	newProxyServer := func(t *testing.T) *nbgrpc.ProxyServiceServer {
		t.Helper()
		tokenStore := nbgrpc.NewOneTimeTokenStore(1 * time.Hour)
		srv := nbgrpc.NewProxyServiceServer(nil, tokenStore, nbgrpc.ProxyOIDCConfig{}, nil, nil)
		t.Cleanup(srv.Close)
		return srv
	}

	t.Run("owner peer can delete own service", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		var storedActivity activity.Activity
		mockStore := store.NewMockStore(ctrl)
		mockAccountMgr := &mock_server.MockAccountManager{
			StoreEventFunc: func(_ context.Context, _, _, _ string, activityID activity.ActivityDescriber, _ map[string]any) {
				storedActivity = activityID.(activity.Activity)
			},
			UpdateAccountPeersFunc: func(_ context.Context, _ string) {},
		}

		mockStore.EXPECT().
			ExecuteInTransaction(ctx, gomock.Any()).
			DoAndReturn(func(ctx context.Context, fn func(store.Store) error) error {
				txMock := store.NewMockStore(ctrl)
				txMock.EXPECT().
					GetServiceByID(ctx, store.LockingStrengthUpdate, accountID, serviceID).
					Return(newEphemeralService(), nil)
				txMock.EXPECT().
					DeleteService(ctx, accountID, serviceID).
					Return(nil)
				txMock.EXPECT().
					GetPeerByID(ctx, store.LockingStrengthNone, accountID, ownerPeerID).
					Return(testPeer, nil)
				return fn(txMock)
			})

		mgr := &managerImpl{
			store:           mockStore,
			accountManager:  mockAccountMgr,
			proxyGRPCServer: newProxyServer(t),
		}

		err := mgr.deletePeerService(ctx, accountID, ownerPeerID, serviceID, activity.PeerServiceUnexposed)
		require.NoError(t, err)
		assert.Equal(t, activity.PeerServiceUnexposed, storedActivity, "should store unexposed activity")
	})

	t.Run("different peer cannot delete service", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockStore := store.NewMockStore(ctrl)

		mockStore.EXPECT().
			ExecuteInTransaction(ctx, gomock.Any()).
			DoAndReturn(func(ctx context.Context, fn func(store.Store) error) error {
				txMock := store.NewMockStore(ctrl)
				txMock.EXPECT().
					GetServiceByID(ctx, store.LockingStrengthUpdate, accountID, serviceID).
					Return(newEphemeralService(), nil)
				return fn(txMock)
			})

		mgr := &managerImpl{
			store: mockStore,
		}

		err := mgr.deletePeerService(ctx, accountID, otherPeerID, serviceID, activity.PeerServiceUnexposed)
		require.Error(t, err)

		sErr, ok := status.FromError(err)
		require.True(t, ok, "should be a status error")
		assert.Equal(t, status.PermissionDenied, sErr.Type(), "should be permission denied")
		assert.Contains(t, err.Error(), "another peer")
	})

	t.Run("cannot delete API-created service", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockStore := store.NewMockStore(ctrl)

		mockStore.EXPECT().
			ExecuteInTransaction(ctx, gomock.Any()).
			DoAndReturn(func(ctx context.Context, fn func(store.Store) error) error {
				txMock := store.NewMockStore(ctrl)
				txMock.EXPECT().
					GetServiceByID(ctx, store.LockingStrengthUpdate, accountID, serviceID).
					Return(newPermanentService(), nil)
				return fn(txMock)
			})

		mgr := &managerImpl{
			store: mockStore,
		}

		err := mgr.deletePeerService(ctx, accountID, ownerPeerID, serviceID, activity.PeerServiceUnexposed)
		require.Error(t, err)

		sErr, ok := status.FromError(err)
		require.True(t, ok, "should be a status error")
		assert.Equal(t, status.PermissionDenied, sErr.Type(), "should be permission denied")
		assert.Contains(t, err.Error(), "API-created")
	})

	t.Run("expire uses correct activity code", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		var storedActivity activity.Activity
		mockStore := store.NewMockStore(ctrl)
		mockAccountMgr := &mock_server.MockAccountManager{
			StoreEventFunc: func(_ context.Context, _, _, _ string, activityID activity.ActivityDescriber, _ map[string]any) {
				storedActivity = activityID.(activity.Activity)
			},
			UpdateAccountPeersFunc: func(_ context.Context, _ string) {},
		}

		mockStore.EXPECT().
			ExecuteInTransaction(ctx, gomock.Any()).
			DoAndReturn(func(ctx context.Context, fn func(store.Store) error) error {
				txMock := store.NewMockStore(ctrl)
				txMock.EXPECT().
					GetServiceByID(ctx, store.LockingStrengthUpdate, accountID, serviceID).
					Return(newEphemeralService(), nil)
				txMock.EXPECT().
					DeleteService(ctx, accountID, serviceID).
					Return(nil)
				txMock.EXPECT().
					GetPeerByID(ctx, store.LockingStrengthNone, accountID, ownerPeerID).
					Return(testPeer, nil)
				return fn(txMock)
			})

		mgr := &managerImpl{
			store:           mockStore,
			accountManager:  mockAccountMgr,
			proxyGRPCServer: newProxyServer(t),
		}

		err := mgr.deletePeerService(ctx, accountID, ownerPeerID, serviceID, activity.PeerServiceExposeExpired)
		require.NoError(t, err)
		assert.Equal(t, activity.PeerServiceExposeExpired, storedActivity, "should store expired activity")
	})

	t.Run("event meta includes peer info", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		var storedMeta map[string]any
		mockStore := store.NewMockStore(ctrl)
		mockAccountMgr := &mock_server.MockAccountManager{
			StoreEventFunc: func(_ context.Context, _, _, _ string, _ activity.ActivityDescriber, meta map[string]any) {
				storedMeta = meta
			},
			UpdateAccountPeersFunc: func(_ context.Context, _ string) {},
		}

		mockStore.EXPECT().
			ExecuteInTransaction(ctx, gomock.Any()).
			DoAndReturn(func(ctx context.Context, fn func(store.Store) error) error {
				txMock := store.NewMockStore(ctrl)
				txMock.EXPECT().
					GetServiceByID(ctx, store.LockingStrengthUpdate, accountID, serviceID).
					Return(newEphemeralService(), nil)
				txMock.EXPECT().
					DeleteService(ctx, accountID, serviceID).
					Return(nil)
				txMock.EXPECT().
					GetPeerByID(ctx, store.LockingStrengthNone, accountID, ownerPeerID).
					Return(testPeer, nil)
				return fn(txMock)
			})

		mgr := &managerImpl{
			store:           mockStore,
			accountManager:  mockAccountMgr,
			proxyGRPCServer: newProxyServer(t),
		}

		err := mgr.deletePeerService(ctx, accountID, ownerPeerID, serviceID, activity.PeerServiceUnexposed)
		require.NoError(t, err)
		require.NotNil(t, storedMeta)
		assert.Equal(t, "test-peer", storedMeta["peer_name"], "meta should contain peer name")
		assert.Equal(t, "100.64.0.1", storedMeta["peer_ip"], "meta should contain peer IP")
		assert.Equal(t, "test-service", storedMeta["name"], "meta should contain service name")
		assert.Equal(t, "test.example.com", storedMeta["domain"], "meta should contain service domain")
	})
}
